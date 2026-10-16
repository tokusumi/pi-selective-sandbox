import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";
import { createMuxProxyServer } from "@anthropic-ai/sandbox-runtime/dist/sandbox/mux-proxy.js";
import { createHttpProxyServer } from "@anthropic-ai/sandbox-runtime/dist/sandbox/http-proxy.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";

function macOS(t: TestContext) {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
}

async function listen(server: net.Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return (server.address() as net.AddressInfo).port;
}

const forbiddenBackend = () => { throw Object.assign(new Error("listen EPERM: Unix backends forbidden"), { code: "EPERM" }); };

test("macOS Node mux needs no backend listener and preserves HTTP/CONNECT authentication and filtering", { timeout: 5000 }, async t => {
  macOS(t);
  let filtered = 0, socks = 0;
  const httpServer = createHttpProxyServer({ proxyAuthToken: "private-token", filter: async () => { filtered++; return false; } });
  const backendListen = t.mock.method(httpServer, "listen", forbiddenBackend);
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => { socks++; socket.end("socks-handler"); } });
  t.after(() => mux.close());
  assert.equal(await mux.listenHttpBackend(), undefined);
  assert.equal(httpServer.address(), null, "there is no hidden TCP or Unix HTTP listener");
  const port = await listen(mux.server);
  const request = (method: "GET" | "CONNECT", token?: string) => new Promise<number>((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: method === "CONNECT" ? "blocked.invalid:443" : "http://blocked.invalid/",
      agent: false, headers: token ? { "Proxy-Authorization": `Basic ${Buffer.from(`srt:${token}`).toString("base64")}` } : {}
    });
    req.on("response", response => { response.resume(); response.on("end", () => resolve(response.statusCode!)); });
    req.on("connect", (response, socket) => { socket.destroy(); resolve(response.statusCode!); });
    req.on("error", reject);
    req.end();
  });
  for (const method of ["GET", "CONNECT"] as const) {
    assert.equal(await request(method), 407);
    assert.equal(await request(method, "wrong-token"), 407);
    assert.equal(await request(method, "private-token"), 403);
  }
  assert.equal(filtered, 2, "unauthenticated requests never reach destination policy");
  const client = net.connect(port, "127.0.0.1");
  t.after(() => client.destroy());
  client.write(Buffer.from([5, 1, 0]));
  const [reply] = await once(client, "data");
  assert.equal(reply.toString(), "socks-handler");
  assert.equal(socks, 1, "SOCKS dispatch still uses its existing handler");
  assert.equal(backendListen.mock.callCount(), 0);
});

test("macOS direct HTTP sockets are destroyed on mux close, including unfinished responses", { timeout: 5000 }, async t => {
  macOS(t);
  const httpServer = http.createServer((_request, response) => { response.writeHead(200); response.write("pending"); });
  t.mock.method(httpServer, "listen", forbiddenBackend);
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => socket.destroy() });
  t.after(() => mux.close());
  await mux.listenHttpBackend();
  const port = await listen(mux.server);
  const client = net.connect(port, "127.0.0.1");
  t.after(() => client.destroy());
  client.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  await once(client, "data");
  const closed = once(client, "close");
  await mux.close();
  await closed;
  assert.equal(client.destroyed, true);
  assert.equal(mux.getPort(), undefined);
});

test("macOS direct HTTP retains Node's incomplete-header timeout without a backend listener", { timeout: 5000 }, async t => {
  macOS(t);
  const httpServer = http.createServer({ headersTimeout: 50, requestTimeout: 100, connectionsCheckingInterval: 10 });
  t.mock.method(httpServer, "listen", forbiddenBackend);
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => socket.destroy() });
  t.after(() => mux.close());
  await mux.listenHttpBackend();
  const port = await listen(mux.server);
  const client = net.connect(port, "127.0.0.1");
  t.after(() => client.destroy());
  client.write("GET / HTTP/1.1\r\nHost: ");
  const [reply] = await once(client, "data");
  assert.match(reply.toString(), /408 Request Timeout/);
});

test("macOS mux rejects HTTP before backend readiness rather than bypassing the guard", { timeout: 5000 }, async t => {
  macOS(t);
  let requests = 0;
  const httpServer = http.createServer(() => { requests++; });
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => socket.destroy() });
  t.after(() => mux.close());
  const port = await listen(mux.server);
  const client = net.connect(port, "127.0.0.1");
  t.after(() => client.destroy());
  client.write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  await once(client, "close");
  assert.equal(requests, 0);
});

test("Bun retains its original Unix backend and never silently falls back to direct HTTP", async t => {
  macOS(t);
  const bun = Object.getOwnPropertyDescriptor(process.versions, "bun");
  Object.defineProperty(process.versions, "bun", { configurable: true, value: "fixture" });
  t.after(() => { if (bun) Object.defineProperty(process.versions, "bun", bun); else Reflect.deleteProperty(process.versions, "bun"); });
  const httpServer = http.createServer();
  const backendListen = t.mock.method(httpServer, "listen", forbiddenBackend);
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => socket.destroy() });
  t.after(() => mux.close());
  await assert.rejects(mux.listenHttpBackend(), { code: "EPERM" });
  assert.equal(backendListen.mock.callCount(), 1);
});

test("macOS SDK initialization and per-attempt proxies survive an enclosing Unix-bind denial", { skip: process.platform !== "darwin", timeout: 10000 }, async t => {
  const originalListen = net.Server.prototype.listen;
  let unixBinds = 0;
  t.mock.method(net.Server.prototype, "listen", function (this: net.Server, ...args: Parameters<typeof originalListen>) {
    const endpoint = args[0];
    if (typeof endpoint === "string" || (typeof endpoint === "object" && endpoint !== null && "path" in endpoint)) {
      unixBinds++;
      forbiddenBackend();
    }
    return originalListen.apply(this, args);
  });
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: process.cwd(), writePolicy: { allow: [process.cwd()], deny: [] }, allowedDomains: [] }, false);
  t.after(() => runtime.dispose());
  const wrapped = await runtime.wrap("true", { commandId: "nested-initialization", commandText: "true" });
  assert.match(wrapped, /sandbox-exec/);
  assert.equal(unixBinds, 0, "neither SDK startup nor attempt proxy may attempt a private Unix bind");
  await runtime.forgetCommand("nested-initialization");
});
