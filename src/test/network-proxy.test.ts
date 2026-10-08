import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import net from "node:net";
import { createCommandNetworkProxy } from "../network-proxy.js";

// A non-resolving destination ensures this works only via the upstream proxy,
// not by accidentally reaching the destination with direct egress.
test("per-command network proxies preserve upstream proxy routing and endpoint filtering", { timeout: 5000 }, async t => {
  const target = http.createServer((_req, res) => res.end("via-upstream"));
  const listen = (server: http.Server) => new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as net.AddressInfo).port));
  });
  const targetPort = await listen(target);
  const tunnels: string[] = [];
  const forwarded: string[] = [];
  const sockets = new Set<net.Socket>();
  const parent = http.createServer((req, res) => {
    forwarded.push(req.url!);
    res.end("via-upstream");
  });
  parent.on("connect", (req, client, head) => {
    tunnels.push(req.url!);
    const upstream = net.connect(targetPort, "127.0.0.1", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    });
    sockets.add(upstream);
    client.on("error", () => upstream.destroy());
    client.on("close", () => upstream.destroy());
    upstream.on("error", () => client.destroy());
    upstream.on("close", () => { sockets.delete(upstream); client.destroy(); });
  });
  const parentPort = await listen(parent);
  const variables = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"] as const;
  const original = variables.map(name => process.env[name]);
  process.env.HTTP_PROXY = process.env.HTTPS_PROXY = `http://127.0.0.1:${parentPort}`;
  process.env.NO_PROXY = "";
  let proxy: Awaited<ReturnType<typeof createCommandNetworkProxy>> | undefined;
  t.after(async () => {
    // Close the proxy's upstream tunnels before waiting for the parent server.
    await proxy?.close();
    variables.forEach((name, index) => {
      if (original[index] === undefined) delete process.env[name];
      else process.env[name] = original[index];
    });
    for (const socket of sockets) socket.destroy();
    await Promise.all([parent, target].map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  });
  const commandProxy = await createCommandNetworkProxy("upstream", ["allowed.invalid:80", "allowed.invalid:443"]);
  proxy = commandProxy;
  const request = (host: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port: commandProxy.port, path: `http://${host}/`, headers: {
      "Proxy-Authorization": `Basic ${Buffer.from(`srt:${commandProxy.token}`).toString("base64")}`
    } }, response => {
      let body = "";
      response.on("data", chunk => body += chunk);
      response.on("end", () => resolve({ status: response.statusCode!, body }));
    });
    req.on("error", reject);
  });
  assert.deepEqual(await request("allowed.invalid"), { status: 200, body: "via-upstream" });
  assert.deepEqual(forwarded, ["http://allowed.invalid/"]);
  // HTTPS CONNECT uses the upstream tunnel path rather than the plain HTTP
  // absolute-URI forwarding path. Payload is opaque to the per-command proxy.
  const tunneled = await new Promise<string>((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: commandProxy.port, method: "CONNECT", path: "allowed.invalid:443", headers: {
      "Proxy-Authorization": `Basic ${Buffer.from(`srt:${commandProxy.token}`).toString("base64")}`
    } });
    req.on("error", reject);
    req.on("connect", (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); reject(new Error(`CONNECT failed: ${res.statusCode}`)); return; }
      let data = "";
      socket.on("data", chunk => data += chunk);
      socket.on("error", reject);
      socket.on("end", () => { socket.destroy(); resolve(data); });
      socket.write("GET / HTTP/1.0\r\nHost: allowed.invalid\r\n\r\n");
    });
    req.end();
  });
  assert.match(tunneled, /via-upstream/);
  assert.deepEqual(tunnels, ["allowed.invalid:443"]);
  assert.equal((await request("denied.invalid")).status, 403);
  assert.deepEqual(forwarded, ["http://allowed.invalid/"], "denied destinations never reach the upstream proxy");
  assert.deepEqual(tunnels, ["allowed.invalid:443"]);
});
