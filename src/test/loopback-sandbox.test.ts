import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import net from "node:net";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { CommandResult } from "../types.js";

const exec = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
const node = (source: string) => `${quote(process.execPath)} -e ${quote(source)}`;

async function runSandbox(command: string, cwd: string): Promise<CommandResult> {
  try {
    return { ...await exec("/bin/bash", ["-c", command], { cwd, timeout: 10000 }), exitCode: 0 };
  } catch (error) {
    const failed = error as Error & { code: number; stdout: string; stderr: string };
    if (typeof failed.code !== "number") throw error;
    return { exitCode: failed.code, stdout: failed.stdout, stderr: failed.stderr };
  }
}

test("macOS defaults support ephemeral local listeners without approvals, not external egress or Unix sockets", { skip: process.platform !== "darwin" }, async t => {
  const base = await realpath(await mkdtemp(join(tmpdir(), "pi-loopback-")));
  const cwd = join(base, "workspace"), blocked = join(base, "blocked");
  await Promise.all([mkdir(cwd), mkdir(blocked)]);
  const hostServer = http.createServer((_req, res) => res.end("host-loopback"));
  t.after(async () => {
    await AnthropicSandboxRuntime.reset();
    await new Promise<void>(resolve => hostServer.close(() => resolve()));
    await rm(base, { recursive: true, force: true });
  });
  await new Promise<void>((resolve, reject) => { hostServer.once("error", reject); hostServer.listen(0, "127.0.0.1", resolve); });
  const port = (hostServer.address() as { port: number }).port;
  // An empty proxy allowlist intentionally does not turn off local binding.
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd, allowedDomains: [], writePolicy: { allow: [cwd], deny: [blocked] } });
  const executor = new SelectiveSandboxExecutor({ runtime, cwd, policy: new CapabilityPolicy([]),
    approvals: { request: async () => { throw new Error("Local TCP must not request port approvals"); } },
    runner: { runSandbox: command => runSandbox(command, cwd), runHost: async () => { throw new Error("Unexpected host replay"); } }
  });
  // Bind/inbound are all-interface SDK capabilities, not a loopback-only claim.
  // Exercise explicit IPv4/IPv6 loopback and the common unspecified-host bind.
  for (const host of ["127.0.0.1", "::1", "0.0.0.0", "::"]) {
    const connectHost = host === "::1" || host === "::" ? "::1" : "127.0.0.1";
    const result = await executor.execute(node(`
      const http = require("node:http");
      const server = http.createServer((req, res) => res.end("local-ok"));
      server.on("error", e => { console.error(e); process.exit(1) });
      server.listen(0, ${JSON.stringify(host)}, () => {
        http.get({ host: ${JSON.stringify(connectHost)}, port: server.address().port }, res => {
          res.pipe(process.stdout);
          res.on("end", () => server.close());
        }).on("error", e => { console.error(e); process.exit(1) });
      });
    `), `listener-${host}`);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.disposition, "sandbox");
    assert.equal(result.stdout, "local-ok");
  }
  for (const [type, host] of [["udp4", "127.0.0.1"], ["udp6", "::1"]]) {
    const result = await executor.execute(node(`
      const socket = require("node:dgram").createSocket(${JSON.stringify(type)});
      socket.on("error", e => { console.error(e); process.exit(1) });
      socket.on("message", message => { console.log(message.toString()); socket.close() });
      socket.bind(0, ${JSON.stringify(host)}, () => socket.send("udp-local-ok", socket.address().port, ${JSON.stringify(host)}));
    `), `listener-${type}`);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout.trim(), "udp-local-ok");
    assert.equal(result.disposition, "sandbox");
  }
  // Loopback reachability also includes pre-existing host services; this is
  // a documented authority increase, not listener ownership isolation.
  const direct = await executor.execute(`/usr/bin/curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:${port}/`, "host-loopback");
  assert.equal(direct.exitCode, 0, direct.stderr);
  assert.equal(direct.stdout, "host-loopback");

  for (const [id, source] of [
    ["external-tcp", `const socket = require("node:net").connect(443, "192.0.2.1");
      socket.setTimeout(2000, () => { console.error("External egress was not denied"); process.exit(1) });
      socket.on("connect", () => process.exit(1));
      socket.on("error", e => { console.log(e.code); socket.destroy() });`],
    ["external-udp", `const socket = require("node:dgram").createSocket("udp4");
      socket.send("no", 443, "192.0.2.1", e => { console.log(e ? e.code : "unexpected success"); socket.close() });`],
    ["unix-socket", `require("node:net").createServer().listen(${JSON.stringify(join(cwd, "test.sock"))})
      .on("listening", () => process.exit(1)).on("error", e => console.log(e.code));`],
    ["filesystem", `try { require("node:fs").writeFileSync(${JSON.stringify(join(blocked, "file"))}, "no"); process.exit(1) }
      catch(e) { console.log(e.code) }`]
  ]) {
    const result = await executor.execute(node(source), id);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout.trim(), "EPERM", id);
    assert.equal(result.disposition, "sandbox");
  }
});

test("macOS local binding opt-out denies ephemeral IPv4 and IPv6 listeners", { skip: process.platform !== "darwin" }, async t => {
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "pi-no-loopback-")));
  t.after(async () => { await AnthropicSandboxRuntime.reset(); await rm(cwd, { recursive: true, force: true }); });
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd, allowedDomains: [], allowLocalBinding: false, writePolicy: { allow: [cwd], deny: [] } });
  for (const host of ["127.0.0.1", "::1"]) {
    const id = `strict-${host}`;
    try {
      const wrapped = await runtime.wrap(node(`require("node:net").createServer().listen(0, ${JSON.stringify(host)})
        .on("listening", () => process.exit(1)).on("error", e => console.log(e.code));`), { commandId: id, commandText: id });
      const result = await runSandbox(wrapped, cwd);
      assert.equal(result.exitCode, 0, result.stderr);
      assert.equal(result.stdout.trim(), "EPERM");
    } finally { await runtime.forgetCommand(id); }
  }
});

for (const first of [true, false]) {
  test(`macOS shared runtimes enforce local binding in ${first} -> ${!first} order`, { skip: process.platform !== "darwin" }, async t => {
    const base = await realpath(await mkdtemp(join(tmpdir(), "pi-shared-binding-")));
    const cwd = join(base, "workspace"), blocked = join(base, "blocked");
    await Promise.all([mkdir(cwd), mkdir(blocked)]);
    const servers: (http.Server | net.Server)[] = [];
    t.after(async () => {
      await AnthropicSandboxRuntime.reset();
      await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
      await rm(base, { recursive: true, force: true });
    });
    // Only dedicated local fixtures are reachable; never probe unrelated services.
    const endpoints: { host: string; port: number }[] = [];
    for (const host of ["127.0.0.1", "::1"]) {
      const server = http.createServer((_req, res) => res.end("fixture-ok"));
      servers.push(server);
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
      endpoints.push({ host, port: (server.address() as net.AddressInfo).port });
    }
    const socketPath = join(cwd, "host.sock");
    const unix = net.createServer(socket => socket.end());
    servers.push(unix);
    await new Promise<void>((resolve, reject) => { unix.once("error", reject); unix.listen(socketPath, resolve); });
    const runtimes: AnthropicSandboxRuntime[] = [];
    for (const allowLocalBinding of [first, !first]) {
      runtimes.push(await AnthropicSandboxRuntime.initialize({ cwd, allowedDomains: [], allowLocalBinding,
        writePolicy: { allow: [cwd], deny: [blocked] } }, false));
    }
    let sequence = 0;
    const run = async (index: number, command: string, resource?: string) => {
      const id = `shared-${sequence++}`;
      const runtime = runtimes[index];
      try {
        const wrapped = await runtime.wrap(command, { commandId: id, commandText: command,
          extraCapabilities: resource ? [{ kind: "network", resource }] : [] });
        for (const rule of [
          '(allow network-bind (local ip "*:*"))',
          '(allow network-inbound (local ip "*:*"))',
          '(allow network-outbound (remote ip "localhost:*"))'
        ]) assert.equal(wrapped.includes(rule), index === 0 ? first : !first, rule);
        assert.doesNotMatch(wrapped, /\(allow network\*\)|\(allow system-socket \(socket-domain AF_UNIX\)\)/);
        return await runSandbox(wrapped, cwd);
      } finally { await runtime.forgetCommand(id); }
    };
    const expectOutput = async (index: number, source: string, expected: string) => {
      const result = await run(index, node(source));
      assert.equal(result.exitCode, 0, result.stderr);
      assert.equal(result.stdout.trim(), expected, source);
    };
    // Alternate both live runtimes, then retry each without resetting the SDK.
    for (const index of [0, 1, 0, 1]) {
      const allowed = index === 0 ? first : !first;
      for (const host of ["127.0.0.1", "::1", "0.0.0.0", "::"]) {
        await expectOutput(index, `const s = require("node:net").createServer();
          s.on("error", e => console.log(e.code));
          s.listen(0, ${JSON.stringify(host)}, () => { console.log("listening"); s.close() });`, allowed ? "listening" : "EPERM");
      }
      for (const { host, port } of endpoints) {
        await expectOutput(index, `const s = require("node:net").connect(${port}, ${JSON.stringify(host)});
          s.on("connect", () => { console.log("connected"); s.destroy() });
          s.on("error", e => console.log(e.code));`, allowed ? "connected" : "EPERM");
      }
      await expectOutput(index, `try { require("node:fs").writeFileSync(${JSON.stringify(join(blocked, "file"))}, "no");
        console.log("unexpected write") } catch(e) { console.log(e.code) }`, "EPERM");
      await expectOutput(index, `const s = require("node:net").createServer();
        s.on("error", e => console.log(e.code));
        s.listen(${JSON.stringify(join(cwd, `child-${sequence}.sock`))}, () => { console.log("unexpected bind"); s.close() });`, "EPERM");
      await expectOutput(index, `const s = require("node:net").connect(${JSON.stringify(socketPath)});
        s.on("connect", () => { console.log("unexpected connect"); s.destroy() });
        s.on("error", e => console.log(e.code));`, "EPERM");
      const { port } = endpoints[0];
      const resource = `127.0.0.1:${port}`;
      const curl = `/usr/bin/curl --noproxy '' -fsS --max-time 3 http://${resource}/`;
      // Proxy filtering still applies even when direct loopback is allowed.
      assert.notEqual((await run(index, curl)).exitCode, 0);
      for (const command of [curl, `${curl} --proxy "$ALL_PROXY"`]) {
        const result = await run(index, command, resource);
        assert.equal(result.exitCode, 0, result.stderr);
        assert.equal(result.stdout, "fixture-ok");
      }
      assert.notEqual((await run(index, curl)).exitCode, 0, "per-attempt grant must not leak into the next proxy");
    }
    await runtimes[0].dispose();
    await expectOutput(1, `const s = require("node:net").createServer(); s.on("error", e => console.log(e.code));
      s.listen(0, "127.0.0.1", () => { console.log("listening"); s.close() });`, !first ? "listening" : "EPERM");
  });
}
