import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import type { RegisteredCommand, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime, withNetworkRestrictions, type NetworkRestrictions } from "../runtime-adapter.js";
import { DEFAULT_WRITE_PROFILES } from "../config.js";

test("session switches are independent, validated, nonpersistent, and preserve native boundaries", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-network-switches-"));
  const previous = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = base;
  t.after(async () => {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = previous;
    await rm(base, { recursive: true, force: true });
  });
  await mkdir(join(base, "pi-selective-sandbox"));
  await writeFile(join(base, "pi-selective-sandbox", "config.json"), JSON.stringify({
    filesystem: { disabledDefaultProfiles: DEFAULT_WRITE_PROFILES }
  }));
  const attempts: NetworkRestrictions[] = [];
  const runtime = {
    logMonitorEnabled: true, supportsNetworkWidening: true,
    wrap: async (_command: string, _context: unknown, restrictions: NetworkRestrictions) => {
      attempts.push(restrictions); return "printf sandbox-fixture";
    },
    getViolationsForCommand: () => []
  };
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => runtime as unknown as AnthropicSandboxRuntime);
  async function session() {
    const tools = new Map<string, ToolDefinition>();
    let command!: Omit<RegisteredCommand, "name" | "sourceInfo">;
    await selectiveSandboxExtension({ on: () => undefined,
      registerCommand: (_name: string, value: typeof command) => { command = value; },
      registerTool: (value: ToolDefinition) => { tools.set(value.name, value); }
    } as never);
    const notices: string[] = [];
    const context = { cwd: process.cwd(), hasUI: false, ui: { notify: (message: string) => notices.push(message) } } as never;
    return {
      command,
      notices,
      toggle: (args: string) => command.handler(args, context),
      run: () => tools.get("bash")!.execute("fixture", { command: "printf host-fixture" }, undefined, undefined, context),
      write: () => tools.get("write")!.execute("write", { path: join(base, "blocked"), content: "no" }, undefined, undefined, context)
    };
  }
  const parent = await session();
  assert.deepEqual(parent.command.getArgumentCompletions?.("network o"), [
    { value: "network on", label: "network on" }, { value: "network off", label: "network off" }
  ]);
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: true });
  await parent.toggle(" network\t off ");
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: false, socket: true });
  for (const invalid of ["network", "socket", "network off extra", "all off", "network OFF", "off socket", "socket off on"]) {
    await parent.toggle(invalid);
    assert.match(parent.notices.at(-1)!, /^Usage:/);
    await parent.run();
    assert.deepEqual(attempts.at(-1), { network: false, socket: true });
  }
  await parent.toggle("socket off");
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: false, socket: false });
  await assert.rejects(parent.write(), /Permission denied/);
  await parent.toggle("network on");
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: false });
  await parent.toggle("off");
  const count = attempts.length;
  assert.match(JSON.stringify((await parent.run()).content), /host-fixture/);
  assert.equal(attempts.length, count);
  await parent.toggle("on");
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: false }, "global on does not reset a component switch");
  const sibling = await session(); // A fresh runtime, like reload or a native child.
  await sibling.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: true });
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: false });
  await parent.toggle("socket on");
  await parent.run();
  assert.deepEqual(attempts.at(-1), { network: true, socket: true });
});

test("operation snapshots survive switch changes and retries and suppress endpoint authority when unrestricted", async () => {
  const seen: NetworkRestrictions[] = [];
  const runtime = { supportsNetworkWidening: true,
    wrap: async (_command: string, _context: unknown, restrictions: NetworkRestrictions) => { seen.push({ ...restrictions }); return "true"; },
    getViolationsForCommand: () => []
  } as unknown as AnthropicSandboxRuntime;
  const switches = { network: false, socket: true };
  const operation = withNetworkRestrictions(runtime, switches);
  switches.network = true;
  switches.socket = false;
  await operation.wrap("true", { commandId: "first", commandText: "true" });
  await operation.wrap("true", { commandId: "retry", commandText: "true" });
  assert.deepEqual(seen, [{ network: false, socket: true }, { network: false, socket: true }]);
  assert.equal(operation.supportsNetworkWidening, false);
  assert.equal(withNetworkRestrictions(runtime, switches).supportsNetworkWidening, true);
});

test("Linux adapter applies socket overrides without claiming network isolation", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "linux" });
  const readFile = t.mock.method(fs, "readFile", async () => "ID=debian\n");
  syncBuiltinESMExports();
  t.after(() => {
    Object.defineProperty(process, "platform", platform);
    readFile.mock.restore();
    syncBuiltinESMExports();
  });
  t.mock.method(SandboxManager, "initialize", async () => {});
  const wrap = t.mock.method(SandboxManager, "wrapWithSandbox", async (command: string) => command);
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/fixture", writePolicy: { allow: ["/fixture"], deny: [] } });
  t.after(() => runtime.dispose());
  assert.equal(runtime.supportsNetworkWidening, false);
  for (const socket of [true, false, true]) {
    await runtime.wrap("true", { commandId: `linux-${socket}`, commandText: "true" }, { network: false, socket });
    const args = wrap.mock.calls.at(-1)!.arguments as unknown as Parameters<typeof SandboxManager.wrapWithSandbox>;
    assert.equal(args[4]?.allowAllNetwork, false);
    assert.equal(args[4]?.allowAllUnixSockets, !socket);
    assert.equal(args[4]?.networkProxy, undefined);
  }
});

test("adapter supplies per-operation overrides and does not create a proxy for network off", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(SandboxManager, "initialize", async () => {});
  const wrap = t.mock.method(SandboxManager, "wrapWithSandbox", async (command: string) => command);
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/fixture", writePolicy: { allow: ["/fixture"], deny: ["/fixture/private"] } });
  t.after(() => runtime.dispose());
  for (const socket of [true, false, true]) {
    const operation = withNetworkRestrictions(runtime, { network: false, socket });
    assert.equal(await operation.wrap("true", { commandId: `off-${socket}`, commandText: "true" }), "true");
    const args = wrap.mock.calls.at(-1)!.arguments as unknown as Parameters<typeof SandboxManager.wrapWithSandbox>;
    assert.equal(args[4]?.networkProxy, undefined);
    assert.equal(args[4]?.allowAllNetwork, true);
    assert.equal(args[4]?.allowAllUnixSockets, !socket);
    assert.deepEqual(args[2]?.filesystem?.denyWrite, ["/fixture/private"]);
    assert.deepEqual(args[2]?.network?.allowMachLookup, ["com.apple.trustd.agent", "com.apple.sysmond", "com.apple.FSEvents"]);
  }
});

for (const initialSocket of [true, false]) {
  test(`real SDK profiles separate network/socket switches after socket baseline ${initialSocket}`, async t => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
    t.after(async () => { try { await SandboxManager.reset(); } finally { Object.defineProperty(process, "platform", platform); } });
    const config = {
      filesystem: { allowWrite: ["/switch-fixture"], denyWrite: ["/switch-fixture/blocked"], denyRead: [] },
      network: { allowedDomains: [], deniedDomains: [], allowAllUnixSockets: initialSocket,
        allowLocalBinding: false, allowMachLookup: ["com.apple.trustd.agent"], httpProxyPort: 43201, socksProxyPort: 43201 }
    };
    await SandboxManager.initialize(config, undefined, false);
    for (const [network, socket] of [[false, false], [true, true], [false, true], [true, false], [false, false]] as const) {
      const wrapped = await SandboxManager.wrapWithSandbox("true", undefined, config, undefined, {
        commandId: `switch-${network}-${socket}`, allowAllNetwork: !network, allowAllUnixSockets: !socket,
        networkProxy: { port: 43202, token: "unused-switch-fixture" }
      });
      assert.equal(wrapped.includes('(allow network-outbound (remote ip "*:*"))'), !network);
      assert.equal(wrapped.includes('(allow network-inbound (local ip "*:*"))'), !network);
      assert.equal(wrapped.includes('(allow system-socket (socket-domain AF_UNIX))'), !socket);
      assert.equal(wrapped.includes('unix-socket (path-regex #"^/")'), !socket);
      assert.equal(wrapped.includes("HTTP_PROXY="), network, "network off must not force clients through a filtering proxy");
      assert.equal(wrapped.includes('(remote ip "localhost:43202")'), network);
      assert.ok(wrapped.includes('(subpath "/switch-fixture/blocked")'));
      assert.ok(wrapped.includes('(global-name "com.apple.trustd.agent")'));
      assert.ok(!wrapped.includes("(allow network*)"));
      assert.ok(!wrapped.includes("(allow mach-lookup)"));
      assert.ok(!wrapped.includes("(allow file-write*)"));
    }
    assert.deepEqual(SandboxManager.getConfig(), config, "no global SDK policy mutation");
  });
}
