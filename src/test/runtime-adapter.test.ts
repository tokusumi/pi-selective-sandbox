import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import fs from "node:fs/promises";
import http from "node:http";
import { syncBuiltinESMExports } from "node:module";
import { SandboxManager, SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { AnthropicSandboxRuntime, buildSandboxRuntimeConfig, isUbuntuRelease, sandboxInitializationError } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";

async function macOSFixture(t: TestContext) {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  const initialize = t.mock.method(SandboxManager, "initialize", async () => {});
  const store = new SandboxViolationStore();
  t.mock.method(SandboxManager, "getSandboxViolationStore", () => store);
  t.mock.method(SandboxManager, "wrapWithSandbox", async (command: string) => command);
  const settings = { cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } };
  const runtime = await AnthropicSandboxRuntime.initialize(settings);
  const record = (commandId: string, line: string) => store.addViolation({
    line, encodedCommand: Buffer.from(commandId).toString("base64"), timestamp: new Date()
  });
  return { runtime, store, initialize, settings, record };
}

test("macOS explicitly enables the SDK log monitor", async t => {
  const { initialize, runtime, settings } = await macOSFixture(t);
  assert.deepEqual(initialize.mock.calls.map(call => call.arguments), [
    [buildSandboxRuntimeConfig(settings), undefined, true]
  ]);
  assert.equal(runtime.logMonitorEnabled, true);
});

test("an explicitly false SDK monitor flag is retained without health inference", async t => {
  const { initialize, settings } = await macOSFixture(t);
  const runtime = await AnthropicSandboxRuntime.initialize(settings, false);
  assert.equal(initialize.mock.calls.at(-1)!.arguments[2], false);
  assert.equal(runtime.logMonitorEnabled, false);
});

test("initialization errors retain the configured flag without losing actionable diagnostics", async t => {
  const { settings } = await macOSFixture(t);
  t.mock.method(SandboxManager, "initialize", async () => {
    throw new Error("apply-seccomp: creating nested user namespace: Operation not permitted");
  });
  for (const flag of [false, true]) {
    const error = await AnthropicSandboxRuntime.initialize(settings, flag).catch(value => value);
    assert.equal(Reflect.get(error, "logMonitorEnabled"), flag);
    assert.match(sandboxInitializationError(error), /nested user namespace/);
    assert.match(sandboxInitializationError(error), /Host execution was not attempted/);
  }
});

test("Linux does not enable the SDK startup-policy monitor", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "linux" });
  const readFile = t.mock.method(fs, "readFile", async () => "ID=debian\n");
  syncBuiltinESMExports();
  t.after(() => {
    Object.defineProperty(process, "platform", platform);
    readFile.mock.restore();
    syncBuiltinESMExports();
  });
  const initialize = t.mock.method(SandboxManager, "initialize", async () => {});
  const settings = { cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } };
  await AnthropicSandboxRuntime.initialize(settings);
  assert.deepEqual(initialize.mock.calls.map(call => call.arguments), [
    [buildSandboxRuntimeConfig(settings), undefined, false]
  ]);
});

test("write denials offer resource widening for ordinary and subagent tool IDs", async t => {
  const { runtime, record } = await macOSFixture(t);
  const resource = "/Users/test/threads/network/output with spaces";
  for (const id of ["ordinary-call", "subagent:reviewer:call-1"]) {
    let attempts = 0, prompts = 0, hostCalls = 0;
    const wrap = t.mock.method(runtime, "wrap", async (command: string, context: Parameters<typeof runtime.wrap>[1]) => {
      if (attempts > 0) assert.deepEqual(context.extraCapabilities, [{ kind: "filesystem.write", resource }]);
      return command;
    });
    const executor = new SelectiveSandboxExecutor({
      runtime,
      policy: new CapabilityPolicy([], "ask"),
      runner: {
        runSandbox: async () => {
          if (++attempts === 1) record(id, `read-helper(123) deny(1) file-write-create ${resource}`);
          return { exitCode: attempts === 1 ? 1 : 0, stdout: "", stderr: "" };
        },
        runHost: async () => { hostCalls++; throw new Error("Unexpected host execution"); }
      },
      approvals: createApprovalProvider({ hasUI: true, ui: { select: async (_message, choices) => {
        prompts++;
        if (choices.includes(resource)) return resource;
        if (choices.includes("Once")) return "Once";
        assert.ok(choices.includes("Allow and retry"));
        assert.ok(choices.includes("Run outside sandbox…"));
        assert.ok(!choices.includes("Run command on host once"));
        return "Allow and retry";
      } } }, new SessionGrantStore())
    });
    assert.equal((await executor.execute("touch file", id)).exitCode, 0);
    assert.equal(attempts, 2);
    assert.equal(prompts, 3);
    assert.equal(hostCalls, 0);
    wrap.mock.restore();
  }
});

test("SDK presentation sanitization never changes the resource proposed for approval", async t => {
  const { runtime, record, store } = await macOSFixture(t);
  const resource = "/repo<a>/file with spaces";
  record("raw-path", `git(123) deny(1) file-write-create ${resource}`);
  assert.match(store.getViolations()[0].line, /\/repoa\//);
  assert.equal((await runtime.getViolationsForCommand("raw-path"))[0].resource, resource);
});

test("missing SDK raw metadata cannot authorize a filesystem grant", async t => {
  const { runtime, store } = await macOSFixture(t);
  t.mock.method(store, "getViolationsForCommand", () => [{
    line: "git(123) deny(1) file-write-create /repo/file", timestamp: new Date()
  }]);
  await assert.rejects(runtime.getViolationsForCommand("unpatched"), /SDK raw violation data is unavailable/);
});

test("control characters cannot silently change a resource into a different path", async t => {
  const { runtime, record } = await macOSFixture(t);
  record("control-path", "git(123) deny(1) file-write-create /repo/a\nfile");
  await assert.rejects(runtime.getViolationsForCommand("control-path"), /unsupported control characters/);
});

test("invalid delayed SDK data rejects observation and releases the subscription", async t => {
  const { runtime, store, record } = await macOSFixture(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const subscribe = store.subscribe.bind(store);
  let listeners = 0;
  t.mock.method(store, "subscribe", (listener: Parameters<SandboxViolationStore["subscribe"]>[0]) => {
    listeners++;
    const unsubscribe = subscribe(listener);
    return () => { listeners--; unsubscribe(); };
  });
  const pending = runtime.getViolationsForCommand("delayed-control");
  const rejection = assert.rejects(pending, /unsupported control characters/);
  assert.doesNotThrow(() => record("delayed-control", "git(123) deny(1) file-write-create /repo/a\nfile"));
  await rejection;
  assert.equal(listeners, 0);
});

test("read and network operations are classified independently of path keywords", async t => {
  const { runtime, record, store } = await macOSFixture(t);
  for (const [operation, resource, kind] of [
    ["file-read-data", "/Users/test/network/config", "filesystem.read"],
    ["network-outbound", "/Users/test/threads/socket", "network"]
  ]) {
    store.clear();
    record("classification", `bash(123) deny(1) ${operation} ${resource}`);
    const violations = await runtime.getViolationsForCommand("classification");
    assert.equal(violations[0].kind, kind);
    assert.equal(violations[0].resource, resource);
  }
});

test("macOS waits for the matching SDK event, not another invocation", async t => {
  const { runtime, record, store } = await macOSFixture(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const subscribe = store.subscribe.bind(store);
  let listeners = 0;
  t.mock.method(store, "subscribe", (listener: Parameters<SandboxViolationStore["subscribe"]>[0]) => {
    listeners++;
    const unsubscribe = subscribe(listener);
    return () => { listeners--; unsubscribe(); };
  });
  let settled = false;
  const pending = runtime.getViolationsForCommand("git-add").then(result => { settled = true; return result; });
  await Promise.resolve();
  record("other-call", "bash(999) deny(1) file-write-create /other/file");
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(listeners, 1);
  record("git-add", "git(123) deny(1) sysctl-read kern.iossupportversion");
  await Promise.resolve();
  assert.equal(settled, false, "sysctl noise is not a resource capability");
  assert.equal(listeners, 1);
  record("git-add", "git(123) deny(1) file-write-create /repo/.git/index.lock");
  const violations = await pending;
  assert.equal(violations[0].resource, "/repo/.git/index.lock");
  assert.equal(listeners, 0);
});

test("macOS ordinary failures stop waiting and release the subscription", async t => {
  const { runtime, store, record } = await macOSFixture(t);
  record("ordinary-failure", "bash(123) deny(1) sysctl-read kern.iossupportversion");
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const subscribe = store.subscribe.bind(store);
  let listeners = 0;
  t.mock.method(store, "subscribe", (listener: Parameters<SandboxViolationStore["subscribe"]>[0]) => {
    listeners++;
    const unsubscribe = subscribe(listener);
    return () => { listeners--; unsubscribe(); };
  });
  const pending = runtime.getViolationsForCommand("ordinary-failure");
  assert.equal(listeners, 1);
  t.mock.timers.tick(1000);
  assert.deepEqual(await pending, []);
  assert.equal(listeners, 0);
});

test("Ubuntu release detection accepts all versions and excludes other distributions", () => {
  assert.equal(isUbuntuRelease('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\nVERSION_ID="24.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\nVERSION_ID="26.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\n'), true);
  assert.equal(isUbuntuRelease('ID=debian\nVERSION_ID="24"\n'), false);
  assert.equal(isUbuntuRelease('ID=linuxmint\nID_LIKE="ubuntu debian"\n'), false);
});

test("macOS defaults allow local TCP without changing destinations, filesystem, or Unix sockets", async t => {
  await macOSFixture(t);
  const settings = { cwd: "/project", allowedDomains: [], writePolicy: { allow: ["/project"], deny: ["/project/secret"] } };
  const defaults = buildSandboxRuntimeConfig(settings);
  const strict = buildSandboxRuntimeConfig({ ...settings, allowLocalBinding: false });
  assert.equal(defaults.network.allowLocalBinding, true);
  assert.equal(strict.network.allowLocalBinding, false);
  assert.deepEqual(defaults.network.allowedDomains, []);
  assert.equal(defaults.network.allowAllUnixSockets, undefined);
  assert.equal(defaults.network.allowUnixSockets, undefined);
  assert.deepEqual(defaults.filesystem, strict.filesystem);
  assert.deepEqual(defaults.network, { ...strict.network, allowLocalBinding: true });
});

test("Linux does not opt into the macOS local binding policy", t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "linux" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  const settings = { cwd: "/project", writePolicy: { allow: ["/project"], deny: [] }, allowLocalBinding: true };
  for (const ubuntu of [false, true]) {
    const config = buildSandboxRuntimeConfig(settings, ubuntu);
    assert.equal(config.network.allowLocalBinding, undefined);
    assert.equal(config.network.allowAllUnixSockets, ubuntu ? true : undefined);
  }
});

test("normal platforms retain Unix-socket isolation", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/project"], deny: [] } });
  assert.equal(config.network.allowAllUnixSockets, undefined);
});

test("Ubuntu execution path disables only Unix-socket isolation", () => {
  const settings = { cwd: "/project", allowRead: ["/read"], writePolicy: { allow: ["/write"], deny: ["/write/secret"] } };
  const normal = buildSandboxRuntimeConfig(settings);
  const ubuntu = buildSandboxRuntimeConfig(settings, true);
  assert.equal(ubuntu.network.allowAllUnixSockets, true);
  assert.deepEqual(ubuntu.filesystem, normal.filesystem);
  assert.deepEqual(ubuntu.network.allowedDomains, normal.network.allowedDomains);
  assert.deepEqual(ubuntu.network.deniedDomains, normal.network.deniedDomains);
});

test("resolved write policy preserves deny roots", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/write"], deny: ["/write/secret"] } });
  assert.deepEqual(config.filesystem.allowWrite, ["/write"]);
  assert.deepEqual(config.filesystem.denyWrite, ["/write/secret"]);
});

test("nested-userns failure has actionable fail-closed diagnostics", () => {
  const message = sandboxInitializationError(new Error("apply-seccomp: creating nested user namespace: Operation not permitted"));
  assert.match(message, /nested user namespace/);
  assert.match(message, /Host execution was not attempted/);
});

test("unavailable strace is reported without offering host execution", () => {
  const message = sandboxInitializationError(new Error("Ubuntu filesystem observation requires working strace."));
  assert.match(message, /strace could not trace commands/);
  assert.match(message, /Host execution was not attempted/);
});


test("proxy denials identify exact network endpoints without parsing shell text", async t => {
  const { runtime, record } = await macOSFixture(t);
  record("proxy-denial", "deny network-outbound Registry.NPMJS.org:443 (host is not on the allow list)");
  assert.equal((await runtime.getViolationsForCommand("proxy-denial"))[0].resource, "registry.npmjs.org:443");
});


test("macOS attempts enforce immutable network grants in separate authenticated proxies", async t => {
  const { runtime } = await macOSFixture(t);
  const target = http.createServer((_request, response) => response.end("allowed"));
  await new Promise<void>((resolve, reject) => { target.once("error", reject); target.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())));
  const targetPort = (target.address() as { port: number }).port;
  const endpoint = `127.0.0.1:${targetPort}`;
  const wrap = t.mock.method(SandboxManager, "wrapWithSandbox", async (..._args: Parameters<typeof SandboxManager.wrapWithSandbox>) => "sandbox");
  const proxies: { port: number; token: string }[] = [];
  for (const [index, grants] of [[], [{ kind: "network" as const, resource: endpoint }]].entries()) {
    const id = `proxy-${index}`;
    await runtime.wrap("curl example", { commandId: id, commandText: "curl example", extraCapabilities: grants });
    t.after(() => runtime.forgetCommand(id));
    const options = wrap.mock.calls.at(-1)!.arguments[4];
    const proxy = options && Reflect.get(options, "networkProxy");
    assert.ok(proxy, "each attempt needs a proxy, not a global config update");
    proxies.push(proxy);
  }
  assert.notEqual(proxies[0].port, proxies[1].port);
  assert.notEqual(proxies[0].token, proxies[1].token);
  const request = (proxy: { port: number; token: string }, port: number, token = proxy.token) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port: proxy.port, path: `http://127.0.0.1:${port}/`,
      headers: { "Proxy-Authorization": `Basic ${Buffer.from(`srt.forged:${token}`).toString("base64")}` } }, response => {
      let body = "";
      response.on("data", chunk => body += chunk);
      response.on("end", () => resolve({ status: response.statusCode!, body }));
    });
    req.on("error", reject);
  });
  assert.equal((await request(proxies[0], targetPort)).status, 403);
  assert.deepEqual(await request(proxies[1], targetPort), { status: 200, body: "allowed" });
  assert.equal((await request(proxies[1], targetPort === 65535 ? 65534 : targetPort + 1)).status, 403);
  assert.equal((await request(proxies[1], targetPort, proxies[0].token)).status, 407);
  const observed = await runtime.getViolationsForCommand("proxy-0");
  assert.equal(observed[0].resource, endpoint, "client attribution cannot redirect denial to another invocation");
  await runtime.forgetCommand("proxy-1");
  await assert.rejects(request(proxies[1], targetPort), /ECONNREFUSED|ECONNRESET/);
});

test("a selected root grant keeps the caller's deny rules in the sandbox retry", async t => {
  await macOSFixture(t);
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: ["/protected/secret"] } });
  const wrap = t.mock.method(SandboxManager, "wrapWithSandbox", async () => "wrapped");
  await runtime.wrap("touch output", { commandId: "root-retry", commandText: "touch output", extraCapabilities: [{ kind: "filesystem.write", resource: "/" }] });
  t.after(() => runtime.forgetCommand("root-retry"));
  const overrides = wrap.mock.calls[0].arguments[2];
  assert.deepEqual(overrides?.filesystem?.allowWrite, ["/worktree", "/"]);
  assert.deepEqual(overrides?.filesystem?.denyWrite, ["/protected/secret"]);
});
