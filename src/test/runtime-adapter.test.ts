import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import fs from "node:fs/promises";
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
      if (attempts > 0) assert.deepEqual(context.extraCapabilities, [{ kind: "filesystem.write", resource, message: `read-helper(123) deny(1) file-write-create ${resource}` }]);
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
        assert.ok(choices.includes("Allow resource and rerun command once"));
        assert.ok(choices.includes("Run command on host once"));
        return "Allow resource and rerun command once";
      } } }, new SessionGrantStore())
    });
    assert.equal((await executor.execute("touch file", id)).exitCode, 0);
    assert.equal(attempts, 2);
    assert.equal(prompts, 1);
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
