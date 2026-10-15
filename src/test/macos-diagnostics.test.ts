import assert from "node:assert/strict";
import test from "node:test";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";
import { SandboxManager, SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { startMacOSSandboxLogMonitor } from "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";
import { AnthropicSandboxRuntime, sandboxCommandKey, sandboxInitializationError, SandboxInitializationFailure } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";

for (const monitorState of ["running", "error", "exited"] as const) {
  test(`missing first filesystem event is diagnosed with ${monitorState} monitoring, without approval or host replay`, async t => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
    const spawn = t.mock.method(childProcess, "spawn", () => child);
    syncBuiltinESMExports();
    const store = new SandboxViolationStore();
    const stop = startMacOSSandboxLogMonitor(event => store.addViolation(event));
    child.emit("spawn");
    if (monitorState === "error") child.emit("error", Object.assign(new Error("not permitted"), { code: "EPERM" }));
    if (monitorState === "exited") child.emit("exit", 1, null);
    t.mock.method(SandboxManager, "initialize", async () => {});
    t.mock.method(SandboxManager, "reset", async () => {});
    t.mock.method(SandboxManager, "getSandboxViolationStore", () => store);
    t.mock.method(SandboxManager, "wrapWithSandbox", async (command: string) => command);
    const namespace = "diagnostic-session", id = "call_first|fc_long";
    const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", commandNamespace: namespace, writePolicy: { allow: ["/worktree"], deny: [] } });
    Object.defineProperty(runtime, "supportsNetworkWidening", { value: false });
    t.after(async () => { await runtime.dispose(); stop(); spawn.mock.restore(); syncBuiltinESMExports(); Object.defineProperty(process, "platform", platform); });
    t.mock.timers.enable({ apis: ["setTimeout"] });
    // The same attempt has CMD64/sysctl telemetry but no filesystem event.
    store.addViolation({ line: "bash(123) deny(1) sysctl-read kern.iossupportversion", encodedCommand: Buffer.from(sandboxCommandKey(namespace, id)).toString("base64"), timestamp: new Date() });
    const subscribe = store.subscribe.bind(store);
    let subscribed!: () => void;
    const ready = new Promise<void>(resolve => { subscribed = resolve; });
    let listeners = 0;
    t.mock.method(store, "subscribe", (listener: Parameters<typeof store.subscribe>[0]) => {
      listeners++;
      const unsubscribe = subscribe(listener);
      subscribed();
      return () => { listeners--; unsubscribe(); };
    });
    const markers: string[] = [];
    let sandboxCalls = 0;
    const executor = new SelectiveSandboxExecutor({ runtime, onStatus: marker => markers.push(marker), policy: new CapabilityPolicy([], "ask"),
      runner: { runSandbox: async () => { sandboxCalls++; return { exitCode: 1, stdout: "", stderr: "open EPERM /not-evidence.txt" }; },
        runHost: async () => { throw new Error("Missing logs must not run on the host"); } },
      approvals: { request: async () => { throw new Error("stderr EPERM is not a permission resource"); } }
    });
    const pending = executor.execute("probe", id);
    await ready;
    t.mock.timers.tick(1000);
    const result = await pending;
    assert.equal(result.exitCode, 1);
    assert.equal(result.disposition, "sandbox");
    assert.deepEqual(result.violations, []);
    assert.equal(listeners, 0);
    assert.equal(sandboxCalls, 1);
    assert.equal(runtime.logMonitorEnabled, true, "process failures never change the configured flag");
    assert.match(result.stderr, /Sandbox observation unconfirmed/);
    assert.match(result.stderr, /matchingEvents=1/);
    assert.match(result.stderr, new RegExp(`"state":"${monitorState}"`));
    assert.match(result.stderr, /EPERM alone does not identify/);
    assert.deepEqual(markers, ["<sandbox: observation-unconfirmed>"]);
    assert.equal(runtime.getObservationDiagnostic(id), undefined, "forgetCommand removes per-attempt diagnostics");
  });
}

test("denied SDK Unix-socket initialization is explicit, cleans up, and retains enforcement", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(SandboxManager, "initialize", async () => { throw new Error("listen EPERM: operation not permitted /tmp/claude/srt-mux-123-0.sock"); });
  const reset = t.mock.method(SandboxManager, "reset", async () => {});
  const error = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } }).catch(value => value);
  assert.ok(error instanceof SandboxInitializationFailure);
  assert.equal(error.logMonitorEnabled, true);
  assert.equal(reset.mock.callCount(), 1);
  const message = sandboxInitializationError(error);
  assert.match(message, /private Unix socket bind was denied/);
  assert.match(message, /AF_UNIX even when loopback TCP works/);
  assert.match(message, /Unix sockets were not globally allowed/);
  assert.match(message, /host execution was not attempted/);
  const executor = new SelectiveSandboxExecutor({ sandboxUnavailableMessage: message, policy: new CapabilityPolicy([]), runner: {
    runSandbox: async () => { throw new Error("No sandbox execution"); }, runHost: async () => { throw new Error("No host fallback"); }
  } });
  assert.equal((await executor.execute("probe", "initialization")).disposition, "sandbox-unavailable");
  assert.equal(sandboxInitializationError(new Error("open EPERM /tmp/not-a-mux.sock")), "Sandbox unavailable; host execution was not attempted.");
});

test("failed sibling initialization must not reset the foreground parent's SDK lease", async t => {
  t.mock.method(SandboxManager, "initialize", async () => {});
  const reset = t.mock.method(SandboxManager, "reset", async () => {});
  const parent = await AnthropicSandboxRuntime.initialize({ cwd: "/parent", writePolicy: { allow: ["/parent"], deny: [] } });
  t.mock.method(SandboxManager, "initialize", async () => { throw new Error("initialization denied"); });
  await assert.rejects(AnthropicSandboxRuntime.initialize({ cwd: "/child", writePolicy: { allow: ["/child"], deny: [] } }));
  assert.equal(reset.mock.callCount(), 0);
  await parent.dispose();
  assert.equal(reset.mock.callCount(), 1);
});
