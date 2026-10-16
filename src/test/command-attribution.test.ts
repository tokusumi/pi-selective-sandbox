import assert from "node:assert/strict";
import test from "node:test";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";
import { SandboxManager, SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { encodeSandboxedCommand, decodeSandboxedCommand } from "@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-utils.js";
import { registerCommandText, resolveCommandText } from "@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-manager.js";
import { startMacOSSandboxLogMonitor, wrapCommandWithSandboxMacOS } from "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";
import { AnthropicSandboxRuntime, sandboxCommandKey } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";

const namespace = "12345678-1234-1234-1234-123456789abc";
// OpenAI tool-call format: 134 characters including the UUID namespace.
const longId = `call_${"a".repeat(24)}|fc_${"b".repeat(64)}`;

test("full long identities separate attempts, commands, sessions, and SDK command registry entries", () => {
  assert.equal(`${namespace}:${longId}`.length, 134);
  assert.equal(encodeSandboxedCommand(`${namespace}:${longId}`), encodeSandboxedCommand(`${namespace}:${longId}:widened:1`), "demonstrate the upstream truncation, independent of OS logs");
  const identities = [
    [namespace, longId], [namespace, `${longId}:widened:1`], [namespace, `${longId}:widened:2`],
    [namespace, `${longId}:widened:16`], [namespace, `${longId}c`], [`${namespace}d`, longId],
    ["a:b", "c"], ["a", "b:c"]
  ];
  const encoded = identities.map(([session, id], index) => {
    const key = sandboxCommandKey(session, id);
    assert.equal(key.length, 67);
    assert.equal(decodeSandboxedCommand(encodeSandboxedCommand(key)), key);
    registerCommandText(`command-${index}`, { commandId: key });
    return encodeSandboxedCommand(key);
  });
  assert.equal(new Set(encoded).size, identities.length);
  const store = new SandboxViolationStore();
  encoded.forEach((key, index) => store.addViolation({ line: `deny file-write-data /file-${index}`, encodedCommand: key, timestamp: new Date() }));
  encoded.forEach((key, index) => {
    const decoded = decodeSandboxedCommand(key);
    assert.equal(resolveCommandText(decoded), `command-${index}`, "later registry entries do not replace earlier commands");
    assert.deepEqual(store.getViolationsForCommand(decoded).map(event => event.rawLine), [`deny file-write-data /file-${index}`]);
  });
});

test("real SDK tags/monitor/store and runtime/executor wait for each fresh denial with long ordinary and subagent IDs", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true });
  const spawn = t.mock.method(childProcess, "spawn", () => child);
  syncBuiltinESMExports();
  const store = new SandboxViolationStore();
  const stop = startMacOSSandboxLogMonitor(event => store.addViolation(event), undefined, resolveCommandText);
  t.after(() => { stop(); spawn.mock.restore(); syncBuiltinESMExports(); Object.defineProperty(process, "platform", platform); });
  t.mock.method(SandboxManager, "initialize", async () => {});
  t.mock.method(SandboxManager, "reset", async () => {});
  t.mock.method(SandboxManager, "getSandboxViolationStore", () => store);
  const keys: string[] = [];
  t.mock.method(SandboxManager, "wrapWithSandbox", async (...[command, _shell, _config, _signal, options]: Parameters<typeof SandboxManager.wrapWithSandbox>) => {
    keys.push(options!.commandId!);
    registerCommandText(command, options);
    return wrapCommandWithSandboxMacOS({ command, commandId: options!.commandId, needsNetworkRestriction: true, readConfig: undefined, writeConfig: undefined });
  });
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", commandNamespace: namespace, writePolicy: { allow: ["/worktree"], deny: [] } });
  // Only OS execution/proxy transport and the UI's selections are fixtures.
  // Attribution still uses real SDK profiles, registry, parser and store.
  Object.defineProperty(runtime, "supportsNetworkWidening", { value: false });
  t.after(() => runtime.dispose());
  const emit = (tag: string, resource: string) => child.stdout.emit("data", Buffer.from(JSON.stringify({
    processID: 0, processImagePath: "/kernel", senderImagePath: "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
    eventMessage: `Sandbox: helper(123) deny(1) file-write-data ${resource}\n${tag}`
  }) + "\n"));
  for (const id of [longId, `subagent:reviewer:${longId}`]) {
    let attempts = 0, approvalRounds = 0;
    const resources = ["/first.txt", "/second.txt", "/third.txt"];
    const firstKeyIndex = keys.length;
    let initialTag = "";
    const start = performance.now();
    const executor = new SelectiveSandboxExecutor({ runtime, policy: new CapabilityPolicy([], "ask"),
      runner: { runSandbox: async wrapped => {
        const index = attempts++;
        if (index === resources.length) return { exitCode: 0, stdout: "ok", stderr: "" };
        const tag = wrapped.match(/CMD64_[A-Za-z0-9+/=]+_END_[A-Za-z0-9_]+/)![0];
        if (index === 0) { initialTag = tag; emit(tag, resources[index]); }
        else {
          // Even a late event for a previously approved attempt cannot stop
          // waiting or trigger the executor's covered-telemetry early return.
          emit(initialTag, resources[0]);
          emit(tag.replace(/CMD64_[A-Za-z0-9+/=]+_END_/, `CMD64_${encodeSandboxedCommand(sandboxCommandKey("other-session", id))}_END_`), "/unrelated.txt");
          setTimeout(() => emit(tag, resources[index]), 50);
        }
        return { exitCode: 1, stdout: "", stderr: "EPERM" };
      }, runHost: async () => { throw new Error("No host replay"); } },
      approvals: createApprovalProvider({ hasUI: true, ui: { select: async (_message, choices) => {
        const resource = resources[approvalRounds];
        if (choices.includes(resource)) return resource;
        if (choices.includes("Once")) return "Once";
        assert.ok(choices.includes("Allow and retry"));
        approvalRounds++;
        return "Allow and retry";
      } } }, new SessionGrantStore())
    });
    const result = await executor.execute("helper writes three files", id);
    assert.equal(result.exitCode, 0);
    assert.equal(result.disposition, "sandbox");
    assert.equal(attempts, 4);
    assert.equal(approvalRounds, 3);
    assert.ok(performance.now() - start >= 90, "fresh delayed denials must be awaited");
    assert.deepEqual(keys.slice(firstKeyIndex), [id, `${id}:widened:1`, `${id}:widened:2`, `${id}:widened:3`].map(attempt => sandboxCommandKey(namespace, attempt)));
  }
});

test("omitted namespaces still isolate separate runtime sessions with the same tool ID", async t => {
  t.mock.method(SandboxManager, "initialize", async () => {});
  t.mock.method(SandboxManager, "reset", async () => {});
  const keys: string[] = [];
  t.mock.method(SandboxManager, "wrapWithSandbox", async (...[command, _shell, _config, _signal, options]: Parameters<typeof SandboxManager.wrapWithSandbox>) => { keys.push(options!.commandId!); return command; });
  const settings = { cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } };
  const runtimes = await Promise.all([AnthropicSandboxRuntime.initialize(settings, false), AnthropicSandboxRuntime.initialize(settings, false)]);
  t.after(() => Promise.all(runtimes.map(runtime => runtime.dispose())));
  for (const runtime of runtimes) {
    Object.defineProperty(runtime, "supportsNetworkWidening", { value: false });
    await runtime.wrap("probe", { commandId: longId, commandText: "probe" });
  }
  assert.notEqual(keys[0], keys[1]);
});
