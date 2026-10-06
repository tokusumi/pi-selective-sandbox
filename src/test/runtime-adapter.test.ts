import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import fs from "node:fs/promises";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { SandboxManager, SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { AnthropicSandboxRuntime, buildSandboxRuntimeConfig, isUbuntuRelease, sandboxInitializationError, violationFromLine } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";
import { gitApprovalPaths } from "../git-write-paths.js";

async function macOSCommandFixture(t: TestContext, id: string) {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(SandboxManager, "initialize", async () => {});
  const store = new SandboxViolationStore();
  t.mock.method(SandboxManager, "getSandboxViolationStore", () => store);
  let encoded = "", tag = "";
  t.mock.method(SandboxManager, "wrapWithSandbox", async (_command: string, _shell: unknown, _config: unknown, _signal: unknown, context: { commandId: string }) => {
    encoded = Buffer.from(context.commandId).toString("base64");
    tag = `CMD64_${encoded}_END__test_SBX`;
    return `sandbox ${tag}`;
  });
  const state: { lines: string[]; queries: number; timeout?: number; error?: Error } = { lines: [], queries: 0 };
  const execFile = t.mock.method(childProcess, "execFile", (
    file: string, args: readonly string[], options: { timeout: number },
    callback: (error: Error | null, stdout: string, stderr: string) => void
  ) => {
    state.queries++;
    state.timeout = options.timeout;
    assert.equal(file, "/usr/bin/log");
    assert.ok(args.includes(`eventMessage ENDSWITH "${tag}"`));
    callback(state.error ?? null, state.lines.map(line => JSON.stringify({
      processID: 0, processImagePath: "/kernel", senderImagePath: "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
      eventMessage: `Sandbox: ${line}\n${tag}`
    })).join("\n"), "");
    return {} as ReturnType<typeof childProcess.execFile>;
  });
  syncBuiltinESMExports();
  t.after(() => { execFile.mock.restore(); syncBuiltinESMExports(); });
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } });
  await runtime.wrap("git add tracked.txt", { commandId: id, commandText: "git add tracked.txt" });
  return { runtime, store, state, encoded };
}

test("a misattributed stream resource cannot authorize another command", async t => {
  const { runtime, store, state, encoded } = await macOSCommandFixture(t, "call-A");
  store.addViolation({ line: "git(222) deny(1) file-write-create /command-B/index.lock", encodedCommand: encoded, timestamp: new Date() });
  // The exact-tagged kernel snapshot contains no denial for A.
  assert.deepEqual(await runtime.getViolationsForCommand("call-A"), []);
  assert.equal(state.queries, 1);
});

test("stream sanitization cannot replace the kernel resource", async t => {
  const { runtime, store, state, encoded } = await macOSCommandFixture(t, "special-path");
  const resource = "/repo<a>/file";
  const line = `git(123) deny(1) file-write-create ${resource}`;
  state.lines = [line];
  store.addViolation({ line, encodedCommand: encoded, timestamp: new Date() });
  assert.match(store.getViolations()[0].line, /\/repoa\/file/);
  assert.deepEqual(await runtime.getViolationsForCommand("special-path"), [{ kind: "filesystem.write", resource, message: line }]);
  assert.equal(state.queries, 1);
});

test("proxy network denials remain available separately from Seatbelt hints", async t => {
  const { runtime, store, state, encoded } = await macOSCommandFixture(t, "proxy-call");
  for (const line of ["deny network-outbound example.invalid:443 (blocked)", "deny http-request GET https://example.invalid/ (blocked)"]) {
    store.clear();
    store.addViolation({ line, encodedCommand: encoded, timestamp: new Date() });
    const events = await runtime.getViolationsForCommand("proxy-call");
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, "network");
    assert.equal(events[0].message, line);
  }
  assert.equal(state.queries, 2);
});

test("a stream hint never bypasses an unavailable authoritative snapshot", async t => {
  const { runtime, store, state, encoded } = await macOSCommandFixture(t, "query-failure");
  state.error = new Error("log unavailable");
  store.addViolation({ line: "git(123) deny(1) file-write-create /repo/file", encodedCommand: encoded, timestamp: new Date() });
  await assert.rejects(runtime.getViolationsForCommand("query-failure"), /observation is unavailable/);
  assert.equal(state.queries, 1);
});

test("macOS assigns a fresh short telemetry key to every attempt", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(SandboxManager, "initialize", async () => {});
  const keys: string[] = [];
  t.mock.method(SandboxManager, "wrapWithSandbox", async (_command: string, _shell: unknown, _config: unknown, _signal: unknown, context: { commandId: string }) => {
    keys.push(context.commandId);
    return `sandbox CMD64_${Buffer.from(context.commandId.slice(0, 100)).toString("base64")}_END__test_SBX`;
  });
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } });
  const prefix = "x".repeat(100);
  for (const commandId of [prefix + "A", prefix + "B", prefix + "A"]) {
    await runtime.wrap("false", { commandId, commandText: "false" });
  }
  assert.ok(keys.every(key => key.length <= 100));
  assert.equal(new Set(keys).size, 3);
});

test("macOS leaves the unvalidated stream monitor disabled and uses snapshots", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  const initialize = t.mock.method(SandboxManager, "initialize", async () => {});
  const settings = { cwd: "/worktree", writePolicy: { allow: ["/worktree"], deny: [] } };
  await AnthropicSandboxRuntime.initialize(settings);
  assert.deepEqual(initialize.mock.calls.map(call => call.arguments), [
    [buildSandboxRuntimeConfig(settings), undefined, false]
  ]);
});

test("Linux initialization leaves the startup-policy violation monitor disabled", async t => {
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

test("macOS snapshot query is bounded and does not invent a sandbox violation", async t => {
  const { runtime, state } = await macOSCommandFixture(t, "ordinary-failure");
  assert.deepEqual(await runtime.getViolationsForCommand("ordinary-failure"), []);
  assert.equal(state.timeout, 1000);
  assert.equal(state.queries, 1);
});

test("a macOS kernel git add denial reaches Git resource approval and sandbox retry", async t => {
  const { runtime, state } = await macOSCommandFixture(t, "git-add-delayed");
  const paths = { commonDir: "/repo/.git", worktreeDir: "/repo/.git/worktrees/child" };
  const wrap = runtime.wrap.bind(runtime);
  t.mock.method(runtime, "wrap", async (command: string, context: Parameters<typeof runtime.wrap>[1]) => {
    if (attempts > 0) assert.deepEqual(context.extraCapabilities?.map(cap => cap.resource), [paths.commonDir]);
    return wrap(command, context);
  });
  let attempts = 0, prompts = 0, hostCalls = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime, policy: new CapabilityPolicy([], "ask"),
    runner: {
      runSandbox: async () => {
        if (++attempts > 1) return { exitCode: 0, stdout: "", stderr: "" };
        state.lines = [`git(123) deny(1) file-write-create ${paths.worktreeDir}/index.lock`];
        return { exitCode: 128, stdout: "", stderr: "fatal: Unable to create index.lock: Operation not permitted" };
      },
      runHost: async () => { hostCalls++; throw new Error("Unexpected host replay"); }
    },
    canonicalizeCapabilities: async capabilities => capabilities.flatMap(capability =>
      gitApprovalPaths(capability.resource, paths).map(resource => ({ kind: "filesystem.write" as const, resource }))),
    approvals: createApprovalProvider({
      hasUI: true,
      ui: { select: async (message, choices) => {
        prompts++;
        assert.match(message, /filesystem\.write: \/repo\/\.git/);
        assert.ok(choices.includes("Allow resource and rerun command once"));
        assert.ok(choices.includes("Run command on host once"));
        return "Allow resource and rerun command once";
      } }
    }, new SessionGrantStore(), undefined, undefined, paths)
  });
  const output = await executor.execute("git add tracked.txt", "git-add-delayed");
  assert.equal(output.exitCode, 0);
  assert.equal(output.disposition, "sandbox");
  assert.equal(attempts, 2);
  assert.equal(prompts, 1);
  assert.equal(hostCalls, 0);
});

test("macOS recovers a missed kernel write denial and ignores sysctl noise", async t => {
  const id = "missed-git-add";
  const { runtime, store, state, encoded } = await macOSCommandFixture(t, id);
  const resource = "/repo with spaces/.git/worktrees/child/index.lock";
  const line = `git(123) deny(1) file-write-create ${resource}`;
  state.lines = [line];
  store.addViolation({ line: "git(123) deny(1) sysctl-read kern.iossupportversion", encodedCommand: encoded, timestamp: new Date() });
  assert.deepEqual(await runtime.getViolationsForCommand(id), [{ kind: "filesystem.write", resource, message: line }]);
  assert.equal(state.queries, 1);
  runtime.forgetCommand(id);
});

test("macOS write denials are classified by operation, not process or path names", () => {
  for (const process of ["bash", "read-helper", "connect-worker"]) {
    for (const resource of ["/Users/test/threads/result", "/Users/test/network/cache", "/Users/test/connect/output", "/Users/test/outbound/log"]) {
      for (const operation of ["file-write-create", "file-write-data", "file-write-unlink"]) {
        const line = `${process}(123) deny(1) ${operation} ${resource}`;
        assert.deepEqual(violationFromLine(line), { kind: "filesystem.write", resource, message: line });
      }
    }
  }
});

test("macOS read and network denials retain their actual capability kind", () => {
  for (const [operation, resource, kind] of [
    ["file-read-data", "/Users/test/network/config", "filesystem.read"],
    ["file-read-metadata", "/Users/test/connect/config", "filesystem.read"],
    ["network-outbound", "/Users/test/threads/socket", "network"]
  ] as const) {
    const line = `bash(123) deny(1) ${operation} ${resource}`;
    assert.deepEqual(violationFromLine(line), { kind, resource, message: line });
  }
  const linux = "deny openat /home/test/network/cache";
  assert.deepEqual(violationFromLine(linux), { kind: "filesystem.write", resource: "/home/test/network/cache", message: linux });
});

test("macOS write telemetry offers resource widening and retries without host execution", async () => {
  const resource = "/Users/test/threads/network/output";
  const violation = violationFromLine(`bash(123) deny(1) file-write-create ${resource}`);
  let sandboxCalls = 0;
  let hostCalls = 0;
  let prompts = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async (command, context) => {
        if (sandboxCalls > 0) assert.deepEqual(context.extraCapabilities?.map(({ kind, resource }) => ({ kind, resource })), [{ kind: "filesystem.write", resource }]);
        return command;
      },
      getViolationsForCommand: () => [violation]
    },
    runner: {
      runSandbox: async () => ({ exitCode: ++sandboxCalls === 1 ? 1 : 0, stdout: "", stderr: "" }),
      runHost: async () => { hostCalls++; throw new Error("Unexpected host replay"); }
    },
    policy: new CapabilityPolicy([], "ask"),
    approvals: createApprovalProvider({
      hasUI: true,
      ui: { select: async (_message, choices) => {
        prompts++;
        const widen = "Allow resource and rerun command once";
        assert.ok(choices.includes(widen), "write denial must offer sandbox widening");
        assert.ok(choices.includes("Run command on host once"));
        return widen;
      } }
    }, new SessionGrantStore())
  });
  const output = await executor.execute(`touch ${resource}`, "macos-write");
  assert.equal(output.disposition, "sandbox");
  assert.equal(output.exitCode, 0);
  assert.equal(sandboxCalls, 2);
  assert.equal(prompts, 1);
  assert.equal(hostCalls, 0);
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
