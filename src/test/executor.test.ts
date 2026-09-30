import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { findTrustedHelper, splitPureInvocation } from "../skills.js";
import { StraceViolationObserver } from "../strace-observer.js";
import type { CommandResult, SandboxRuntime } from "../types.js";

const result = (exitCode = 0, stdout = "ok", stderr = ""): CommandResult => ({ exitCode, stdout, stderr });
function fixtures(violations: readonly { kind: "filesystem.write"; resource: string }[] = []) {
  const calls = { sandbox: 0, elevated: 0, approvals: 0 };
  const runtime: SandboxRuntime = {
    wrap: async command => `sandbox ${command}`,
    getViolationsForCommand: () => violations
  };
  const runner = {
    runSandbox: async () => { calls.sandbox++; return result(1, "", "normal failure"); },
    runHost: async () => { calls.elevated++; return result(0, "host"); }
  };
  const approvals = { request: async () => { calls.approvals++; return "sandbox-allow-once" as const; } };
  return { calls, runtime, runner, approvals };
}

test("ordinary sandbox failure never requests approval", async () => {
  const f = fixtures();
  const executor = new SelectiveSandboxExecutor({ runtime: f.runtime, runner: f.runner, approvals: f.approvals, policy: new CapabilityPolicy([]) });
  const output = await executor.execute("git status | cat", "call-1");
  assert.equal(output.disposition, "sandbox");
  assert.equal(f.calls.approvals, 0);
  assert.equal(f.calls.elevated, 0);
});

test("trace observation reaches the existing host replay approval path", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-executor-trace-"));
  const writable = join(root, "writable"), blocked = join(root, "blocked");
  await Promise.all([mkdir(writable), mkdir(blocked)]);
  const observer = new StraceViolationObserver(writable, { allow: [writable], deny: [] });
  const calls = { approval: 0, host: 0 };
  const runtime: SandboxRuntime = {
    wrap: async command => command,
    traceSinkForCommand: () => chunk => observer.ingest(chunk),
    getViolationsForCommand: () => observer.getViolations()
  };
  const executor = new SelectiveSandboxExecutor({
    runtime, policy: new CapabilityPolicy([]),
    runner: {
      runSandbox: async (_command, onTrace) => {
        onTrace?.(Buffer.from([
          '1 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0',
          '1 clone(flags=SIGCHLD) = 2',
          '2 execve("/usr/bin/bash", ["bash"], 0x0) = 0',
          `2 openat(AT_FDCWD<${blocked}>, "file", O_WRONLY|O_CREAT, 0666) = -1 EROFS (Read-only file system)`
        ].join("\n") + "\n"));
        return result(1);
      },
      runHost: async () => { calls.host++; return result(0); }
    },
    approvals: { request: async request => {
      calls.approval++;
      assert.deepEqual(request.capabilities.map(({ kind, resource }) => ({ kind, resource })), [{ kind: "filesystem.write", resource: blocked }]);
      return "host-allow-once";
    } }
  });
  const output = await executor.execute("touch ../blocked/file", "trace-call");
  assert.equal(output.disposition, "host");
  assert.equal(calls.approval, 1);
  assert.equal(calls.host, 1);
});

test("sandbox success is returned without entering escalation", async () => {
  const f = fixtures([{ kind: "filesystem.write", resource: "/reports/result.json" }]);
  f.runner.runSandbox = async () => { f.calls.sandbox++; return result(0, "done"); };
  const executor = new SelectiveSandboxExecutor({ runtime: f.runtime, runner: f.runner, approvals: f.approvals, policy: new CapabilityPolicy([]) });
  const output = await executor.execute("git status", "call-success");
  assert.equal(output.disposition, "sandbox");
  assert.equal(f.calls.approvals, 0);
  assert.equal(f.calls.elevated, 0);
});

test("an attributed violation asks, warns about replay, then selectively escalates", async () => {
  const f = fixtures([{ kind: "filesystem.write", resource: "/reports/result.json" }]);
  let request: { replayWarning: boolean; sessionGrantEligible?: boolean; projectGrantEligible?: boolean; capabilities: readonly { resource: string }[]; toolCallId: string; inputDigest: string } | undefined;
  const executor = new SelectiveSandboxExecutor({
    runtime: f.runtime, runner: f.runner, policy: new CapabilityPolicy([]),
    approvals: { request: async value => { request = value; return "sandbox-allow-once"; } }
  });
  const output = await executor.execute("cp result.json /reports/result.json", "call-2");
  assert.equal(output.disposition, "sandbox");
  assert.equal(f.calls.sandbox, 2);
  assert.equal(f.calls.elevated, 0);
  assert.equal(request?.replayWarning, true);
  assert.equal(request?.sessionGrantEligible, true);
  assert.equal(request?.toolCallId, "call-2");
  assert.match(request?.inputDigest ?? "", /^[a-f0-9]{64}$/);
  assert.deepEqual(request?.capabilities, [{ kind: "filesystem.write", resource: "/reports/result.json" }]);
});

test("mixed violations with a deny-root candidate suppress sandbox widening", async () => {
  const f = fixtures([
    { kind: "filesystem.write", resource: "/ordinary/output" },
    { kind: "filesystem.write", resource: "/denied/output" }
  ]);
  let offered: readonly { resource: string }[] | undefined;
  const executor = new SelectiveSandboxExecutor({
    runtime: f.runtime, runner: f.runner, policy: new CapabilityPolicy([]),
    canonicalizeCapabilities: async () => undefined,
    approvals: { request: async request => { offered = request.capabilities; return "host-allow-once"; } }
  });
  const output = await executor.execute("write two outputs", "mixed-deny");
  assert.equal(output.disposition, "host");
  assert.deepEqual(offered, []);
  assert.equal(f.calls.sandbox, 1);
  assert.equal(f.calls.elevated, 1);
});

test("a stored grant cannot hide a deny-root violation", async () => {
  const denied = { kind: "filesystem.write" as const, resource: "/denied/output" };
  const f = fixtures([denied]);
  let offered: readonly { resource: string }[] | undefined;
  const executor = new SelectiveSandboxExecutor({
    runtime: f.runtime, runner: f.runner, policy: new CapabilityPolicy([]),
    getSandboxCapabilities: async () => [denied],
    canonicalizeCapabilities: async () => undefined,
    approvals: { request: async request => { offered = request.capabilities; return "host-allow-once"; } }
  });
  assert.equal((await executor.execute("write denied output", "stored-deny")).disposition, "host");
  assert.deepEqual(offered, []);
  assert.equal(f.calls.elevated, 1);
});

test("post-violation auto policy still requires replay approval", async () => {
  const f = fixtures([{ kind: "filesystem.write", resource: "/reports/result.json" }]);
  const executor = new SelectiveSandboxExecutor({
    runtime: f.runtime, runner: f.runner, policy: new CapabilityPolicy([], "auto-escalate"), approvals: f.approvals
  });
  const output = await executor.execute("echo x >> local.log && cp x /reports/result.json", "call-auto");
  assert.equal(output.disposition, "sandbox");
  assert.equal(f.calls.approvals, 1);
  assert.equal(f.calls.elevated, 0);
});

test("policy can deny a real violation without host execution", async () => {
  const f = fixtures([{ kind: "filesystem.write", resource: "/forbidden/file" }]);
  const executor = new SelectiveSandboxExecutor({ runtime: f.runtime, runner: f.runner, approvals: f.approvals, policy: new CapabilityPolicy([{ kind: "filesystem.write", resource: /^\/forbidden/, decision: "deny" }]) });
  const output = await executor.execute("cp x /forbidden/file", "call-3");
  assert.equal(output.disposition, "denied");
  assert.equal(f.calls.approvals, 0);
  assert.equal(f.calls.elevated, 0);
});

test("sandbox initialization failure never falls back to host execution", async () => {
  const f = fixtures();
  const executor = new SelectiveSandboxExecutor({ runner: f.runner, policy: new CapabilityPolicy([]) });
  const output = await executor.execute("gh pr view 1", "call-4");
  assert.equal(output.disposition, "sandbox-unavailable");
  assert.equal(f.calls.sandbox + f.calls.elevated, 0);
});

test("classified initialization failure remains fail closed", async () => {
  const f = fixtures();
  const diagnostic = "Linux sandbox is unavailable because nested user namespaces are blocked. Host execution was not attempted.";
  const executor = new SelectiveSandboxExecutor({ runner: f.runner, policy: new CapabilityPolicy([]), sandboxUnavailableMessage: diagnostic });
  const output = await executor.execute("cargo test", "strict-unavailable");
  assert.equal(output.disposition, "sandbox-unavailable");
  assert.equal(output.stderr, diagnostic);
  assert.equal(f.calls.sandbox + f.calls.elevated + f.calls.approvals, 0);
});

test("sandbox wrapping failure can be classified without host fallback", async () => {
  const f = fixtures();
  f.runtime.wrap = async () => { throw new Error("apply-seccomp: Operation not permitted"); };
  const executor = new SelectiveSandboxExecutor({
    runtime: f.runtime,
    runner: f.runner,
    policy: new CapabilityPolicy([]),
    sandboxUnavailableMessage: error => `classified: ${error instanceof Error ? error.message : "unknown"}`
  });
  const output = await executor.execute("cargo test", "wrap-unavailable");
  assert.equal(output.disposition, "sandbox-unavailable");
  assert.match(output.stderr, /classified: apply-seccomp/);
  assert.equal(f.calls.sandbox + f.calls.elevated + f.calls.approvals, 0);
});

test("redaction occurs before results are returned", async () => {
  const f = fixtures();
  f.runner.runSandbox = async () => result(0, "ghp_verysecret");
  const executor = new SelectiveSandboxExecutor({ runtime: f.runtime, runner: f.runner, policy: new CapabilityPolicy([]), redactor: { redact: text => text.replace(/ghp_\w+/, "[REDACTED:GitHub Token]") } });
  assert.equal((await executor.execute("gh auth token", "call-5")).stdout, "[REDACTED:GitHub Token]");
});

test("only pure canonical helpers under an active trusted root are auto-approved", async () => {
  const root = await mkdtemp(join(tmpdir(), "trusted-skill-"));
  await mkdir(join(root, "scripts"));
  const helper = join(root, "scripts", "foo.py");
  await writeFile(helper, "print('ok')");
  const authority = { getActiveSkills: async () => [{ id: "demo", root, active: true, trusted: true }] };
  const documentation = join(root, "README.md");
  await writeFile(documentation, "not a helper");
  assert.ok(await findTrustedHelper(`python ${helper} --arg x`, authority));
  assert.equal(await findTrustedHelper(`python ${helper} | cat`, authority), undefined);
  const outside = join(tmpdir(), "outside-helper.py");
  assert.equal(await findTrustedHelper(`bash ${documentation}`, authority), undefined);
  await writeFile(outside, "print('outside')");
  await symlink(outside, join(root, "scripts", "escape.py"));
  assert.equal(await findTrustedHelper(`python ${join(root, "scripts", "escape.py")}`, authority), undefined);
  assert.equal(splitPureInvocation(`python ${helper} && rm -rf x`), undefined);
});

test("stored sandbox capabilities are applied before the first sandbox attempt", async () => {
  let extras: readonly { kind: string; resource: string }[] | undefined;
  const runtime: SandboxRuntime = {
    wrap: async (_command, context) => { extras = context.extraCapabilities; return "sandbox command"; },
    getViolationsForCommand: () => []
  };
  const runner = { runSandbox: async () => result(0), runHost: async () => result(0) };
  const executor = new SelectiveSandboxExecutor({ runtime, runner, policy: new CapabilityPolicy([]), getSandboxCapabilities: async () => [{ kind: "filesystem.write", resource: "/approved/output" }] });
  assert.equal((await executor.execute("touch /approved/output", "stored-grant")).disposition, "sandbox");
  assert.deepEqual(extras, [{ kind: "filesystem.write", resource: "/approved/output" }]);
});


test("stored sandbox grants suppress matching diagnostic telemetry on normal failure", async () => {
  const f = fixtures([{ kind: "filesystem.write", resource: "/approved/output" }]);
  const executor = new SelectiveSandboxExecutor({ runtime: f.runtime, runner: f.runner, approvals: f.approvals, policy: new CapabilityPolicy([]), getSandboxCapabilities: async () => [{ kind: "filesystem.write", resource: "/approved/output" }] });
  const output = await executor.execute("echo x > /approved/output; exit 1", "covered-telemetry");
  assert.equal(output.disposition, "sandbox");
  assert.equal(f.calls.approvals, 0);
  assert.equal(f.calls.elevated, 0);
});

test("one failure offers every observed write path together", async () => {
  const paths = ["/outside/first", "/other/second"];
  const offered: string[][] = [];
  const applied: string[][] = [];
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async (_command, context) => { applied.push(context.extraCapabilities?.map(capability => capability.resource) ?? []); return "sandbox command"; },
      getViolationsForCommand: () => paths.map(resource => ({ kind: "filesystem.write", resource }))
    },
    runner: { runSandbox: async () => result(applied.length === 1 ? 1 : 0), runHost: async () => { throw new Error("unexpected host run"); } },
    policy: new CapabilityPolicy([]),
    approvals: { request: async request => { offered.push(request.capabilities.map(capability => capability.resource)); return "sandbox-allow-once"; } }
  });
  const output = await executor.execute("write both paths", "multiple-paths");
  assert.equal(output.exitCode, 0);
  assert.deepEqual(offered, [paths]);
  assert.deepEqual(applied, [[], paths]);
});

test("a later write violation requests another grant before retrying", async () => {
  const first = "/outside/first", second = "/outside/second";
  const offered: string[][] = [];
  const applied: string[][] = [];
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async (_command, context) => { applied.push(context.extraCapabilities?.map(capability => capability.resource) ?? []); return "sandbox command"; },
      getViolationsForCommand: commandId => [{ kind: "filesystem.write", resource: commandId.endsWith(":1") ? second : first }]
    },
    runner: { runSandbox: async () => result(applied.length < 3 ? 1 : 0), runHost: async () => { throw new Error("unexpected host run"); } },
    policy: new CapabilityPolicy([]),
    approvals: { request: async request => { offered.push(request.capabilities.map(capability => capability.resource)); return "sandbox-allow-once"; } }
  });
  const output = await executor.execute("write first && write second", "sequential-paths");
  assert.equal(output.exitCode, 0);
  assert.deepEqual(offered, [[first], [second]]);
  assert.deepEqual(applied, [[], [first], [first, second]]);
});

test("denying a later write stops before a third sandbox run", async () => {
  const offered: string[][] = [];
  let runs = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async command => command,
      getViolationsForCommand: commandId => [{ kind: "filesystem.write", resource: commandId.endsWith(":1") ? "/second" : "/first" }]
    },
    runner: { runSandbox: async () => { runs++; return result(1); }, runHost: async () => { throw new Error("unexpected host run"); } },
    policy: new CapabilityPolicy([]),
    approvals: { request: async request => { offered.push(request.capabilities.map(capability => capability.resource)); return offered.length === 1 ? "sandbox-allow-once" : "deny"; } }
  });
  const output = await executor.execute("write first && write second", "deny-later");
  assert.equal(output.disposition, "denied");
  assert.equal(runs, 2);
  assert.deepEqual(offered, [["/first"], ["/second"]]);
});

test("a repeat violation under the approved capability does not prompt again", async () => {
  const offered: string[][] = [];
  let runs = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async command => command,
      getViolationsForCommand: () => [{ kind: "filesystem.write", resource: "/outside/file" }]
    },
    runner: { runSandbox: async () => { runs++; return result(1); }, runHost: async () => { throw new Error("unexpected host run"); } },
    policy: new CapabilityPolicy([]),
    canonicalizeCapabilities: async () => [{ kind: "filesystem.write", resource: "/outside" }],
    approvals: { request: async request => { offered.push(request.capabilities.map(capability => capability.resource)); return "sandbox-allow-once"; } }
  });
  const output = await executor.execute("write /outside/file", "repeat-path");
  assert.equal(output.disposition, "sandbox");
  assert.equal(runs, 2);
  assert.deepEqual(offered, [["/outside"]]);
});
