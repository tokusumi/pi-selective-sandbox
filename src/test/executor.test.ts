import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { findTrustedHelper, splitPureInvocation } from "../skills.js";
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
