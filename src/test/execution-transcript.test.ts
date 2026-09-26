import assert from "node:assert/strict";
import test from "node:test";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { ApprovalResponse, CommandResult, SandboxRuntime } from "../types.js";

const erofs = "fatal: Unable to create '.git/index.lock': Read-only file system\n";
const writeViolation = [{ kind: "filesystem.write" as const, resource: "/project/.git" }];
const result = (exitCode: number): CommandResult => ({ exitCode, stdout: "", stderr: "" });

async function runScenario({ initialExit, initialOutput, retryExit, replayExit, approval, violations = writeViolation }: {
  initialExit: number;
  initialOutput?: string;
  retryExit?: number;
  replayExit?: number;
  approval?: ApprovalResponse;
  violations?: typeof writeViolation;
}) {
  const transcript: string[] = [];
  const events: string[] = [];
  const stream = (chunk: string) => { transcript.push(chunk); events.push(chunk); };
  let sandboxRuns = 0;
  let hostRuns = 0;
  const runtime: SandboxRuntime = {
    wrap: async command => command,
    getViolationsForCommand: () => violations
  };
  const executor = new SelectiveSandboxExecutor({
    runtime,
    policy: new CapabilityPolicy([]),
    runner: {
      runSandbox: async () => {
        sandboxRuns++;
        if (sandboxRuns === 1) {
          stream(initialOutput ?? (initialExit === 0 ? "initial success\n" : erofs));
          return result(initialExit);
        }
        stream("retry output\n");
        return result(retryExit ?? 0);
      },
      runHost: async () => { hostRuns++; stream("replay output\n"); return result(replayExit ?? 0); }
    },
    approvals: { request: async () => {
      events.push("approval UI\n");
      return approval ?? "deny";
    } },
    commandIdentity: async shellCommand => ({ shellCommand, cwd: "/project", executionMode: "shell" }),
    onStatus: marker => stream(`${marker}\n`)
  });
  const output = await executor.execute("git add .", "call");
  return { output, transcript: transcript.join(""), events: events.join(""), sandboxRuns, hostRuns };
}

test("EROFS then approved widening streams attempt transitions and adopts successful retry", async () => {
  const { output, transcript, events, sandboxRuns, hostRuns } = await runScenario({ initialExit: 128, retryExit: 0, approval: "sandbox-allow-once" });
  assert.equal(output.exitCode, 0);
  assert.equal(output.disposition, "sandbox");
  assert.equal(sandboxRuns, 2);
  assert.equal(hostRuns, 0);
  assert.equal(transcript, erofs
    + "<sandbox: approval-required filesystem.write>\n"
    + "<sandbox: approved widen retry>\n"
    + "retry output\n"
    + "<sandbox: retry exit=0>\n");
  assert.ok(events.indexOf("<sandbox: approval-required filesystem.write>") < events.indexOf("approval UI"));
  assert.ok(events.indexOf("approval UI") < events.indexOf("<sandbox: approved widen retry>"));
});

test("EROFS then approved widening adopts a failing retry exit code", async () => {
  const { output, transcript } = await runScenario({ initialExit: 128, retryExit: 7, approval: "sandbox-allow-once" });
  assert.equal(output.exitCode, 7);
  assert.match(transcript, /<sandbox: retry exit=7>\n$/);
});

test("EROFS then approved host replay streams replay markers and adopts replay success", async () => {
  const { output, transcript, sandboxRuns, hostRuns } = await runScenario({ initialExit: 128, replayExit: 0, approval: "host-allow-once" });
  assert.equal(output.exitCode, 0);
  assert.equal(output.disposition, "host");
  assert.equal(sandboxRuns, 1);
  assert.equal(hostRuns, 1);
  assert.equal(transcript, erofs
    + "<sandbox: approval-required filesystem.write>\n"
    + "<sandbox: approved host-replay>\n"
    + "replay output\n"
    + "<sandbox: replay exit=0>\n");
});

test("EROFS then denied approval retains the initial sandbox exit code", async () => {
  const { output, transcript, sandboxRuns, hostRuns } = await runScenario({ initialExit: 128, approval: "deny" });
  assert.equal(output.exitCode, 128);
  assert.equal(output.disposition, "denied");
  assert.equal(sandboxRuns, 1);
  assert.equal(hostRuns, 0);
  assert.equal(transcript, erofs
    + "<sandbox: approval-required filesystem.write>\n"
    + "<sandbox: approval-denied>\n");
});

test("ordinary sandbox failure has no markers or approval", async () => {
  const { output, transcript, sandboxRuns, hostRuns } = await runScenario({ initialExit: 2, initialOutput: "command failed\n", violations: [] });
  assert.equal(output.exitCode, 2);
  assert.equal(output.disposition, "sandbox");
  assert.equal(transcript, "command failed\n");
  assert.equal(sandboxRuns, 1);
  assert.equal(hostRuns, 0);
});

test("normal sandbox success has no markers or approval", async () => {
  const { output, transcript, sandboxRuns, hostRuns } = await runScenario({ initialExit: 0 });
  assert.equal(output.exitCode, 0);
  assert.equal(output.disposition, "sandbox");
  assert.equal(transcript, "initial success\n");
  assert.equal(sandboxRuns, 1);
  assert.equal(hostRuns, 0);
});
