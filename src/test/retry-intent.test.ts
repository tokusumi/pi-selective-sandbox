import assert from "node:assert/strict";
import test from "node:test";
import { ApprovalDiagnostics, type ApprovalDiagnosticEvent } from "../approval-diagnostics.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { createApprovalProvider } from "../pi-extension.js";
import { ProjectGrantStore } from "../project-grants.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";
import { SessionGrantStore } from "../session-grants.js";
import { SessionHostCommandGrantStore } from "../session-host-command-grants.js";
import { sessionAuditEvent } from "../session-audit.js";
import type { SandboxExecutionOptions, SandboxViolation } from "../types.js";
import { commandOutcomeFixtures } from "./command-outcome-fixtures.js";

const observations: SandboxViolation[][] = [
  [{ kind: "network", resource: "unknown", message: "fixture unsupported denial" }],
  [{ kind: "network", resource: "api.github.com:443" }],
  [{ kind: "filesystem.write", resource: "/outside/file" }],
  [{ kind: "filesystem.read", resource: "/private/config" }, { kind: "network", resource: "unknown" }]
];

for (const fixture of commandOutcomeFixtures) {
  test(`${fixture.name}: original result survives without unrequested retry, regardless of command or denial type`, async () => {
    for (const command of [fixture.command, "unrelated application command"]) for (const observed of observations) {
      const events: ApprovalDiagnosticEvent[] = [], markers: string[] = [];
      const order: string[] = [];
      const executor = new SelectiveSandboxExecutor({
        runtime: {
          supportsNetworkWidening: true,
          wrap: async text => text,
          getViolationsForCommand: () => { order.push("observe"); return observed; },
          forgetCommand: () => { order.push("forget"); }
        },
        runner: { runSandbox: async () => { order.push("sandbox"); return fixture.result; }, runHost: async () => assert.fail("unrequested host replay") },
        policy: { decide: () => assert.fail("retry policy must not run without retry intent") },
        canonicalizeCapabilities: async () => assert.fail("scope preparation before intent gate"),
        commandIdentity: async () => assert.fail("command matching before intent gate"),
        approvals: { request: async () => assert.fail("unrequested approval, including stored host lookup") },
        diagnostics: new ApprovalDiagnostics(event => events.push(event)),
        onStatus: marker => markers.push(marker)
      });
      const output = await executor.execute(command, "fixture");
      assert.equal(output.exitCode, fixture.result.exitCode);
      assert.equal(output.stdout, fixture.result.stdout);
      assert.equal(output.stderr, fixture.result.stderr);
      assert.equal(output.disposition, "sandbox", "observed denial is neither a causal diagnosis nor a rejected approval");
      if (fixture.result.exitCode === 0) {
        assert.deepEqual(order, ["sandbox", "forget"]);
        assert.deepEqual(output.violations, []);
        assert.equal(output.retryNotRequested, undefined);
        assert.deepEqual(markers, []);
      } else {
        assert.deepEqual(order, ["sandbox", "observe", "forget"]);
        assert.deepEqual(output.violations, observed);
        assert.equal(output.retryNotRequested, true);
        assert.deepEqual(markers, ["<sandbox: denial-observed retry-not-requested>"]);
        const skipped = events.find(event => event.event === "retry")!;
        assert.equal(skipped.reason, "not-requested");
        assert.equal(skipped.outcome, "skipped");
        assert.equal(sessionAuditEvent(skipped)?.reason, "not-requested");
      }
      assert.equal(events.at(-1)?.exitCode, fixture.result.exitCode);
      assert.equal(events.at(-1)?.disposition, "sandbox");
      assert.ok(!events.some(event => event.event === "provider.start"));
      assert.doesNotMatch(JSON.stringify(events), /outside|private|fixture unsupported denial/);
    }
  });
}

test("only literal true requests retry, and intent cannot leak between invocations of one executor", async () => {
  let sandbox = 0, host = 0, approval = 0, observed = 0, forgotten = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: { wrap: async text => text, getViolationsForCommand: () => { observed++; return observations[0]; }, forgetCommand: () => { forgotten++; } },
    runner: {
      runSandbox: async () => { sandbox++; return { exitCode: 8, stdout: "opaque status", stderr: "" }; },
      runHost: async () => { host++; return { exitCode: 3, stdout: "explicit host fixture", stderr: "" }; }
    },
    policy: { decide: () => "ask" },
    approvals: { request: async () => { approval++; return "host-allow-once"; } }
  });
  for (const retryOnSandboxDenial of [undefined, false, "true", 1]) {
    const output = await executor.execute("opaque application", "not-requested", "bash", { retryOnSandboxDenial } as SandboxExecutionOptions);
    assert.equal(output.retryNotRequested, true);
  }
  assert.equal(approval, 0);
  const optedIn = await executor.execute("opaque application", "requested", "bash", { retryOnSandboxDenial: true });
  assert.equal(optedIn.disposition, "host");
  assert.equal(optedIn.exitCode, 3);
  const subsequent = await executor.execute("opaque application", "default-again");
  assert.equal(subsequent.exitCode, 8);
  assert.equal(subsequent.retryNotRequested, true);
  assert.deepEqual({ sandbox, host, approval, observed, forgotten }, { sandbox: 6, host: 1, approval: 1, observed: 6, forgotten: 6 });
});

test("a matching stored host grant is permission, not retry intent (session and project)", async t => {
  const identity = { shellCommand: "opaque application", cwd: "/canonical/project", executionMode: "shell" };
  for (const scope of ["session", "project"] as const) {
    const hosts = new SessionHostCommandGrantStore();
    hosts.grant("session", identity);
    const projectHosts = new ProjectHostCommandGrantStore("/not-used-host-grants.json");
    const covers = t.mock.method(projectHosts, "covers", async () => true);
    const provider = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "session" } }, new SessionGrantStore(),
      scope === "project" ? { projectId: "/project", grants: new ProjectGrantStore("/not-used-grants.json"), hostGrants: projectHosts } : undefined, hosts);
    let requests = 0, hostRuns = 0;
    const executor = new SelectiveSandboxExecutor({
      runtime: { wrap: async text => text, getViolationsForCommand: () => observations[0] },
      runner: { runSandbox: async () => commandOutcomeFixtures[0].result, runHost: async () => { hostRuns++; return commandOutcomeFixtures[0].result; } },
      commandIdentity: async () => identity, policy: { decide: () => "ask" },
      approvals: { request: async request => { requests++; return provider.request(request); } }
    });
    const original = await executor.execute(identity.shellCommand, "stored-default");
    assert.equal(original.exitCode, 8);
    assert.equal(original.retryNotRequested, true);
    assert.equal(requests, 0);
    assert.equal(covers.mock.callCount(), 0);
    assert.equal(hostRuns, 0);
    const requested = await executor.execute(identity.shellCommand, "stored-requested", "bash", { retryOnSandboxDenial: true });
    assert.equal(requested.disposition, "host");
    assert.equal(requested.exitCode, 8, "explicit retry does not launder a nonzero host result into success");
    assert.equal(requests, 1);
    assert.equal(hostRuns, 1);
    assert.equal(covers.mock.callCount(), scope === "project" ? 1 : 0);
  }
});

test("default return retains redaction and never inspects application output for causality", async () => {
  const original = { exitCode: 1, stdout: "secret pending", stderr: "secret EACCES" };
  const executor = new SelectiveSandboxExecutor({
    runtime: { wrap: async text => text, getViolationsForCommand: () => observations[0] },
    runner: { runSandbox: async () => original, runHost: async () => assert.fail("host") },
    policy: { decide: () => "auto-escalate" }, approvals: { request: async () => assert.fail("approval") },
    redactor: { redact: text => text.replaceAll("secret", "[REDACTED]") }
  });
  const output = await executor.execute("unrelated command", "redacted");
  assert.equal(output.stdout, "[REDACTED] pending");
  assert.equal(output.stderr, "[REDACTED] EACCES");
  assert.equal(output.exitCode, 1);
  assert.equal(original.stdout, "secret pending");
});

test("retry intent is captured before any asynchronous work", async () => {
  const options: SandboxExecutionOptions = {};
  const executor = new SelectiveSandboxExecutor({
    runtime: { wrap: async text => text, getViolationsForCommand: () => observations[0] },
    runner: { runSandbox: async () => { options.retryOnSandboxDenial = true; return commandOutcomeFixtures[0].result; }, runHost: async () => assert.fail("late intent cannot authorize replay") },
    policy: { decide: () => assert.fail("late intent cannot start approval") }
  });
  const output = await executor.execute("opaque application", "snapshot", "bash", options);
  assert.equal(output.retryNotRequested, true);
  assert.equal(output.exitCode, 8);
});

test("retry intent alone cannot cause replay without observations, policy permission and approval", async () => {
  for (const mode of ["no-denial", "policy-deny", "no-provider", "approval-deny"] as const) {
    let runs = 0, requests = 0;
    const executor = new SelectiveSandboxExecutor({
      runtime: { wrap: async text => text, getViolationsForCommand: () => mode === "no-denial" ? [] : observations[0] },
      runner: { runSandbox: async () => { runs++; return commandOutcomeFixtures[3].result; }, runHost: async () => assert.fail("host without permission") },
      policy: { decide: () => mode === "policy-deny" ? "deny" : "ask" },
      approvals: mode === "no-provider" ? undefined : { request: async () => { requests++; return "deny"; } }
    });
    const output = await executor.execute("opaque application", mode, "bash", { retryOnSandboxDenial: true });
    assert.equal(output.exitCode, 1);
    assert.equal(output.disposition, mode === "no-denial" ? "sandbox" : "denied");
    assert.equal(output.retryNotRequested, undefined);
    assert.equal(requests, mode === "approval-deny" ? 1 : 0);
    assert.equal(runs, 1);
  }
});
