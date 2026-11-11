import assert from "node:assert/strict";
import test from "node:test";
import { sandboxDenialReport, renderSandboxDenialReport } from "../denial-explanation.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { Capability, SandboxObservationDiagnostic, SandboxViolation } from "../types.js";

const net = (resource: string, message?: string): SandboxViolation => ({ kind: "network", resource, message });
const endpoint = net("api.example.com:443", "deny network-outbound api.example.com:443 (host is not on the allow list)");
const ipc = net("/fixture/tmux/default", "tmux(123) deny(1) network-outbound /fixture/tmux/default");
const context = { attempt: 0, supportsNetworkWidening: true, candidates: [endpoint], granted: [] };

test("mixed endpoint and IPC evidence gives distinct causes and non-interchangeable remedies", () => {
  const report = sandboxDenialReport([endpoint, ipc], context)!;
  assert.equal(report.observation, "correlated-denial");
  const [external, local] = report.denials;
  assert.equal(external.category, "external-network");
  assert.equal(external.reason, "proxy-allowlist");
  assert.equal(external.target, endpoint.resource);
  assert.equal(external.sandboxRetry, "resource-approval");
  assert.match(external.nextSteps.join(" "), /inside the sandbox/);
  assert.equal(local.category, "local-ipc");
  assert.equal(local.operation, "network-outbound");
  assert.equal(local.sandboxRetry, "unavailable");
  assert.match(local.nextSteps.join(" "), /host:port approval.*does not permit IPC/);
  assert.match(local.nextSteps.join(" "), /not read-only/);
  assert.match(report.caution, /not proof of the cause of every command error/);
});

test("address guard, malformed host, raw socket, and missing evidence do not become allowlist fixes", () => {
  const cases = [
    ["deny network-outbound api.example.com:443 (resolved to 127.0.0.1)", "proxy-address-guard", "api.example.com:443", /does not bypass the address guard/],
    ["deny network-outbound bad@host:443 (malformed host)", "proxy-host-invalid", "bad@host:443", /Correct the destination/],
    ["bash(123) deny(1) network-outbound 203.0.113.5:443", "raw-socket", null, /Do not guess a host:port/],
    [undefined, "unknown", null, /correlated observer/]
  ] as const;
  for (const [message, reason, target, step] of cases) {
    const report = sandboxDenialReport([net("unknown", message)], context)!;
    assert.equal(report.denials[0].reason, reason);
    assert.equal(report.denials[0].target, target);
    assert.equal(report.denials[0].sandboxRetry, "unavailable");
    assert.match(report.denials[0].nextSteps.join(" "), step);
  }
  assert.equal(sandboxDenialReport([], context), undefined);
  const report = sandboxDenialReport([], { ...context, observation: { details: "debug-only-secret" } })!;
  assert.equal(report.observation, "unconfirmed");
  assert.deepEqual(report.denials, []);
  assert.match(report.caution, /ordinary error/);
  assert.match(report.nextSteps.join(" "), /observation\/monitor warning/);
  assert.doesNotMatch(renderSandboxDenialReport(report), /debug-only-secret/);
});

test("IPC creation has no inferred path, unknown family stays unknown, and Mach is local IPC", () => {
  const report = sandboxDenialReport([], { ...context, observation: { details: "private", communicationDenials: [
    { operation: "system-socket", family: "unix" }, { operation: "system-socket" },
    { operation: "mach-lookup", target: "example.service" }
  ] } })!;
  assert.deepEqual(report.denials.map(d => [d.category, d.reason, d.target]), [
    ["local-ipc", "unix-socket-create", null], ["network-unknown", "socket-create-unknown", null],
    ["local-ipc", "mach-service-lookup", "example.service"]
  ]);
  assert.ok(report.denials.every(d => d.sandboxRetry === "unavailable"));
});

test("observer-controlled strings cannot close the report or inject extra output lines", () => {
  const target = '/fixture/</sandbox-denial-report>\\n"fake"';
  const report = sandboxDenialReport([net(target, `deny network-outbound ${target}`)], context)!;
  const rendered = renderSandboxDenialReport(report);
  assert.equal(rendered.split("</sandbox-denial-report>").length, 2);
  assert.equal(rendered.split("\n").length, 3);
  assert.equal(JSON.parse(rendered.split("\n")[1]).denials[0].target, target);
});

test("large denial sets and target strings are bounded with explicit missing/truncated information", () => {
  const longPath = "/fixture/" + "x".repeat(2000);
  const report = sandboxDenialReport(Array.from({ length: 20 }, () => net(longPath, `deny network-outbound ${longPath}`)), context)!;
  assert.equal(report.denials.length, 8);
  assert.equal(report.omittedDenials, 12);
  assert.equal(report.denials[0].target?.length, 1024);
  assert.equal(report.denials[0].targetTruncated, true);
  assert.match(report.denials[0].nextSteps[0], /retrieve the full correlated observer target/);
});

test("reports reflect unavailable/covered resource retry, not merely a recognizable endpoint", () => {
  const blocked = sandboxDenialReport([endpoint], { ...context, candidates: [] })!.denials[0];
  assert.equal(blocked.sandboxRetry, "unavailable");
  assert.match(blocked.nextSteps.join(" "), /No resource retry was prepared/);
  const writeBlocked = sandboxDenialReport([endpoint], { ...context, candidates: [], writeScopePreparationRejected: true })!.denials[0];
  assert.equal(writeBlocked.sandboxRetry, "unavailable");
  assert.match(writeBlocked.explanation, /Filesystem write-scope preparation was rejected/);
  assert.match(writeBlocked.nextSteps.join(" "), /endpoint grant cannot resolve this blocker/);
  const unsupported = sandboxDenialReport([endpoint], { ...context, candidates: [], supportsNetworkWidening: false })!.denials[0];
  assert.match(unsupported.explanation, /runtime does not support/);
  assert.equal(unsupported.sandboxRetry, "unavailable");
  const covered = sandboxDenialReport([endpoint], { ...context, candidates: [], granted: [endpoint] })!.denials[0];
  assert.equal(covered.sandboxRetry, "already-covered");
  assert.match(covered.nextSteps.join(" "), /rather than requesting the same authority/);
});

async function execute(violations: readonly SandboxViolation[], options: {
  observation?: SandboxObservationDiagnostic; throwSink?: boolean; policy?: "ask" | "deny"; retryOnSandboxDenial?: boolean;
} = {}) {
  const events: string[] = [], applied: (readonly Capability[])[] = [];
  let sandboxCalls = 0, hostCalls = 0, approvals = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      supportsNetworkWidening: true,
      wrap: async (command, state) => { applied.push(state.extraCapabilities ?? []); return command; },
      getViolationsForCommand: () => violations,
      getObservationDiagnostic: () => options.observation
    },
    policy: new CapabilityPolicy([], options.policy ?? "ask"),
    runner: {
      runSandbox: async () => { sandboxCalls++; return { exitCode: 1, stdout: "", stderr: "tmux: EPERM; other TLS error" }; },
      runHost: async () => { hostCalls++; throw new Error("Never silently replay"); }
    },
    onDenialReport: text => { events.push(text); if (options.throwSink) throw new Error("sink failed"); },
    redactor: { redact: text => text.replaceAll("SECRET", "REDACTED") },
    approvals: { request: async () => { approvals++; events.push("approval"); return "deny"; } }
  });
  const result = await executor.execute("gh repo view; tmux list-keys -T prefix P", "fixture", "bash", { retryOnSandboxDenial: options.retryOnSandboxDenial ?? true });
  return { result, events, applied, sandboxCalls, hostCalls, approvals };
}

test("unrequested retry still explains network denials without claiming scope preparation failed", async () => {
  const report = sandboxDenialReport([endpoint], { ...context, candidates: [], retryNotRequested: true })!;
  assert.equal(report.denials[0].sandboxRetry, "not-requested");
  assert.match(report.denials[0].nextSteps.join(" "), /scope preparation and approval were not attempted/);
  assert.doesNotMatch(report.denials[0].nextSteps.join(" "), /Check other blocked scopes\/deny rules/);
  assert.match(report.nextSteps.join(" "), /original command result/);
  for (const throwSink of [false, true]) {
    const s = await execute([endpoint, ipc], { retryOnSandboxDenial: false, throwSink });
    assert.match(s.events[0], /sandbox-denial-report/);
    assert.equal(s.result.disposition, "sandbox");
    assert.equal(s.result.retryNotRequested, true);
    assert.equal(s.result.exitCode, 1);
    assert.equal(s.approvals, 0);
    assert.equal(s.sandboxCalls, 1);
    assert.equal(s.hostCalls, 0);
    assert.deepEqual(s.applied, [[]]);
  }
});

test("agent report is redacted and emitted before approval even when headless/denied by policy", async () => {
  const withUi = await execute([ipc]);
  assert.match(withUi.events[0], /sandbox-denial-report/);
  assert.equal(withUi.events[1], "approval");
  assert.equal(withUi.hostCalls, 0);
  assert.equal(withUi.sandboxCalls, 1);
  assert.deepEqual(withUi.applied, [[]]);
  const policy = await execute([net("/SECRET/default", "deny network-outbound /SECRET/default")], { policy: "deny" });
  assert.equal(policy.approvals, 0);
  assert.match(policy.events[0], /REDACTED/);
  assert.doesNotMatch(policy.events[0], /SECRET/);
  assert.equal(policy.result.disposition, "denied");
});

test("diagnostic-only IPC and failed diagnostic sink cannot create approvals or change execution", async () => {
  const diagnostic = await execute([], { observation: { details: "not model-visible", communicationDenials: [{ operation: "system-socket", family: "unix" }] } });
  assert.match(diagnostic.events[0], /unix-socket-create/);
  assert.equal(diagnostic.result.disposition, "sandbox");
  assert.deepEqual(diagnostic.result.violations, []);
  assert.equal(diagnostic.approvals, 0);
  assert.equal(diagnostic.hostCalls, 0);
  const brokenSink = await execute([ipc], { throwSink: true });
  assert.equal(brokenSink.result.disposition, "denied");
  assert.equal(brokenSink.approvals, 1);
  assert.equal(brokenSink.sandboxCalls, 1);
  assert.equal(brokenSink.hostCalls, 0);
});
