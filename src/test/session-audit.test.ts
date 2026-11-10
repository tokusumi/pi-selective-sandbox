import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";
import { SessionManager, type CustomEntry, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { ApprovalDiagnostics, type ApprovalDiagnosticEvent } from "../approval-diagnostics.js";
import { createSessionAuditSink, SESSION_AUDIT_TYPE, SESSION_AUDIT_STATUS_TYPE, withSessionAuditLink } from "../session-audit.js";
import { networkDiagnostics } from "../network-diagnostics.js";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { DEFAULT_WRITE_PROFILES } from "../config.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { ApprovalRequest } from "../types.js";

const secret = "credential-super-private";
const request: ApprovalRequest = { kind: "escalation", toolCallId: secret, toolName: "bash", command: secret, inputDigest: secret,
  capabilities: [{ kind: "network", resource: `private-${secret}.example:443` }], replayWarning: true };
function fixture() {
  const rows: { type: string; customType: string; data: unknown }[] = [];
  const d = new ApprovalDiagnostics(event => sink.sink(event));
  const sink = createSessionAuditSink((type, data) => rows.push({ type: "custom", customType: type, data }), d.originId);
  sink.start();
  return { rows, d, sink, trace: d.trace(request) };
}

test("session sink keeps closed facts and opaque links, not raw extras or model messages", () => {
  const { rows, d, trace } = fixture();
  d.emit(trace, Object.assign({ event: "attempt.denial" as const, relation: "first" as const, observed: d.scopes(request.capabilities),
    network: [{ id: d.token("scope", "network\0" + request.capabilities[0].resource), reason: "proxy-allowlist" as const, family: "other" as const }] },
    { command: secret, path: secret, message: secret, token: secret }));
  assert.equal(rows[0].customType, SESSION_AUDIT_STATUS_TYPE);
  assert.equal(rows[1].customType, SESSION_AUDIT_TYPE);
  assert.ok(!JSON.stringify(rows).includes(secret));
  const result = withSessionAuditLink({ details: { original: true }, content: [] }, d.originId, d.token("call", secret));
  assert.equal(result.details.original, true);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal((rows[1].data as ApprovalDiagnosticEvent).callId, d.token("call", secret));
  const manager = SessionManager.inMemory();
  manager.appendMessage({ role: "user", content: "fixture", timestamp: Date.now() });
  const before = manager.buildSessionContext().messages;
  for (const row of rows) manager.appendCustomEntry(row.customType, row.data);
  assert.deepEqual(manager.buildSessionContext().messages, before);
});

test("caps and write failures are visible, bounded and do not throw", () => {
  const rows: { type: string; data: unknown }[] = [];
  const d = new ApprovalDiagnostics(() => {}), trace = d.trace(request);
  const event: ApprovalDiagnosticEvent = { ...trace, event: "provider.start", version: 1, emitterId: d.originId, sequence: 1, time: Date.now() };
  for (const limits of [{ maxEvents: 1 }, { maxBytes: 1 }]) {
    rows.length = 0;
    const sink = createSessionAuditSink((type, data) => { rows.push({ type, data }); }, d.originId, limits);
    sink.start(); for (let i = 0; i < 100; i++) sink.sink(event);
    assert.equal(rows.filter(r => r.type === SESSION_AUDIT_STATUS_TYPE && (r.data as { status: string }).status === "truncated").length, 1);
    assert.ok(rows.length <= 3);
  }
  let calls = 0;
  const broken = createSessionAuditSink((type) => { calls++; if (type === SESSION_AUDIT_TYPE) throw new Error(secret); }, d.originId);
  broken.start(); broken.sink(event); broken.sink(event);
  assert.equal(calls, 3); // manifest, failed event, loss notice; no repeated write attempts
});

test("closing a session stops late callback writes and reload identities are independent", () => {
  const first = fixture(), second = fixture();
  first.sink.close(); const count = first.rows.length;
  first.d.emit(first.trace, { event: "provider.response", outcome: "allow" });
  assert.equal(first.rows.length, count);
  assert.notEqual(first.d.token("call", secret), second.d.token("call", secret));
  assert.notDeepEqual(first.d.scopes(request.capabilities), second.d.scopes(request.capabilities));
});

test("observer classifications distinguish endpoints, sockets, address guard and unknown without raw identities", () => {
  const d = new ApprovalDiagnostics(() => {});
  const observed = [
    { kind: "network" as const, resource: "results-receiver.actions.githubusercontent.com:443", message: "deny network-outbound results-receiver.actions.githubusercontent.com:443 (host is not on the allow list)" },
    { kind: "network" as const, resource: `/private/${secret}.sock`, message: `deny(1) network-bind /private/${secret}.sock` },
    { kind: "network" as const, resource: "unknown", message: `deny network-outbound ${secret}.example:443 (resolved to a loopback address)` },
    { kind: "network" as const, resource: "unknown", message: "deny(1) network-outbound 192.0.2.1:443" },
    { kind: "network" as const, resource: "unknown", message: secret },
  ];
  const info = networkDiagnostics(observed, resource => d.token("scope", resource));
  assert.deepEqual(info.map(i => i.reason), ["proxy-allowlist", "unix-socket", "proxy-address-guard", "raw-socket", "unknown"]);
  assert.equal(info[0].family, "github-actions");
  assert.ok(!JSON.stringify(info).includes(secret));
  assert.ok(!JSON.stringify(info).includes("192.0.2.1"));
});

test("failed host replay and denial type can be reconstructed from persisted safe events", async () => {
  const { rows, d } = fixture();
  let attempt = 0;
  const executor = new SelectiveSandboxExecutor({ diagnostics: d, runtime: { supportsNetworkWidening: true,
    wrap: async () => "fixture", forgetCommand() {}, getViolationsForCommand: () => [{ kind: "network", resource: `/private/${secret}.sock`, message: `deny(1) network-bind /private/${secret}.sock` }] },
    runner: { runSandbox: async () => ({ exitCode: ++attempt, stdout: "", stderr: secret }), runHost: async () => ({ exitCode: 7, stdout: "", stderr: secret }) },
    policy: new CapabilityPolicy([], "ask"), approvals: { request: async () => "host-allow-once" } });
  const output = await executor.execute(secret, secret);
  assert.equal(output.disposition, "host"); assert.equal(output.exitCode, 7);
  const events = rows.filter(row => row.customType === SESSION_AUDIT_TYPE).map(row => row.data as ApprovalDiagnosticEvent);
  assert.ok(events.some(e => e.event === "attempt.denial" && e.network?.[0].reason === "unix-socket"));
  assert.ok(events.some(e => e.event === "attempt.result" && e.execution === "host" && e.exitCode === 7));
  assert.ok(events.some(e => e.event === "operation.end" && e.disposition === "host" && e.exitCode === 7));
  assert.ok(!JSON.stringify(rows).includes(secret));
});

test("default extension records into a real session without opt-in and links even failed native tool results", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-session-default-"));
  const old = { dir: process.env.PI_CODING_AGENT_DIR, audit: process.env.PI_SELECTIVE_SANDBOX_SESSION_AUDIT, diagnostic: process.env.PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS };
  process.env.PI_CODING_AGENT_DIR = base;
  delete process.env.PI_SELECTIVE_SANDBOX_SESSION_AUDIT;
  delete process.env.PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS;
  t.after(async () => {
    for (const [key, value] of [["PI_CODING_AGENT_DIR", old.dir], ["PI_SELECTIVE_SANDBOX_SESSION_AUDIT", old.audit], ["PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS", old.diagnostic]] as const) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(base, { recursive: true, force: true });
  });
  await mkdir(join(base, "pi-selective-sandbox"));
  await writeFile(join(base, "pi-selective-sandbox", "config.json"), JSON.stringify({ filesystem: { disabledDefaultProfiles: DEFAULT_WRITE_PROFILES } }));
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({ logMonitorEnabled: true, dispose: async () => {} }) as AnthropicSandboxRuntime);
  const manager = SessionManager.create(base, join(base, "sessions"));
  manager.appendMessage({ role: "user", content: "fixture", timestamp: Date.now() });
  const handlers = new Map<string, (...args: any[]) => any>(), tools = new Map<string, ToolDefinition>();
  const api = { on: (name: string, handler: (...args: any[]) => any) => { handlers.set(name, handler); },
    appendEntry: (type: string, data: unknown) => manager.appendCustomEntry(type, data), registerCommand() {},
    registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); } };
  await selectiveSandboxExtension(api as never, { loadSubagentApi: async () => undefined });
  const context = { cwd: base, hasUI: false, sessionManager: manager };
  await handlers.get("session_start")!({}, context);
  await assert.rejects(tools.get("write")!.execute("fixture-call", { path: join(base, "blocked"), content: secret }, new AbortController().signal, () => {}, context as never), /Permission denied/);
  const patch = handlers.get("tool_result")!({ toolName: "write", toolCallId: "fixture-call", details: undefined, isError: true });
  manager.appendMessage({ role: "toolResult", toolCallId: "fixture-call", toolName: "write", content: [{ type: "text", text: "denied" }], isError: true, details: patch.details, timestamp: Date.now() });
  const data = await readFile(manager.getSessionFile()!, "utf8");
  assert.ok(data.includes(SESSION_AUDIT_TYPE)); assert.ok(data.includes(SESSION_AUDIT_STATUS_TYPE));
  assert.ok(!data.includes(secret));
  const custom = manager.getEntries().filter((e): e is CustomEntry => e.type === "custom" && e.customType === SESSION_AUDIT_TYPE);
  assert.ok(custom.some(e => (e.data as ApprovalDiagnosticEvent).event === "provider.response"));
  const call = patch.details.selectiveSandboxAudit;
  assert.ok(custom.some(e => (e.data as ApprovalDiagnosticEvent).callId === call.callId));
  const { stdout } = await promisify(execFile)(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", manager.getSessionFile()!]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.sessionFilesWithAudit, 1); assert.equal(summary.providerCalls, 1);
  assert.equal(summary.requestsWithLinkedToolResult, 1); assert.equal(summary.selectorsInvoked, 0);
  await handlers.get("session_shutdown")!();
  assert.equal(handlers.get("tool_result")!({ toolName: "write", toolCallId: "late" }), undefined);

  process.env.PI_SELECTIVE_SANDBOX_SESSION_AUDIT = "0";
  const before = manager.getEntries().length;
  await selectiveSandboxExtension(api as never, { loadSubagentApi: async () => undefined });
  await handlers.get("session_start")!({}, context);
  assert.equal(manager.getEntries().length, before);
  assert.equal(handlers.get("tool_result")!({ toolName: "write", toolCallId: "disabled" }), undefined);
  await handlers.get("session_shutdown")!();
});

test("concurrent operations keep independent opaque tool links and final outcomes", async () => {
  const { rows, d } = fixture();
  const executor = new SelectiveSandboxExecutor({ diagnostics: d, runtime: { supportsNetworkWidening: true,
    wrap: async () => "fixture", forgetCommand() {}, getViolationsForCommand: () => [{ kind: "network", resource: "unknown" }] },
    runner: { runSandbox: async () => ({ exitCode: 1, stdout: "", stderr: "" }), runHost: async () => assert.fail("host") },
    policy: new CapabilityPolicy([], "deny") });
  await Promise.all([executor.execute(secret, secret + "-one"), executor.execute(secret, secret + "-two")]);
  const ends = rows.filter(row => row.customType === SESSION_AUDIT_TYPE).map(row => row.data as ApprovalDiagnosticEvent).filter(e => e.event === "operation.end");
  assert.equal(ends.length, 2); assert.equal(new Set(ends.map(e => e.operationId)).size, 2);
  assert.equal(new Set(ends.map(e => e.callId)).size, 2);
  assert.ok(ends.every(e => e.disposition === "denied"));
  assert.ok(!JSON.stringify(rows).includes(secret));
});

test("a thrown host runner error is recorded without its text and propagates unchanged", async () => {
  const { rows, d } = fixture(), error = new Error(secret);
  const executor = new SelectiveSandboxExecutor({ diagnostics: d, runtime: { supportsNetworkWidening: true,
    wrap: async () => "fixture", forgetCommand() {}, getViolationsForCommand: () => [{ kind: "network", resource: "unknown" }] },
    runner: { runSandbox: async () => ({ exitCode: 1, stdout: "", stderr: "" }), runHost: async () => { throw error; } },
    policy: new CapabilityPolicy([], "ask"), approvals: { request: async () => "host-allow-once" } });
  await assert.rejects(executor.execute(secret, secret), e => e === error);
  const events = rows.filter(row => row.customType === SESSION_AUDIT_TYPE).map(row => row.data as ApprovalDiagnosticEvent);
  assert.ok(events.some(e => e.event === "attempt.result" && e.execution === "host" && e.outcome === "error" && e.exitCode === undefined));
  assert.ok(events.some(e => e.event === "operation.end" && e.disposition === "host" && e.outcome === "error"));
  assert.ok(!JSON.stringify(rows).includes(secret));
});

test("session projection does not coerce object IDs or access unrelated extra fields", () => {
  const { rows, d, sink, trace } = fixture();
  const valid: ApprovalDiagnosticEvent = { ...trace, version: 1, emitterId: d.originId, sequence: 1, time: Date.now(), event: "provider.start" };
  Object.defineProperty(valid, "unrelated", { enumerable: true, get() { throw new Error(secret); } });
  sink.sink(valid);
  assert.equal(rows[1].customType, SESSION_AUDIT_TYPE);
  const malformed = JSON.parse(JSON.stringify({ ...trace, version: 1, emitterId: d.originId, sequence: 2, time: Date.now(), event: "provider.start" }));
  malformed.selectorId = { toString: secret };
  malformed.scopes = [null, { kind: "network", id: { toString: secret } }];
  malformed.network = [null, { id: { toString: secret }, reason: "unknown", family: "other" }];
  sink.sink(malformed);
  assert.equal(rows[2].customType, SESSION_AUDIT_TYPE);
  assert.deepEqual((rows[2].data as ApprovalDiagnosticEvent).scopes, []);
  assert.ok(!JSON.stringify(rows).includes(secret));
});
