import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, realpath, rm, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { ApprovalDiagnostics, createDiagnosticFileSink, selectorTrace, type ApprovalDiagnosticEvent } from "../approval-diagnostics.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { ProjectGrantStore } from "../project-grants.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";
import { SessionGrantStore } from "../session-grants.js";
import { SessionHostCommandGrantStore } from "../session-host-command-grants.js";
import { bridgeApprovalContext, startApprovalBridge } from "../subagent-approval.js";
import type { EscalationUI } from "../widening-dialog.js";
import type { ApprovalRequest, Capability, EscalationApprovalRequest } from "../types.js";

const secret = "credential-super-private";
const cap: Capability = { kind: "network", resource: `private-${secret}.example:443` };
const request = (native = false): ApprovalRequest => ({ ...(native ? {} : { kind: "escalation" as const, commandIdentity: { shellCommand: secret, cwd: `/private/${secret}`, executionMode: "shell" }, observedCapabilities: [{ ...cap, message: secret }] }),
  toolCallId: secret, toolName: native ? "write" : "bash", inputDigest: secret, command: secret, capabilities: [cap], replayWarning: !native, sessionGrantEligible: true, projectGrantEligible: true });
const fixture = async (t: test.TestContext) => { const root = await mkdtemp(join(tmpdir(), "pi-approval-telemetry-")); t.after(() => rm(root, { recursive: true, force: true })); return root; };
function telemetry() { const events: ApprovalDiagnosticEvent[] = []; return { events, diagnostics: new ApprovalDiagnostics(event => events.push(event)) }; }
function ui(answers: string[], onSelect?: () => void): EscalationUI {
  return { hasUI: true, sessionManager: { getSessionId: () => secret }, ui: { select: async (_title, choices) => { onSelect?.(); const answer = answers.shift(); assert.ok(answer === undefined || choices.includes(answer)); return answer; } } };
}
function provider(context: EscalationUI, d: ApprovalDiagnostics, grants = new SessionGrantStore()) { return createApprovalProvider(context, grants, undefined, undefined, undefined, d); }

for (const native of [false, true]) {
  test(`${native ? "native" : "bash"} headless and pre-abort record no selector or grant`, async () => {
    const { events, diagnostics } = telemetry();
    const grants = new SessionGrantStore();
    assert.equal(await provider({ hasUI: false }, diagnostics, grants).request(request(native)), "deny");
    const controller = new AbortController(); controller.abort();
    assert.equal(await provider({ ...ui([]), signal: controller.signal }, diagnostics, grants).request(request(native)), "deny");
    assert.equal(events.filter(e => e.event === "provider.start").length, 2);
    assert.deepEqual(events.filter(e => e.event === "provider.response").map(e => e.outcome), ["deny", "aborted"]);
    assert.ok(events.some(e => e.event === "provider.skip" && e.reason === "headless"));
    assert.ok(!events.some(e => e.event === "selector.open" || e.event === "persist"));
    assert.deepEqual(grants.capabilities(secret), []);
  });
  test(`${native ? "native" : "bash"} session hit bypasses UI and scopes stay opaque`, async () => {
    const { events, diagnostics } = telemetry();
    const grants = new SessionGrantStore(); grants.grant(secret, [cap]);
    assert.equal(await provider(ui([], () => assert.fail("UI on grant hit")), diagnostics, grants).request(request(native)), "sandbox-allow-session");
    assert.ok(events.some(e => e.event === "lookup" && e.authority === "resource" && e.duration === "session" && e.outcome === "hit"));
    assert.ok(!events.some(e => e.event === "selector.open"));
    assert.ok(!JSON.stringify(events).includes(secret));
    assert.equal(events[0].tool, native ? "native" : "bash");
  });
}

test("host stored grants are separate from resource grants and retain lookup order", async t => {
  const root = await fixture(t), { events, diagnostics } = telemetry();
  const resource = new ProjectGrantStore(join(root, "resource.json"));
  const hosts = new ProjectHostCommandGrantStore(join(root, "host.json"));
  const r = request() as EscalationApprovalRequest;
  await hosts.grant(`/project/${secret}`, r.commandIdentity!);
  const p = createApprovalProvider(ui([], () => assert.fail("UI on host hit")), new SessionGrantStore(), { projectId: `/project/${secret}`, grants: resource, hostGrants: hosts }, new SessionHostCommandGrantStore(), undefined, diagnostics);
  assert.equal(await p.request(r), "host-allow-project");
  assert.deepEqual(events.filter(e => e.event === "lookup").map(e => [e.authority, e.duration, e.outcome]), [["host", "project", "hit"]]);
  assert.equal(events.at(-1)?.authority, "host");
  assert.ok(!JSON.stringify(events).includes(secret));
});

for (const native of [false, true]) {
  test(`${native ? "native" : "bash"} project persistence succeeds and the next request hits without UI`, async t => {
    const root = await fixture(t), { events, diagnostics } = telemetry();
    const project = { projectId: `/project/${secret}`, grants: new ProjectGrantStore(join(root, "grants.json")) };
    const p = createApprovalProvider(ui(native ? ["Allow for project"] : ["This project", "Allow and retry"]), new SessionGrantStore(), project, undefined, undefined, diagnostics);
    await p.request(request(native));
    assert.equal(await p.request(request(native)), "sandbox-allow-project");
    assert.ok(events.some(e => e.event === "persist" && e.duration === "project" && e.outcome === "success"));
    assert.ok(events.some(e => e.event === "lookup" && e.duration === "project" && e.outcome === "hit"));
    assert.equal(events.filter(e => e.event === "selector.open").length, native ? 1 : 2);
    assert.ok(!JSON.stringify(events).includes(secret));
  });
}

for (const authority of ["resource", "host"] as const) {
  test(`${authority} persistence failure still denies and never grants session authority`, async t => {
    const root = await fixture(t), { events, diagnostics } = telemetry();
    const resources = new ProjectGrantStore(join(root, "r.json")), hosts = new ProjectHostCommandGrantStore(join(root, "h.json"));
    t.mock.method(authority === "resource" ? resources : hosts, "grant", async () => { throw new Error(secret); });
    const grants = new SessionGrantStore();
    const r = request() as EscalationApprovalRequest;
    if (authority === "host") r.capabilities = [];
    const p = createApprovalProvider(ui(authority === "resource" ? ["This project", "Allow and retry"] : ["Run outside sandbox…", "This project", "Run on host"]), grants,
      { projectId: `/project/${secret}`, grants: resources, hostGrants: hosts }, undefined, undefined, diagnostics);
    assert.equal(await p.request(r), "deny");
    assert.ok(events.some(e => e.event === "persist" && e.authority === authority && e.outcome === "error"));
    assert.deepEqual(grants.capabilities(secret), []);
    assert.ok(!JSON.stringify(events).includes(secret));
  });
}

test("lookup errors retain their stage and propagate unchanged", async t => {
  const root = await fixture(t), { events, diagnostics } = telemetry();
  const store = new ProjectGrantStore(join(root, "grants.json")), error = new Error(secret);
  t.mock.method(store, "covers", async () => { throw error; });
  const p = createApprovalProvider(ui([]), new SessionGrantStore(), { projectId: secret, grants: store }, undefined, undefined, diagnostics);
  await assert.rejects(p.request(request(true)), e => e === error);
  assert.ok(events.some(e => e.event === "lookup" && e.duration === "project" && e.outcome === "error"));
  assert.ok(!JSON.stringify(events).includes(secret));
});

async function execution(diagnostics?: ApprovalDiagnostics, sequence: Capability[][] = [[cap], [cap]]) {
  const order: string[] = [], events: string[] = [];
  let attempts = 0;
  const executor = new SelectiveSandboxExecutor({ diagnostics,
    runtime: { supportsNetworkWidening: true, wrap: async command => { order.push("wrap"); return command; }, getViolationsForCommand: () => sequence[Math.min(attempts - 1, sequence.length - 1)], forgetCommand: () => { order.push("forget"); } },
    runner: { runSandbox: async () => { order.push("run"); attempts++; return { exitCode: 1, stdout: secret, stderr: "" }; }, runHost: async () => { assert.fail("host fallback"); } },
    policy: new CapabilityPolicy([]), onStatus: marker => events.push(marker), approvals: { request: async r => { order.push("provider"); return { decision: "sandbox-allow-once", capabilities: r.capabilities }; } }
  });
  const result = await executor.execute(secret, secret, "bash", { retryOnSandboxDenial: true });
  return { result, order, events };
}

test("disabled, throwing, rejecting and unwritable diagnostic sinks preserve execution and markers", async t => {
  const root = await fixture(t);
  await writeFile(join(root, "not-directory"), "fixture");
  const file = createDiagnosticFileSink(join(root, "not-directory", "diagnostics"));
  const baseline = await execution();
  for (const diagnostics of [new ApprovalDiagnostics(() => { throw new Error(secret); }), new ApprovalDiagnostics(async () => { throw new Error(secret); }), new ApprovalDiagnostics(file.sink)]) {
    assert.deepEqual(await execution(diagnostics), baseline);
  }
  await file.close();
});

test("retry observed-target relation, prepared coverage and provider request/attempt correlation are distinct", async () => {
  const { events, diagnostics } = telemetry();
  const next: Capability = { kind: "network", resource: "next.example:443" };
  await execution(diagnostics, [[cap], [next], [next]]);
  assert.deepEqual(events.filter(e => e.event === "attempt.denial").map(e => [e.attempt, e.relation]), [[0, "first"], [1, "new"], [2, "same"]]);
  assert.deepEqual(new Set(events.map(e => e.operationId)).size, 1);
  const mixed = telemetry();
  await execution(mixed.diagnostics, [[cap], [cap, next], [cap, next]]);
  assert.deepEqual(mixed.events.filter(e => e.event === "attempt.denial").map(e => e.relation), ["first", "mixed", "same"]);
  assert.ok(events.some(e => e.event === "retry" && e.reason === "covered" && e.outcome === "skipped"));
  assert.ok(events.some(e => e.event === "coverage" && e.outcome === "hit"));
  const d = telemetry();
  const p = provider(ui(["Once", "Allow and retry"]), d.diagnostics);
  const operationId = randomUUID(), requestId = randomUUID();
  await p.request({ ...request(), diagnosticContext: { operationId, requestId, attempt: 2 } });
  assert.ok(d.events.every(e => e.operationId === operationId && e.requestId === requestId && e.attempt === 2));
});

test("abort while selecting records no persistence and creates no grant", async () => {
  const { events, diagnostics } = telemetry(), controller = new AbortController(), grants = new SessionGrantStore();
  const context = ui(["This session"], () => controller.abort());
  assert.equal(await provider({ ...context, signal: controller.signal }, diagnostics, grants).request(request()), "deny");
  assert.ok(events.some(e => e.event === "selector.response" && e.outcome === "aborted"));
  assert.ok(!events.some(e => e.event === "persist"));
  assert.deepEqual(grants.capabilities(secret), []);
});

test("child dispatch is not display: parent invocation and timeout correlate without prompt leakage", async t => {
  const root = await fixture(t), parent = telemetry(), child = telemetry();
  const bridge = await startApprovalBridge({ root, parentSessionId: secret, diagnostics: parent.diagnostics, pollIntervalMs: 5, select: async () => new Promise<string>(() => {}) });
  t.after(() => bridge.close());
  const context = bridgeApprovalContext({ cwd: `/child/${secret}`, hasUI: false, sessionManager: { getSessionId: () => secret } }, bridge.binding, { diagnostics: child.diagnostics, timeoutMs: 250, pollIntervalMs: 5 });
  assert.equal(await provider(context, child.diagnostics).request(request()), "deny");
  await bridge.close();
  const dispatch = child.events.find(e => e.event === "selector.dispatch")!, open = parent.events.find(e => e.event === "selector.open")!;
  assert.ok(dispatch && open);
  assert.equal(open.actor, "child"); assert.equal(open.renderer, "parent");
  assert.equal(open.requestId, dispatch.requestId); assert.equal(open.selectorId, dispatch.selectorId);
  assert.ok(!child.events.some(e => e.event === "selector.open"));
  assert.ok(child.events.some(e => e.event === "bridge.response" && e.outcome === "timeout"));
  assert.ok(!JSON.stringify([...child.events, ...parent.events]).includes(secret));
});

test("malformed metadata is ignored and near-limit requests omit metadata without changing admission", async t => {
  const root = await fixture(t), { events, diagnostics } = telemetry();
  let count = 0;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", diagnostics, pollIntervalMs: 5, select: async (_title, choices) => { count++; return choices[0]; } });
  t.after(() => bridge.close());
  const child = { cwd: "/child", sessionManager: { getSessionId: () => "child" } };
  const context = bridgeApprovalContext(child, bridge.binding, { diagnostics });
  assert.equal(await context.ui!.select("valid", ["Allow"], { diagnostic: { bad: secret } as never }), "Allow");
  assert.equal(selectorTrace({ ...diagnostics.trace(request()), selectorId: secret }), undefined);
  const base = { ...bridge.binding, id: randomUUID(), childSessionId: "child", cwd: "/child", title: "", choices: ["Allow"], expiresAt: Date.now() + 300_000 };
  const title = "é".repeat(Math.floor((256 * 1024 - Buffer.byteLength(JSON.stringify(base)) - 100) / 2));
  const trace = { ...diagnostics.trace(request()), selectorId: randomUUID() };
  assert.equal(await context.ui!.select(title, ["Allow"], { diagnostic: trace }), "Allow");
  assert.equal(count, 2);
  assert.ok(!events.some(e => e.event === "selector.open")); // both requests had no usable metadata
});

test("custom UI invocation, first render and result are separate, and UI errors still propagate", async t => {
  const { events, diagnostics } = telemetry();
  const r = request() as EscalationApprovalRequest;
  r.capabilities = [{ kind: "filesystem.write", resource: join(await realpath(await fixture(t)), "target") }];
  const context: EscalationUI = { mode: "tui", hasUI: true, ui: { select: async () => assert.fail("unexpected select"), custom: async factory => {
    let result: unknown;
    const component = await factory({ requestRender() {}, terminal: { rows: 24 } } as never, { fg: (_c: string, text: string) => text, bold: (text: string) => text } as never, {} as never, value => { result = value; });
    component.render(80); component.render(80);
    component.handleInput?.("\r"); component.handleInput?.("\r"); component.handleInput?.("\r");
    return result as never;
  } } };
  assert.notEqual(await provider(context, diagnostics).request(r), "deny");
  assert.equal(events.filter(e => e.event === "selector.open").length, 1);
  assert.equal(events.filter(e => e.event === "selector.render").length, 1);
  assert.equal(events.filter(e => e.event === "selector.response").length, 1);
  const error = new Error(secret);
  context.ui!.custom = async () => { throw error; };
  await assert.rejects(provider(context, diagnostics).request(r), e => e === error);
  assert.ok(events.some(e => e.event === "selector.response" && e.outcome === "error"));
  assert.ok(!JSON.stringify(events).includes(secret));
});

test("aggregate counts API invocations, not markers, child dispatches or duplicate input files", async t => {
  const root = await fixture(t), { events, diagnostics } = telemetry();
  await provider(ui(["Once", "Allow and retry"]), diagnostics).request(request());
  const path = join(root, "events.jsonl");
  await writeFile(path, events.map(e => JSON.stringify(e)).join("\n") + "\n<sandbox: approval-required network>\n");
  const { stdout } = await promisify(execFile)(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", path, path]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.providerCalls, 1); assert.equal(summary.selectorsInvoked, 2);
  assert.equal(summary.requestsWithSelectorInvocation, 1); assert.equal(summary.invalidLines, 2);
  assert.equal(summary.childDispatches, 0);
  assert.ok(!stdout.includes(secret));
});

test("provider decisions and lookup/UI/grant order are unchanged by sink exceptions", async () => {
  async function run(d?: ApprovalDiagnostics) {
    const grants = new SessionGrantStore(), order: string[] = [];
    const oldCovers = grants.covers.bind(grants), oldGrant = grants.grant.bind(grants);
    grants.covers = (...args) => { order.push("covers"); return oldCovers(...args); };
    grants.grant = (...args) => { order.push("grant"); return oldGrant(...args); };
    const p = createApprovalProvider(ui(["This session", "Allow and retry"], () => order.push("ui")), grants, undefined, undefined, undefined, d);
    const first = await p.request(request()), second = await p.request(request());
    return { first, second, order };
  }
  const baseline = await run();
  assert.deepEqual(await run(new ApprovalDiagnostics(() => { throw new Error(secret); })), baseline);
  assert.deepEqual(await run(new ApprovalDiagnostics(async () => { throw new Error(secret); })), baseline);
  assert.deepEqual(await run(new ApprovalDiagnostics(() => new Promise(() => {}))), baseline);
});

test("queued child timeout never emits a parent UI invocation for that selector", async t => {
  const root = await fixture(t), parent = telemetry(), child = telemetry();
  let opened!: () => void;
  const displayed = new Promise<void>(resolve => { opened = resolve; });
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", diagnostics: parent.diagnostics, pollIntervalMs: 5,
    select: async () => { opened(); return new Promise<string>(() => {}); } });
  t.after(() => bridge.close());
  const controller = new AbortController(), trace = child.diagnostics.trace(request(), "child");
  const firstId = randomUUID(), secondId = randomUUID();
  const context = { cwd: "/child", sessionManager: { getSessionId: () => "child" } };
  const first = bridgeApprovalContext({ ...context, signal: controller.signal }, bridge.binding, { diagnostics: child.diagnostics }).ui!.select("first", ["Allow"], { diagnostic: { ...trace, selectorId: firstId } });
  await displayed;
  const second = bridgeApprovalContext(context, bridge.binding, { diagnostics: child.diagnostics, timeoutMs: 80, pollIntervalMs: 5 }).ui!.select("second", ["Allow"], { diagnostic: { ...trace, selectorId: secondId } });
  assert.equal(await second, undefined);
  controller.abort(); assert.equal(await first, undefined); await bridge.close();
  assert.deepEqual(parent.events.filter(e => e.event === "selector.open").map(e => e.selectorId), [firstId]);
  assert.ok(child.events.some(e => e.event === "bridge.response" && e.selectorId === secondId && e.outcome === "timeout"));
  assert.ok(child.events.some(e => e.event === "bridge.response" && e.selectorId === firstId && e.outcome === "aborted"));
});

test("parent adapter records only the final UI API, not a skipped stale-session forwarding call", async t => {
  const root = await fixture(t), { events, diagnostics } = telemetry();
  let active = false;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", diagnostics, selectIsAdapter: true, pollIntervalMs: 5,
    select: async (_title, choices, options) => { if (!active) return undefined; options.onInvoke?.(); return choices[0]; } });
  t.after(() => bridge.close());
  const context = bridgeApprovalContext({ cwd: "/child" }, bridge.binding);
  const trace = { ...diagnostics.trace(request(), "child"), selectorId: randomUUID() };
  assert.equal(await context.ui!.select("stale", ["Allow"], { diagnostic: trace }), undefined);
  assert.ok(!events.some(e => e.event === "selector.open"));
  active = true;
  assert.equal(await context.ui!.select("active", ["Allow"], { diagnostic: { ...trace, selectorId: randomUUID() } }), "Allow");
  assert.equal(events.filter(e => e.event === "selector.open").length, 1);
});

test("session grant errors stay synchronous failures and have a persistence result", async t => {
  const { events, diagnostics } = telemetry(), grants = new SessionGrantStore(), error = new Error(secret);
  t.mock.method(grants, "grant", () => { throw error; });
  await assert.rejects(provider(ui(["This session", "Allow and retry"]), diagnostics, grants).request(request()), e => e === error);
  assert.ok(events.some(e => e.event === "persist" && e.duration === "session" && e.outcome === "error"));
  assert.ok(!JSON.stringify(events).includes(secret));
});

test("diagnostic IDs reject untrusted context and strip metadata extras", () => {
  const { diagnostics } = telemetry();
  const trace = diagnostics.trace({ ...request(), diagnosticContext: { operationId: secret, requestId: secret, attempt: -1 } });
  assert.ok(!JSON.stringify(trace).includes(secret));
  assert.equal(trace.attempt, 0);
  assert.ok(!JSON.stringify(selectorTrace({ ...trace, selectorId: randomUUID(), extra: secret })).includes(secret));
  assert.notDeepEqual(diagnostics.scopes([cap]), new ApprovalDiagnostics(() => {}).scopes([cap]));
});

test("file queue and byte caps drop diagnostic work without unbounded writes", async t => {
  const root = await fixture(t), { diagnostics } = telemetry();
  const trace = diagnostics.trace(request());
  const event: ApprovalDiagnosticEvent = { ...trace, event: "provider.start", version: 1, emitterId: diagnostics.originId, sequence: 1, time: Date.now() };
  const queueDirectory = join(root, "queue"), queue = createDiagnosticFileSink(queueDirectory);
  for (let i = 0; i < 300; i++) queue.sink(event);
  await queue.close();
  const queuePath = join(queueDirectory, (await readdir(queueDirectory))[0]);
  assert.equal((await readFile(queuePath, "utf8")).trim().split("\n").length, 256);
  const byteDirectory = join(root, "bytes"), bytes = createDiagnosticFileSink(byteDirectory);
  for (let i = 0; i < 100; i++) bytes.sink({ ...event, scopes: Array.from({ length: 1000 }, () => ({ kind: "network", id: "a".repeat(64) })) });
  await bytes.close();
  const bytePath = join(byteDirectory, (await readdir(byteDirectory))[0]);
  assert.ok((await stat(bytePath)).size <= 4 * 1024 * 1024);
  assert.ok((await readFile(bytePath, "utf8")).trim().split("\n").length < 100);
});

test("JSONL storage is private, bounded, retains no raw input, and prunes only old diagnostic files", async t => {
  const root = await fixture(t), directory = join(root, "diagnostics");
  const file = createDiagnosticFileSink(directory), d = new ApprovalDiagnostics(file.sink);
  await provider(ui(["Once", "Allow and retry"]), d).request(request());
  await file.flush();
  const old = join(directory, `${randomUUID()}.jsonl`), unrelated = join(directory, "keep.txt");
  await writeFile(old, "old"); await utimes(old, new Date(0), new Date(0)); await writeFile(unrelated, "keep");
  const next = createDiagnosticFileSink(directory), nextD = new ApprovalDiagnostics(next.sink);
  await provider({ hasUI: false }, nextD).request(request());
  await next.close(); await file.close();
  assert.ok(!(await readdir(directory)).includes(old.split("/").at(-1)!));
  assert.equal(await readFile(unrelated, "utf8"), "keep");
  assert.equal((await stat(directory)).mode & 0o077, 0);
  for (const name of (await readdir(directory)).filter(name => name.endsWith(".jsonl"))) {
    const path = join(directory, name), text = await readFile(path, "utf8");
    assert.ok(!text.includes(secret)); assert.ok(!text.includes("inputDigest"));
    assert.equal((await stat(path)).mode & 0o077, 0);
    assert.ok(Buffer.byteLength(text) <= 4 * 1024 * 1024);
    text.trim().split("\n").forEach(line => assert.equal(JSON.parse(line).version, 1));
  }
  const linked = join(root, "linked"); await symlink(directory, linked);
  const unsafe = createDiagnosticFileSink(linked);
  unsafe.sink({ ...d.trace(request()), event: "provider.start", version: 1, emitterId: d.originId, sequence: 1, time: Date.now() });
  await unsafe.close();
});
