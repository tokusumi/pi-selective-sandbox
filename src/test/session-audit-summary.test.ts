import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

const run = promisify(execFile);
const audit = "pi-selective-sandbox:approval-audit:v1";
const status = "pi-selective-sandbox:approval-audit-status:v1";
const ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"];
const event = (event: string, extra: Record<string, unknown> = {}) => ({ version: 1, originId: ids[0], requestId: ids[1], emitterId: ids[2], sequence: 1, actor: "parent", tool: "bash", event, ...extra });

test("historical session audit entries aggregate with plain diagnostics and ignore unrelated custom entries", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const plain = join(dir, "diagnostics.jsonl"), session = join(dir, "session.jsonl");
  const provider = event("provider.start");
  const recorded = (data: unknown) => ({ type: "custom", customType: audit, data });
  await writeFile(plain, JSON.stringify(provider) + "\n");
  await writeFile(session, [JSON.stringify({ type: "message", message: { role: "assistant", content: "ordinary" } }),
    JSON.stringify({ type: "custom", customType: "custom_message", data: provider }), JSON.stringify(recorded(provider)),
    JSON.stringify({ type: "custom", customType: status, data: { version: 1, originId: ids[0], status: "recording" } })].join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", plain, session]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.providerCalls, 1);
  assert.equal(summary.sessionFilesWithAudit, 1);
  assert.equal(summary.sessionFilesWithoutAudit, 0);
  assert.equal(summary.invalidLines, 0);
});

test("safe category counts and truncated status are summarized without echoing extras", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-audit-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const session = join(dir, "legacy.jsonl"), secret = "/private/raw-path/secret.example";
  const denial = event("attempt.denial", { network: [{ id: "opaque-hmac-secret", reason: "unix-socket", family: "aws", path: secret }] });
  const host = event("attempt.result", { sequence: 2, execution: "host", outcome: "error", exitCode: 7, command: secret });
  const truncated = { type: "custom", customType: status, data: { version: 1, originId: ids[0], status: "truncated", path: secret } };
  await writeFile(session, [JSON.stringify({ type: "message", message: { role: "user", content: "old" } }), JSON.stringify({ type: "custom", customType: audit, data: denial }), JSON.stringify({ type: "custom", customType: audit, data: host }), JSON.stringify(truncated)].join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", session]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.sessionFilesWithAudit, 1);
  assert.equal(summary.sessionTruncated, 1);
  assert.equal(summary.hostFailures, 1);
  assert.equal(summary.networkReasons["unix-socket"], 1);
  assert.equal(summary.networkFamilies.aws, 1);
  assert.ok(!stdout.includes(secret));
  assert.ok(!stdout.includes("opaque-hmac-secret"));
});

test("session recognition uses entries rather than filename and distinguishes legacy unknown coverage", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-coverage-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const plain = join(dir, `${ids[0]}.jsonl`), legacy = join(dir, "diagnostic-looking-session.txt");
  await writeFile(plain, JSON.stringify(event("provider.start")) + "\n");
  await writeFile(legacy, [JSON.stringify({ type: "session", version: 3, id: ids[0] }),
    JSON.stringify({ type: "model_change" }), JSON.stringify({ type: "message", message: { role: "user", content: "<sandbox: approval-required network>" } })].join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", plain, legacy]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.sessionFiles, 1); assert.equal(summary.sessionFilesWithoutAudit, 1);
  assert.equal(summary.providerCalls, 1); assert.equal(summary.invalidLines, 0);
  assert.match(summary.coverage, /unknown/);
});

test("recording manifest with no approvals is known coverage; malformed and custom-message lookalikes are not events", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-empty-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "arbitrary-name");
  await writeFile(path, ["null", "[]", JSON.stringify({ type: "custom_message", customType: audit, data: event("provider.start") }),
    JSON.stringify({ type: "custom", customType: status, data: { version: 1, originId: ids[0], status: "recording" } })].join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", path]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.providerCalls, 0); assert.equal(summary.sessionFilesWithAudit, 1);
  assert.equal(summary.sessionFilesWithoutAudit, 0); assert.equal(summary.sessionStatusGaps, 0);
  assert.equal(summary.invalidLines, 2);
});

test("copied session records deduplicate status and parent/child UI and link results without exposing IDs", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-links-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "session.jsonl"), callId = "a".repeat(64), selectorId = "44444444-4444-4444-8444-444444444444";
  const rows = [
    { type: "session", id: ids[0] },
    { type: "custom", customType: status, data: { version: 1, originId: ids[0], status: "truncated" } },
    { type: "custom", customType: audit, data: event("provider.start", { callId }) },
    { type: "custom", customType: audit, data: event("selector.dispatch", { sequence: 2, actor: "child", selectorId }) },
    { type: "custom", customType: audit, data: event("selector.open", { emitterId: ids[1], sequence: 1, actor: "child", renderer: "parent", selectorId }) },
    { type: "message", message: { role: "toolResult", toolCallId: "raw-never-in-summary", details: { selectiveSandboxAudit: { version: 1, originId: ids[0], callId } } } },
  ];
  await writeFile(path, rows.map(row => JSON.stringify(row)).join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", path, path]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.providerCalls, 1); assert.equal(summary.selectorsInvoked, 1);
  assert.equal(summary.requestsWithSelectorInvocation, 1); assert.equal(summary.childDispatches, 1);
  assert.equal(summary.sessionTruncated, 1); assert.equal(summary.linkedToolResults, 1);
  assert.equal(summary.requestsWithLinkedToolResult, 1);
  assert.ok(!stdout.includes(callId)); assert.ok(!stdout.includes("raw-never-in-summary"));
});

test("malformed object-shaped UUID and token fields never coerce or crash historical analysis", async t => {
  const dir = await mkdtemp(join(tmpdir(), "session-malformed-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "session.jsonl"), bad = { toString: "sensitive-extra" };
  const rows = [
    { type: "custom", customType: status, data: { version: 1, originId: bad, status: "recording" } },
    { type: "custom", customType: audit, data: event("provider.start", { callId: bad }) },
    { type: "custom", customType: audit, data: event("selector.open", { sequence: 2, selectorId: bad, renderer: "local" }) },
    { type: "message", message: { role: "toolResult", details: { selectiveSandboxAudit: { version: 1, originId: bad, callId: bad } } } },
  ];
  await writeFile(path, rows.map(row => JSON.stringify(row)).join("\n"));
  const { stdout } = await run(process.execPath, ["scripts/summarize-approval-diagnostics.mjs", path]);
  const summary = JSON.parse(stdout);
  assert.equal(summary.providerCalls, 1); assert.equal(summary.selectorsInvoked, 0);
  assert.equal(summary.linkedToolResults, 0); assert.ok(!stdout.includes("sensitive-extra"));
});
