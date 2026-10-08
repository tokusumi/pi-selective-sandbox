import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, readdir, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { bridgeApprovalContext, startApprovalBridge } from "../subagent-approval.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { Capability, EscalationApprovalRequest } from "../types.js";

async function fixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "pi-subagent-approval-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
const child = { cwd: "/child/worktree", hasUI: false, sessionManager: { getSessionId: () => "child-session" } };
const request = (capability: Capability): EscalationApprovalRequest => ({ kind: "escalation", toolCallId: "child-call", toolName: "bash", inputDigest: "digest", capabilities: [capability], command: "probe", replayWarning: true, sessionGrantEligible: true });

for (const kind of ["filesystem.write", "network"] as const) {
  test(`headless child ${kind} approval reaches the parent and retries only in the sandbox`, async t => {
    const root = await fixture(t);
    const capability = { kind, resource: kind === "network" ? "example.com:443" : join(root, "target") };
    const titles: string[] = [];
    const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
      select: async (title, choices) => { titles.push(title); return choices[0]; } });
    t.after(() => bridge.close());
    const provider = createApprovalProvider(bridgeApprovalContext(child, bridge.binding), new SessionGrantStore());
    const attempts: Capability[][] = [];
    const executor = new SelectiveSandboxExecutor({
      runtime: { supportsNetworkWidening: true, wrap: async (command, context) => { attempts.push([...(context.extraCapabilities ?? [])]); return command; }, getViolationsForCommand: () => [capability] },
      runner: { runSandbox: async () => ({ exitCode: attempts.length === 1 ? 1 : 0, stdout: "", stderr: "" }), runHost: async () => { throw new Error("Unexpected host replay"); } },
      policy: new CapabilityPolicy([]), approvals: provider
    });
    assert.equal((await executor.execute("probe", "child-call")).disposition, "sandbox");
    assert.deepEqual(attempts, [[], [capability]]);
    assert.ok(titles.every(title => title.includes("/child/worktree") && title.includes("child-session")));
    assert.equal(titles.length, kind === "network" ? 2 : 3);
  });
}

test("session grants stay in the requesting child session, not the parent or another child", async t => {
  const root = await fixture(t);
  const cap = { kind: "network" as const, resource: "example.com:443" };
  let prompts = 0;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async (_title, choices) => { prompts++; return choices.includes("This session") ? "This session" : "Allow and retry"; } });
  t.after(() => bridge.close());
  const grants = new SessionGrantStore();
  const provider = createApprovalProvider(bridgeApprovalContext(child, bridge.binding), grants);
  assert.deepEqual(await provider.request(request(cap)), { decision: "sandbox-allow-session", capabilities: [cap] });
  assert.equal(grants.covers("child-session", [cap]), true);
  assert.equal(grants.covers("parent", [cap]), false);
  assert.equal(grants.covers("other-child", [cap]), false);
  assert.equal(await provider.request(request(cap)), "sandbox-allow-session");
  assert.equal(prompts, 2);
});

test("parent denial, missing parent, timeout and malformed binding cannot grant authority", async t => {
  const root = await fixture(t);
  const cap = { kind: "network" as const, resource: "example.com:443" };
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async () => undefined });
  const grants = new SessionGrantStore();
  assert.equal(await createApprovalProvider(bridgeApprovalContext(child, bridge.binding), grants).request(request(cap)), "deny");
  assert.equal(await createApprovalProvider(bridgeApprovalContext(child, { ...bridge.binding, nonce: "wrong" }), grants).request(request(cap)), "deny");
  const binding = bridge.binding;
  await bridge.close();
  assert.equal(await createApprovalProvider(bridgeApprovalContext(child, binding), grants).request(request(cap)), "deny");
  assert.deepEqual(grants.capabilities("child-session"), []);
});

test("aborting a queued or displayed request cancels the parent selector and creates no grant", async t => {
  const root = await fixture(t);
  let opened!: () => void;
  const displayed = new Promise<void>(resolve => { opened = resolve; });
  let parentSignal: AbortSignal | undefined;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async (_title, _choices, options) => { parentSignal = options.signal; opened(); return await new Promise<string>(() => {}); } });
  t.after(() => bridge.close());
  const controller = new AbortController();
  const grants = new SessionGrantStore();
  const provider = createApprovalProvider(bridgeApprovalContext({ ...child, signal: controller.signal }, bridge.binding), grants);
  const pending = provider.request(request({ kind: "network", resource: "example.com:443" }));
  await displayed;
  controller.abort();
  assert.equal(await pending, "deny");
  await bridge.close();
  assert.equal(parentSignal?.aborted, true);
  assert.deepEqual(grants.capabilities("child-session"), []);
});

test("an unanswered parent selector times out without blocking the next child", async t => {
  const root = await fixture(t);
  let prompts = 0;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async () => { prompts++; return prompts === 1 ? await new Promise<string>(() => {}) : "Allow"; } });
  t.after(() => bridge.close());
  const first = bridgeApprovalContext(child, bridge.binding, { timeoutMs: 500, pollIntervalMs: 5 });
  assert.equal(await first.ui!.select("first", ["Allow"]), undefined);
  const second = bridgeApprovalContext(child, bridge.binding, { timeoutMs: 1000, pollIntervalMs: 5 });
  assert.equal(await second.ui!.select("second", ["Allow"]), "Allow");
  assert.equal(prompts, 2);
});

test("concurrent children are serialized and replies cannot cross parent identities", async t => {
  const root = await fixture(t);
  let active = 0, maxActive = 0;
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async (_title, choices) => { active++; maxActive = Math.max(maxActive, active); await Promise.resolve(); active--; return choices[0]; } });
  t.after(() => bridge.close());
  const ui = bridgeApprovalContext(child, bridge.binding).ui!;
  assert.deepEqual(await Promise.all([ui.select("A", ["A"]), ui.select("B", ["B"])]), ["A", "B"]);
  assert.equal(maxActive, 1);
  assert.equal(await bridgeApprovalContext(child, { ...bridge.binding, parentSessionId: "other" }).ui!.select("wrong parent", ["Allow"]), undefined);
});

test("oversized/malformed queue entries and symlinks never open an approval UI", async t => {
  const root = await fixture(t);
  let prompts = 0;
  const warning = t.mock.method(console, "warn", () => {});
  const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
    select: async () => { prompts++; return "Allow"; } });
  t.after(() => bridge.close());
  await writeFile(join(bridge.binding.directory, "00000000-0000-4000-8000-000000000000.request.json"), "x".repeat(300_000));
  const symlinkId = "00000000-0000-4000-8000-000000000001";
  const sentinel = join(root, "outside-queue.json");
  const sentinelContent = JSON.stringify({ ...bridge.binding, id: symlinkId, childSessionId: "child-session", cwd: child.cwd,
    title: "must not open", choices: ["Allow"], expiresAt: Date.now() + 10_000 });
  await writeFile(sentinel, sentinelContent);
  await symlink(sentinel, join(bridge.binding.directory, `${symlinkId}.request.json`));
  await writeFile(join(bridge.binding.directory, "00000000-0000-4000-8000-000000000002.request.json"), "{not-json");
  // A valid subsequent request is an observable polling barrier, not a fixed sleep.
  assert.equal(await bridgeApprovalContext(child, bridge.binding).ui!.select("valid", ["Allow"]), "Allow");
  assert.equal(prompts, 1);
  assert.equal(await readFile(sentinel, "utf8"), sentinelContent);
  assert.equal(warning.mock.callCount(), 3);
  assert.ok((await readdir(bridge.binding.directory)).every(name => !name.endsWith(".request.json")));
});

for (const invalidField of ["id", "parentSessionId", "nonce", "version", "index"] as const) {
  test(`a reply with an invalid ${invalidField} cannot approve a waiting child`, async t => {
    const root = await fixture(t);
    let opened!: () => void;
    const displayed = new Promise<void>(resolve => { opened = resolve; });
    const bridge = await startApprovalBridge({ root, parentSessionId: "parent", pollIntervalMs: 5,
      select: async () => { opened(); return await new Promise<string>(() => {}); } });
    t.after(() => bridge.close());
    const pending = bridgeApprovalContext(child, bridge.binding).ui!.select("needs consent", ["Allow"]);
    await displayed;
    const name = (await readdir(bridge.binding.directory)).find(name => name.endsWith(".request.json"))!;
    const id = name.slice(0, -".request.json".length);
    const reply: Record<string, unknown> = { version: 1, id, parentSessionId: "parent", nonce: bridge.binding.nonce, index: 0 };
    reply[invalidField] = invalidField === "index" ? 1 : invalidField === "version" ? 2 : "invalid-identity";
    const temporary = join(bridge.binding.directory, `${id}.forged.tmp`);
    await writeFile(temporary, JSON.stringify(reply), { mode: 0o600 });
    await rename(temporary, join(bridge.binding.directory, `${id}.reply.json`));
    assert.equal(await pending, undefined);
  });
}
