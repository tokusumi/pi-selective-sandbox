import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { boundaryAwareTool } from "../mutation-tools.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";
import type { ApprovalRequest, Capability } from "../types.js";

const write = (resource: string): Capability => ({ kind: "filesystem.write", resource });
const request = (resource: string, eligible = true): ApprovalRequest => ({
  toolCallId: "call", toolName: "write", inputDigest: "digest", capabilities: [write(resource)],
  command: `write ${resource}`, replayWarning: false, sessionGrantEligible: eligible
});

test("SessionGrantStore matches only exact capability/resource in one session", () => {
  const grants = new SessionGrantStore();
  grants.grant("A", [write("/outside/a")]);
  assert.equal(grants.covers("A", [write("/outside/a")]), true);
  assert.equal(grants.covers("A", [{ kind: "filesystem.read", resource: "/outside/a" }]), false);
  assert.equal(grants.covers("A", [write("/outside/b")]), false);
  assert.equal(grants.covers("A", [write("/outside/a/child")]), false);
  assert.equal(grants.covers("B", [write("/outside/a")]), false);
  assert.equal(grants.covers("A", []), false);
  grants.grant("A", [write("/outside/a")]);
  assert.equal(grants.covers("A", [write("/outside/a")]), true);
  grants.clear("A");
  assert.equal(grants.covers("A", [write("/outside/a")]), false);
});

test("approval provider stores only Allow for session and reuses it noninteractively", async () => {
  const grants = new SessionGrantStore(); let prompts = 0;
  const interactive = createApprovalProvider({
    hasUI: true, sessionManager: { getSessionId: () => "A" },
    ui: { select: async () => { prompts++; return "Allow once"; } }
  }, grants);
  assert.equal(await interactive.request(request("/outside/a")), "sandbox-allow-once");
  assert.equal(grants.covers("A", [write("/outside/a")]), false);
  const denied = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => "Deny" } }, grants);
  assert.equal(await denied.request(request("/outside/a")), "deny");
  assert.equal(grants.covers("A", [write("/outside/a")]), false);
  const session = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => "Allow for session" } }, grants);
  assert.equal(await session.request(request("/outside/a")), "sandbox-allow-session");
  const noninteractive = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "A" } }, grants);
  assert.equal(await noninteractive.request(request("/outside/a")), "sandbox-allow-session");
  assert.equal(await noninteractive.request(request("/outside/b")), "deny");
  assert.equal(await createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "B" } }, grants).request(request("/outside/a")), "deny");
  assert.equal(prompts, 1);
  assert.equal(new SessionGrantStore().covers("A", [write("/outside/a")]), false);
});

test("session-grant UI describes exact scope and bash never offers it", async () => {
  const grants = new SessionGrantStore(); const seen: { message: string; choices: string[] }[] = [];
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async (message, choices) => { seen.push({ message, choices }); return "Deny"; } } }, grants);
  await provider.request(request("/outside/a"));
  await provider.request({ ...request("/outside/a", false), replayWarning: true, toolName: "bash" });
  assert.deepEqual(seen[0].choices, ["Allow once", "Allow for session", "Deny"]);
  assert.match(seen[0].message, /remembers exactly the capability\/resource/);
  assert.deepEqual(seen[1].choices, ["Allow once", "Deny"]);
  grants.grant("A", [write("/outside/a")]);
  assert.equal(await createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "A" } }, grants).request({ ...request("/outside/a", false), replayWarning: true, toolName: "bash" }), "deny");
});

async function fakeTool(kind: "write" | "edit", cwd: string, approvals: ReturnType<typeof createApprovalProvider>, calls: unknown[]) {
  return boundaryAwareTool<any>(kind, { async execute(_id, params) { calls.push(params); } }, { cwd, writableRoots: [cwd], approvals: () => approvals });
}

test("write and edit share a session grant despite changed payloads", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-grants-")); const project = join(base, "project"); const outside = join(base, "outside"); await Promise.all([mkdir(project), mkdir(outside)]);
  const grants = new SessionGrantStore(); let prompts = 0;
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => { prompts++; return "Allow for session"; } } }, grants);
  const writeCalls: unknown[] = []; const editCalls: unknown[] = [];
  const writer = await fakeTool("write", project, provider, writeCalls); const editor = await fakeTool("edit", project, provider, editCalls);
  const path = join(outside, "same.txt");
  await writer.execute("w1", { path, content: "A" }, new AbortController().signal, (() => {}) as never);
  await writer.execute("w2", { path, content: "B" }, new AbortController().signal, (() => {}) as never);
  await editor.execute("e", { path, edits: [{ oldText: "B", newText: "C" }] }, new AbortController().signal, (() => {}) as never);
  assert.equal(prompts, 1); assert.equal(writeCalls.length, 2); assert.equal(editCalls.length, 1);
});

test("an edit grant covers write and canonical target changes do not inherit it", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-grants-")); const project = join(base, "project"); const outside = join(base, "outside"); await Promise.all([mkdir(project), mkdir(outside)]);
  const one = join(outside, "one"); const two = join(outside, "two"); await Promise.all([mkdir(one), mkdir(two)]);
  const lexical = join(project, "link"); await symlink(one, lexical);
  const grants = new SessionGrantStore(); let prompts = 0;
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => { prompts++; return "Allow for session"; } } }, grants);
  const editCalls: unknown[] = []; const writeCalls: unknown[] = []; const editor = await fakeTool("edit", project, provider, editCalls); const writer = await fakeTool("write", project, provider, writeCalls);
  await editor.execute("e", { path: "link/file", edits: [] }, new AbortController().signal, (() => {}) as never);
  await writer.execute("w", { path: "link/file", content: "x" }, new AbortController().signal, (() => {}) as never);
  await rm(lexical); await symlink(two, lexical);
  await writer.execute("changed", { path: "link/file", content: "y" }, new AbortController().signal, (() => {}) as never);
  assert.equal(prompts, 2); assert.equal(editCalls.length, 1); assert.equal(writeCalls.length, 2);
});
