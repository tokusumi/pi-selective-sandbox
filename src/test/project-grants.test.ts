import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { createApprovalProvider } from "../pi-extension.js";
import { boundaryAwareTool } from "../mutation-tools.js";
import { ProjectGrantStore } from "../project-grants.js";
import { resolveProjectIdentity } from "../project-identity.js";
import { SessionGrantStore } from "../session-grants.js";
import type { ApprovalRequest, Capability } from "../types.js";

const exec = promisify(execFile);
const write = (resource: string): Capability => ({ kind: "filesystem.write", resource });
const request = (resource: string): ApprovalRequest => ({
  toolCallId: "call", toolName: "write", inputDigest: "digest", capabilities: [write(resource)],
  command: "write " + resource, replayWarning: false, sessionGrantEligible: true, projectGrantEligible: true
});

test("project identity uses a canonical git worktree root and safe fallback", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-id-"));
  const repo = join(base, "repo"); const nested = join(repo, "a", "b");
  await mkdir(nested, { recursive: true });
  await exec("git", ["init", repo]);
  assert.equal(await resolveProjectIdentity(nested), await resolveProjectIdentity(repo));
  const alias = join(base, "alias"); await symlink(repo, alias);
  assert.equal(await resolveProjectIdentity(alias), await resolveProjectIdentity(repo));

  const plain = join(base, "plain"); await mkdir(plain);
  assert.equal(await resolveProjectIdentity(plain), await resolveProjectIdentity(plain, { gitRoot: async () => { throw new Error("no git"); } }));
  assert.equal(await resolveProjectIdentity(plain, { gitRoot: async () => { throw new Error("no git"); } }), await import("node:fs/promises").then(fs => fs.realpath(plain)));
  assert.equal(await resolveProjectIdentity(plain, { gitRoot: async () => { throw new Error("no git"); }, canonicalize: async () => { throw new Error("no canonical cwd"); } }), undefined);
});

test("ProjectGrantStore persists only exact project capability/resource grants", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-store-"));
  const path = join(base, "state", "project-grants.json");
  const first = new ProjectGrantStore(path);
  await first.grant("/project-a", [write("/outside/foo")]);
  await first.grant("/project-a", [write("/outside/foo")]);
  assert.equal(await first.covers("/project-a", [write("/outside/foo")]), true);
  assert.equal(await first.covers("/project-b", [write("/outside/foo")]), false);
  assert.equal(await first.covers("/project-a", [write("/outside/bar")]), false);
  assert.equal(await first.covers("/project-a", [{ kind: "filesystem.read", resource: "/outside/foo" }]), false);
  assert.equal(await first.covers("/project-a", []), false);
  const second = new ProjectGrantStore(path);
  assert.equal(await second.covers("/project-a", [write("/outside/foo")]), true);
  const persisted = JSON.parse(await readFile(path, "utf8"));
  assert.equal(persisted.version, 1);
  assert.deepEqual(persisted.projects["/project-a"], [{ kind: "filesystem.write", resource: "/outside/foo" }]);
});

test("malformed project grant data fails closed", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-invalid-"));
  const path = join(base, "grants.json");
  await writeFile(path, "{ bad json");
  assert.equal(await new ProjectGrantStore(path).covers("/project", [write("/outside/foo")]), false);
  await writeFile(path, JSON.stringify({ version: 99, projects: { "/project": [write("/outside/foo")] } }));
  assert.equal(await new ProjectGrantStore(path).covers("/project", [write("/outside/foo")]), false);
  await writeFile(path, JSON.stringify({ version: 1, projects: { "/project": [{ kind: "filesystem.write" }, { kind: "made.up", resource: "/outside/foo" }] } }));
  assert.equal(await new ProjectGrantStore(path).covers("/project", [write("/outside/foo")]), false);
});

test("project grants take precedence, persist across providers, and bash is ineligible", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-provider-"));
  const store = new ProjectGrantStore(join(base, "grants.json"));
  await store.grant("/project-a", [write("/outside/foo")]);
  let prompts = 0; const seen: string[][] = [];
  const provider = createApprovalProvider({
    hasUI: true, sessionManager: { getSessionId: () => "session" },
    ui: { select: async (_message, choices) => { prompts++; seen.push(choices); return "Deny"; } }
  }, new SessionGrantStore(), { projectId: "/project-a", grants: store });
  assert.equal(await provider.request(request("/outside/foo")), "sandbox-allow-project");
  assert.equal(prompts, 0);

  const session = new SessionGrantStore(); session.grant("session", [write("/outside/bar")]);
  const sessionProvider = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "session" } }, session, { projectId: "/project-a", grants: store });
  assert.equal(await sessionProvider.request(request("/outside/bar")), "sandbox-allow-session");

  const fresh = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "new" } }, new SessionGrantStore(), { projectId: "/project-a", grants: new ProjectGrantStore(join(base, "grants.json")) });
  assert.equal(await fresh.request({ ...request("/outside/foo"), toolName: "edit", inputDigest: "changed" }), "sandbox-allow-project");
  assert.equal(await createApprovalProvider({ hasUI: false }, new SessionGrantStore(), { projectId: "/project-b", grants: new ProjectGrantStore(join(base, "grants.json")) }).request(request("/outside/foo")), "deny");

  await provider.request({ ...request("/outside/nope"), toolName: "bash", replayWarning: true, sessionGrantEligible: false, projectGrantEligible: false });
  assert.deepEqual(seen, [["Allow once", "Deny"]]);
});

test("project approval UI persists before allowing and fails closed when storage fails", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-approval-"));
  const choices: string[][] = [];
  const store = new ProjectGrantStore(join(base, "state", "grants.json"));
  const provider = createApprovalProvider({
    hasUI: true, sessionManager: { getSessionId: () => "session" },
    ui: { select: async (_message, choices) => { choices && choices.length; return "Allow for project"; } }
  }, new SessionGrantStore(), { projectId: "/project", grants: store });
  assert.equal(await provider.request(request("/outside/foo")), "sandbox-allow-project");
  assert.equal(await new ProjectGrantStore(join(base, "state", "grants.json")).covers("/project", [write("/outside/foo")]), true);

  const blocked = join(base, "blocked"); await writeFile(blocked, "not a directory");
  const failed = createApprovalProvider({
    hasUI: true, ui: { select: async (_message, choices) => { choices && choices.length; return "Allow for project"; } }
  }, new SessionGrantStore(), { projectId: "/project", grants: new ProjectGrantStore(join(blocked, "grants.json")) });
  assert.equal(await failed.request(request("/outside/bar")), "deny");
  assert.deepEqual(choices, []);
});


test("write project grant is persisted before execution and reused by edit in a new session", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-mutation-"));
  const project = join(base, "project"); const outside = join(base, "outside");
  await Promise.all([mkdir(project), mkdir(outside)]);
  const storePath = join(base, "state", "grants.json");
  let prompts = 0; const writeCalls: unknown[] = []; const editCalls: unknown[] = [];
  const first = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "one" }, ui: { select: async () => { prompts++; return "Allow for project"; } } }, new SessionGrantStore(), { projectId: project, grants: new ProjectGrantStore(storePath) });
  const writer = await boundaryAwareTool<any>("write", { async execute(_id, params) { writeCalls.push(params); } }, { cwd: project, writableRoots: [project], approvals: first });
  const target = join(outside, "same.txt");
  await writer.execute("write", { path: target, content: "A" }, new AbortController().signal, (() => {}) as never);
  const future = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "two" } }, new SessionGrantStore(), { projectId: project, grants: new ProjectGrantStore(storePath) });
  const editor = await boundaryAwareTool<any>("edit", { async execute(_id, params) { editCalls.push(params); } }, { cwd: project, writableRoots: [project], approvals: future });
  await editor.execute("edit", { path: target, edits: [{ oldText: "A", newText: "B" }] }, new AbortController().signal, (() => {}) as never);
  assert.equal(prompts, 1); assert.equal(writeCalls.length, 1); assert.equal(editCalls.length, 1);
});

test("failed project persistence prevents the mutation side effect", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-fail-mutation-"));
  const project = join(base, "project"); const outside = join(base, "outside");
  await Promise.all([mkdir(project), mkdir(outside)]);
  const blocked = join(base, "blocked"); await writeFile(blocked, "not a directory");
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async () => "Allow for project" } }, new SessionGrantStore(), { projectId: project, grants: new ProjectGrantStore(join(blocked, "grants.json")) });
  const calls: unknown[] = [];
  const writer = await boundaryAwareTool<any>("write", { async execute(_id, params) { calls.push(params); } }, { cwd: project, writableRoots: [project], approvals: provider });
  await assert.rejects(writer.execute("write", { path: join(outside, "no.txt"), content: "no" }, new AbortController().signal, (() => {}) as never));
  assert.equal(calls.length, 0);
});


test("a project grant follows the canonical symlink target, not its lexical path", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-symlink-"));
  const project = join(base, "project"); const outside = join(base, "outside"); const one = join(outside, "one"); const two = join(outside, "two");
  await Promise.all([mkdir(project), mkdir(one, { recursive: true }), mkdir(two, { recursive: true })]);
  const link = join(project, "link"); await symlink(one, link);
  let prompts = 0; const calls: unknown[] = [];
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async () => ++prompts === 1 ? "Allow for project" : "Deny" } }, new SessionGrantStore(), { projectId: project, grants: new ProjectGrantStore(join(base, "state", "grants.json")) });
  const writer = await boundaryAwareTool<any>("write", { async execute(_id, params) { calls.push(params); } }, { cwd: project, writableRoots: [project], approvals: provider });
  await writer.execute("one", { path: "link/file.txt", content: "one" }, new AbortController().signal, (() => {}) as never);
  await rm(link); await symlink(two, link);
  await assert.rejects(writer.execute("two", { path: "link/file.txt", content: "two" }, new AbortController().signal, (() => {}) as never));
  assert.equal(prompts, 2); assert.equal(calls.length, 1);
});
