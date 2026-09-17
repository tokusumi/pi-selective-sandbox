import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import test from "node:test";
import { MutationBoundary, inputDigest } from "../filesystem-boundary.js";
import { boundaryAwareTool, createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "../mutation-tools.js";
import type { ApprovalRequest, ApprovalResponse } from "../types.js";

type Input = { path: string; content?: string; edits?: unknown[] };
const signal = new AbortController().signal;
const noUpdate = (() => {}) as never;

async function fixture() {
  const base = await mkdtemp(join(tmpdir(), "pi-selective-"));
  const project = join(base, "project");
  const outside = join(base, "outside");
  await Promise.all([mkdir(project), mkdir(outside)]);
  return { base, project, outside };
}

async function tool(kind: "write" | "edit", cwd: string, approval: (request: ApprovalRequest) => Promise<ApprovalResponse>, calls: Input[]) {
  return boundaryAwareTool<Input>(kind, {
    async execute(_id, params) { calls.push(params); if (kind === "write") await writeFile(isAbsolute(params.path) ? params.path : join(cwd, params.path), params.content ?? ""); }
  }, { cwd, writableRoots: [cwd], approvals: { request: approval } });
}

test("inside project mutations proceed without approval, including edit", async () => {
  const { project } = await fixture();
  const requests: ApprovalRequest[] = [];
  const writes: Input[] = [];
  const write = await tool("write", project, async request => { requests.push(request); return "deny"; }, writes);
  await write.execute("write-1", { path: "inside.txt", content: "one" }, signal, noUpdate);
  const edits: Input[] = [];
  const edit = await tool("edit", project, async request => { requests.push(request); return "deny"; }, edits);
  await edit.execute("edit-1", { path: "inside.txt", edits: [{ oldText: "one", newText: "two" }] }, signal, noUpdate);
  assert.equal(requests.length, 0);
  assert.equal(writes.length, 1);
  assert.equal(edits.length, 1);
});

test("native write and edit retain their normal project behavior without approval", async () => {
  const { project } = await fixture();
  const approvals: ApprovalRequest[] = [];
  const provider = { request: async (request: ApprovalRequest): Promise<ApprovalResponse> => { approvals.push(request); return "deny"; } };
  const write = await createBoundaryAwareWriteTool({ cwd: project, writableRoots: [project], approvals: provider });
  await write.execute("native-write", { path: "nested/file.txt", content: "before" }, signal, noUpdate);
  const edit = await createBoundaryAwareEditTool({ cwd: project, writableRoots: [project], approvals: provider });
  await edit.execute("native-edit", { path: "nested/file.txt", edits: [{ oldText: "before", newText: "after" }] }, signal, noUpdate);
  assert.equal(await readFile(join(project, "nested/file.txt"), "utf8"), "after");
  assert.deepEqual(approvals, []);
});

test("context.cwd controls native target resolution without widening startup writable roots", async () => {
  const { base, project } = await fixture();
  const otherProject = join(base, "other-project"); await mkdir(otherProject);
  const requests: ApprovalRequest[] = [];
  const write = await createBoundaryAwareWriteTool({
    cwd: project,
    writableRoots: [project],
    approvals: { request: async request => { requests.push(request); return "sandbox-allow-once"; } }
  });
  await write.execute("context-cwd", { path: "foo.txt", content: "from-context" }, signal, noUpdate, { cwd: otherProject });
  assert.equal(await readFile(join(otherProject, "foo.txt"), "utf8"), "from-context");
  await assert.rejects(readFile(join(project, "foo.txt")));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].capabilities[0].resource, join(await realpath(otherProject), "foo.txt"));
});

test("allowed temporary root does not prompt", async () => {
  const { project, base } = await fixture();
  const temp = join(base, "temp"); await mkdir(temp);
  const calls: Input[] = [];
  const write = await boundaryAwareTool<Input>("write", { async execute(_id, params) { calls.push(params); } }, { cwd: project, writableRoots: [project, temp], approvals: { request: async () => { throw new Error("should not prompt"); } } });
  await write.execute("temp", { path: join(temp, "okay.txt"), content: "x" }, signal, noUpdate);
  assert.equal(calls.length, 1);
});

test("outside write denies before native execution and reports canonical metadata", async () => {
  const { project, outside } = await fixture();
  const calls: Input[] = []; const requests: ApprovalRequest[] = [];
  const write = await tool("write", project, async request => { requests.push(request); return "deny"; }, calls);
  await assert.rejects(write.execute("w", { path: join(outside, "new", "file.txt"), content: "secret" }, signal, noUpdate));
  assert.equal(calls.length, 0); assert.equal(requests.length, 1);
  assert.equal(requests[0].toolName, "write"); assert.equal(requests[0].replayWarning, false);
  assert.equal(requests[0].sessionGrantEligible, true);
  assert.equal(requests[0].capabilities[0].kind, "filesystem.write");
  assert.equal(requests[0].capabilities[0].resource, join(await realpath(outside), "new", "file.txt"));
});

test("outside allow-once executes exactly once, while denied edit remains unchanged", async () => {
  const { project, outside } = await fixture();
  const calls: Input[] = []; let approvals = 0;
  const write = await tool("write", project, async () => { approvals++; return "sandbox-allow-once"; }, calls);
  await write.execute("w", { path: join(outside, "file.txt"), content: "x" }, signal, noUpdate);
  assert.equal(approvals, 1); assert.equal(calls.length, 1);
  const editCalls: Input[] = [];
  const edit = await tool("edit", project, async () => "deny", editCalls);
  await assert.rejects(edit.execute("e", { path: join(outside, "file.txt"), edits: [{ oldText: "x", newText: "y" }] }, signal, noUpdate));
  assert.equal(editCalls.length, 0);
});

test("native outside mutations deny before side effects and allow once exactly once", async () => {
  const { project, outside } = await fixture();
  const target = join(outside, "new-parent", "file.txt");
  const denied = await createBoundaryAwareWriteTool({ cwd: project, writableRoots: [project], approvals: { request: async () => "deny" } });
  await assert.rejects(denied.execute("deny", { path: target, content: "no" }, signal, noUpdate));
  await assert.rejects(readFile(target));
  const requests: ApprovalRequest[] = [];
  const allowed = await createBoundaryAwareWriteTool({ cwd: project, writableRoots: [project], approvals: { request: async request => { requests.push(request); return "sandbox-allow-once"; } } });
  await allowed.execute("allow", { path: target, content: "yes" }, signal, noUpdate);
  assert.equal(await readFile(target, "utf8"), "yes");
  assert.equal(requests.length, 1);
  const deniedEdit = await createBoundaryAwareEditTool({ cwd: project, writableRoots: [project], approvals: { request: async () => "deny" } });
  await assert.rejects(deniedEdit.execute("edit-deny", { path: target, edits: [{ oldText: "yes", newText: "no" }] }, signal, noUpdate));
  assert.equal(await readFile(target, "utf8"), "yes");
  const editRequests: ApprovalRequest[] = [];
  const allowedEdit = await createBoundaryAwareEditTool({ cwd: project, writableRoots: [project], approvals: { request: async request => { editRequests.push(request); return "sandbox-allow-once"; } } });
  await allowedEdit.execute("edit-allow", { path: target, edits: [{ oldText: "yes", newText: "edited" }] }, signal, noUpdate);
  assert.equal(await readFile(target, "utf8"), "edited");
  assert.equal(editRequests.length, 1);
});

test("relative escapes, prefix collisions, and symlink escapes are outside", async () => {
  const { base, project, outside } = await fixture();
  const collision = join(base, "project-other"); await mkdir(collision);
  await symlink(outside, join(project, "linked"));
  const boundary = await MutationBoundary.create(project, [project]);
  assert.equal((await boundary.resolve("../project-other/file")).allowed, false);
  assert.equal((await boundary.resolve(join(collision, "file"))).allowed, false);
  assert.equal((await boundary.resolve("linked/existing-or-new.txt")).allowed, false);
});

test("existing symlinks and canonical allowed-root symlinks resolve correctly", async () => {
  const { base, project, outside } = await fixture();
  await writeFile(join(outside, "existing.txt"), "x");
  await symlink(join(outside, "existing.txt"), join(project, "file-link"));
  const boundary = await MutationBoundary.create(project, [project]);
  assert.equal((await boundary.resolve("file-link")).allowed, false);
  const alias = join(base, "project-alias"); await symlink(project, alias);
  const aliasBoundary = await MutationBoundary.create(project, [alias]);
  assert.equal((await aliasBoundary.resolve("accepted.txt")).allowed, true);
});

test("input digests cover write content and edit replacements", () => {
  assert.notEqual(inputDigest({ path: "same", content: "one" }), inputDigest({ path: "same", content: "two" }));
  assert.notEqual(inputDigest({ path: "same", edits: [{ oldText: "a", newText: "b" }] }), inputDigest({ path: "same", edits: [{ oldText: "a", newText: "c" }] }));
});
