import assert from "node:assert/strict";
import { link, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createApprovalProvider } from "../pi-extension.js";
import { createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "../mutation-tools.js";
import { NativeMutationIO } from "../native-mutation-io.js";
import { SessionGrantStore } from "../session-grants.js";

const signal = new AbortController().signal;
const noUpdate = (() => {}) as never;
const before = "before\n";
const after = "after\n";

async function fixture(t: TestContext) {
  const temporary = await mkdtemp(join(tmpdir(), "pi-native-race-test-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const base = await realpath(temporary);
  const workspace = join(base, "workspace"), approved = join(base, "approved"), other = join(base, "other"), denied = join(base, "denied");
  await Promise.all([workspace, approved, other, denied].map(path => mkdir(path)));
  for (const directory of [approved, other, denied]) await writeFile(join(directory, "fixture.txt"), before);
  return { base, workspace, approved, other, denied, policy: { allow: [workspace], deny: [denied] } };
}

for (const kind of ["write", "edit"] as const) {
  const factory = kind === "write" ? createBoundaryAwareWriteTool : createBoundaryAwareEditTool;
  const input = (path: string) => kind === "write" ? { path, content: after } : { path, edits: [{ oldText: before, newText: after }] };
  for (const shape of ["leaf", "parent"] as const) {
    for (const destination of ["stable", "other", "denied"] as const) {
      test(`${kind}: ${shape} symlink ${destination} during real approval`, async t => {
        const f = await fixture(t);
        const alias = join(f.workspace, "link");
        const requested = shape === "leaf" ? "link" : "link/fixture.txt";
        const canonical = join(f.approved, "fixture.txt");
        await symlink(shape === "leaf" ? canonical : f.approved, alias);
        let approvals = 0;
        let reads = 0;
        if (kind === "edit") {
          const read = NativeMutationIO.prototype.readFile;
          t.mock.method(NativeMutationIO.prototype, "readFile", function(this: NativeMutationIO) {
            reads++;
            return read.call(this);
          });
        }
        const provider = createApprovalProvider({ hasUI: true, ui: { async select(message, choices) {
          approvals++;
          assert.ok(message.includes(`filesystem.write: ${canonical}`));
          assert.ok(choices.includes("Allow once"));
          if (destination !== "stable") {
            await unlink(alias);
            await symlink(shape === "leaf" ? join(f[destination], "fixture.txt") : f[destination], alias);
          }
          return "Allow once";
        } } }, new SessionGrantStore());
        const tool = await factory({ cwd: f.workspace, writePolicy: f.policy, approvals: provider });
        const operation = tool.execute("race", input(requested) as never, signal, noUpdate);
        if (destination === "stable") await operation;
        else await assert.rejects(operation, /target changed|configured deny root/);
        assert.equal(approvals, 1);
        if (kind === "edit") assert.equal(reads, destination === "stable" ? 1 : 0);
        assert.equal(await readFile(canonical, "utf8"), destination === "stable" ? after : before);
        assert.equal(await readFile(join(f.other, "fixture.txt"), "utf8"), before);
        assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
      });
    }
  }

  test(`${kind}: replacement of the canonical parent during approval is rejected`, async t => {
    const f = await fixture(t);
    const moved = join(f.base, "approved-original");
    const tool = await factory({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
      await rename(f.approved, moved);
      await symlink(f.denied, f.approved);
      return "sandbox-allow-once";
    } } });
    await assert.rejects(tool.execute("canonical-parent", input(join(f.approved, "fixture.txt")) as never, signal, noUpdate), /deny root|target changed/);
    assert.equal(await readFile(join(moved, "fixture.txt"), "utf8"), before);
    assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
  });

  test(`${kind}: same-path file replacement during approval is rejected`, async t => {
    const f = await fixture(t);
    const path = join(f.approved, "fixture.txt"), original = `${path}.original`;
    const tool = await factory({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
      await rename(path, original);
      await writeFile(path, before);
      return "sandbox-allow-once";
    } } });
    await assert.rejects(tool.execute("replacement", input(path) as never, signal, noUpdate), /target changed/);
    assert.equal(await readFile(original, "utf8"), before);
    assert.equal(await readFile(path, "utf8"), before);
  });

  for (const decision of ["sandbox-allow-session", "sandbox-allow-project"] as const) {
    test(`${kind}: retarget cannot reuse ${decision}`, async t => {
      const f = await fixture(t);
      const alias = join(f.workspace, "link");
      await symlink(join(f.approved, "fixture.txt"), alias);
      const tool = await factory({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
        await unlink(alias);
        await symlink(join(f.denied, "fixture.txt"), alias);
        return decision;
      } } });
      await assert.rejects(tool.execute("stored-grant", input("link") as never, signal, noUpdate), /deny root/);
      assert.equal(await readFile(join(f.approved, "fixture.txt"), "utf8"), before);
      assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
    });
  }

  test(`${kind}: no-approval fast path also rejects a retarget after preparation`, async t => {
    const f = await fixture(t);
    const inside = join(f.workspace, "fixture.txt"), alias = join(f.workspace, "link");
    await writeFile(inside, before);
    await symlink(inside, alias);
    const prepare = NativeMutationIO.prepare;
    t.mock.method(NativeMutationIO, "prepare", async (type: "write" | "edit", canonical: string, abortSignal?: AbortSignal) => {
      const io = await prepare(type, canonical, abortSignal);
      await unlink(alias);
      await symlink(join(f.denied, "fixture.txt"), alias);
      return io;
    });
    const tool = await factory({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() { throw new Error("Unexpected approval"); } } });
    await assert.rejects(tool.execute("fast-path", input("link") as never, signal, noUpdate), /deny root/);
    assert.equal(await readFile(inside, "utf8"), before);
    assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
  });

  test(`${kind}: canonical-parent race after final validation is refused by descriptor backend`, async t => {
    const f = await fixture(t);
    const moved = join(f.base, "approved-original");
    const io = await NativeMutationIO.prepare(kind, join(f.approved, "fixture.txt"), signal);
    t.after(() => io.close());
    await io.validate();
    await rename(f.approved, moved);
    await symlink(f.denied, f.approved);
    // A plain realpath check followed by path-based I/O used to reach denied.
    if (kind === "edit") await assert.rejects(io.readFile(), /target changed/);
    else await assert.rejects(io.writeFile(after), /target changed/);
    assert.equal(await readFile(join(moved, "fixture.txt"), "utf8"), before);
    assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
  });
}

test("write: new nested file is created only after stable approval", async t => {
  const f = await fixture(t);
  const path = join(f.approved, "new", "nested", "fixture.txt");
  let approvals = 0;
  const tool = await createBoundaryAwareWriteTool({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
    approvals++;
    await assert.rejects(lstat(join(f.approved, "new")), { code: "ENOENT" });
    return "sandbox-allow-once";
  } } });
  await tool.execute("new", { path, content: after }, signal, noUpdate);
  assert.equal(approvals, 1);
  assert.equal(await readFile(path, "utf8"), after);
});

test("write: retarget of an absent suffix creates no denied directories", async t => {
  const f = await fixture(t);
  const alias = join(f.workspace, "link");
  await symlink(f.approved, alias);
  const tool = await createBoundaryAwareWriteTool({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
    await unlink(alias);
    await symlink(f.denied, alias);
    return "sandbox-allow-once";
  } } });
  await assert.rejects(tool.execute("new-retarget", { path: "link/new/nested/fixture.txt", content: after }, signal, noUpdate), /deny root/);
  for (const dir of [f.approved, f.denied]) await assert.rejects(lstat(join(dir, "new")), { code: "ENOENT" });
});

test("write: new leaf introduced after preparation cannot be followed or overwritten", async t => {
  const f = await fixture(t);
  const path = join(f.approved, "new.txt");
  const io = await NativeMutationIO.prepare("write", path, signal);
  t.after(() => io.close());
  await io.validate();
  await symlink(join(f.denied, "fixture.txt"), path);
  await assert.rejects(io.writeFile(after), /target changed/);
  assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
});

test("edit: read and write use one handle and refuse an intervening leaf swap", async t => {
  const f = await fixture(t);
  const path = join(f.approved, "fixture.txt"), original = `${path}.original`;
  const io = await NativeMutationIO.prepare("edit", path, signal);
  t.after(() => io.close());
  assert.equal((await io.readFile()).toString(), before);
  await rename(path, original);
  await symlink(join(f.denied, "fixture.txt"), path);
  await assert.rejects(io.writeFile(after), /target changed/);
  assert.equal(await readFile(original, "utf8"), before);
  assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
});

test("deny and abort release prepared handles without creating or truncating", async t => {
  const f = await fixture(t);
  const controller = new AbortController();
  const path = join(f.approved, "fixture.txt");
  const tool = await createBoundaryAwareWriteTool({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() {
    controller.abort();
    return "sandbox-allow-once";
  } } });
  await assert.rejects(tool.execute("abort", { path, content: after }, controller.signal, noUpdate), /cancelled/);
  assert.equal(await readFile(path, "utf8"), before);
  const denied = await createBoundaryAwareWriteTool({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() { return "deny"; } } });
  await assert.rejects(denied.execute("deny", { path: join(f.approved, "new", "file"), content: after }, signal, noUpdate), /Permission denied/);
  await assert.rejects(lstat(join(f.approved, "new")), { code: "ENOENT" });
});

test("multiply-linked files fail closed rather than bypassing a deny alias", async t => {
  const f = await fixture(t);
  const path = join(f.workspace, "hardlink");
  await link(join(f.denied, "fixture.txt"), path);
  const tool = await createBoundaryAwareWriteTool({ cwd: f.workspace, writePolicy: f.policy, approvals: { async request() { throw new Error("Unexpected approval"); } } });
  await assert.rejects(tool.execute("hardlink", { path, content: after }, signal, noUpdate), /regular file with one link/);
  assert.equal(await readFile(join(f.denied, "fixture.txt"), "utf8"), before);
});
