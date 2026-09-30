import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { gitApprovalPaths, resolveGitWritePaths } from "../git-write-paths.js";

const execFileAsync = promisify(execFile);

test("Git approval groups include index/object and branch/ref-log metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-git-write-paths-"));
  const main = join(root, "main");
  const worktree = join(root, "worktree");
  await mkdir(main);
  try {
    await execFileAsync("git", ["init", "-q", main]);
    await execFileAsync("git", ["-C", main, "config", "user.name", "Test"]);
    await execFileAsync("git", ["-C", main, "config", "user.email", "test@example.invalid"]);
    await writeFile(join(main, "tracked.txt"), "base\n");
    await execFileAsync("git", ["-C", main, "add", "."]);
    await execFileAsync("git", ["-C", main, "commit", "-qm", "initial"]);
    await execFileAsync("git", ["-C", main, "worktree", "add", "-qb", "test-worktree", worktree]);

    const paths = await resolveGitWritePaths(worktree, { allow: [worktree], deny: [] });
    assert.ok(paths);
    assert.deepEqual(gitApprovalPaths(paths.worktreeDir, paths), [paths.worktreeDir, paths.objectsDir]);
    assert.deepEqual(gitApprovalPaths(paths.headsDir, paths), [paths.worktreeDir, paths.headsDir, paths.headsLogsDir]);
    assert.deepEqual(gitApprovalPaths(join(paths.headsLogsDir, "nested"), paths), [paths.worktreeDir, paths.headsDir, paths.headsLogsDir]);
    assert.deepEqual(gitApprovalPaths(root, paths), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Git approval paths are not discovered when the worktree is outside the write policy", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-git-write-policy-"));
  const main = join(root, "main");
  await mkdir(main);
  try {
    await execFileAsync("git", ["init", "-q", main]);
    assert.equal(await resolveGitWritePaths(main, { allow: [], deny: [] }), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
