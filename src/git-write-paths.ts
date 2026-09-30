import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import type { WritePolicy } from "./filesystem-policy.js";

const execFileAsync = promisify(execFile);

function contains(root: string, target: string): boolean {
  const path = relative(root, target);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

export type GitWritePaths = {
  worktreeDir: string;
  commonDir: string;
};

/**
 * Discovers Git's per-worktree and shared metadata directories. Metadata
 * approval is available only when the worktree is writable under policy.
 */
export async function resolveGitWritePaths(cwd: string, policy: WritePolicy): Promise<GitWritePaths | undefined> {
  let canonicalCwd: string;
  try { canonicalCwd = await realpath(cwd); } catch { return undefined; }
  const denied = policy.deny.some(root => {
    try { return contains(resolve(root), canonicalCwd); } catch { return false; }
  });
  const writable = policy.allow.some(root => {
    try { return contains(resolve(root), canonicalCwd); } catch { return false; }
  });
  if (!writable || denied) return undefined;

  try {
    const { stdout } = await execFileAsync("git", ["-C", canonicalCwd, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"], {
      encoding: "utf8", timeout: 5000
    });
    const [gitDir, commonDir] = stdout.trim().split(/\r?\n/);
    if (!gitDir || !commonDir || !isAbsolute(gitDir) || !isAbsolute(commonDir)) return undefined;
    const [worktreeDir, sharedDir] = await Promise.all([realpath(gitDir), realpath(commonDir)]);
    return { worktreeDir, commonDir: sharedDir };
  } catch {
    // Non-Git directories and incomplete repositories keep their normal policy.
    return undefined;
  }
}

/** Offer shared Git metadata, plus a separate worktree admin root if needed. */
export function gitApprovalPaths(resource: string, paths: GitWritePaths | undefined): string[] {
  if (!paths) return [];
  if (contains(paths.worktreeDir, resource) || contains(paths.commonDir, resource)) {
    return contains(paths.commonDir, paths.worktreeDir) ? [paths.commonDir] : [paths.worktreeDir, paths.commonDir];
  }
  return [];
}
