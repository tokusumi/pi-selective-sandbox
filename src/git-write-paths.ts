import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { canonicalPath, type WritePolicy } from "./filesystem-policy.js";

const execFileAsync = promisify(execFile);

function contains(root: string, target: string): boolean {
  const path = relative(root, target);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

export type GitWritePaths = {
  worktreeDir: string;
  objectsDir: string;
  headsDir: string;
  headsLogsDir: string;
};

/**
 * Discovers the Git metadata locations needed for staging and branch updates
 * in a linked worktree. Metadata approval is available only when the worktree
 * itself is writable under the caller's policy.
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
    const [worktreeDir, objectsDir, headsDir, headsLogsDir] = await Promise.all([
      realpath(gitDir),
      realpath(resolve(commonDir, "objects")),
      canonicalPath(resolve(commonDir, "refs", "heads")),
      canonicalPath(resolve(commonDir, "logs", "refs", "heads"))
    ]);
    return { worktreeDir, objectsDir, headsDir, headsLogsDir };
  } catch {
    // Non-Git directories and incomplete repositories keep their normal policy.
    return undefined;
  }
}

/** Groups Git metadata roots that one explicit widening must grant together. */
export function gitApprovalPaths(resource: string, paths: GitWritePaths | undefined): string[] {
  if (!paths) return [];
  if (contains(paths.worktreeDir, resource) || contains(paths.objectsDir, resource)) {
    return [paths.worktreeDir, paths.objectsDir];
  }
  if (contains(paths.headsDir, resource) || contains(paths.headsLogsDir, resource)) {
    return [paths.worktreeDir, paths.headsDir, paths.headsLogsDir];
  }
  return [];
}
