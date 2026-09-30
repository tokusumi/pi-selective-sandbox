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

/**
 * Returns only the Git metadata locations needed to stage files in a linked
 * worktree. Metadata is writable from bash only when the worktree itself is
 * already writable under the caller's policy.
 */
export async function resolveGitWritePaths(cwd: string, policy: WritePolicy): Promise<string[]> {
  let canonicalCwd: string;
  try { canonicalCwd = await realpath(cwd); } catch { return []; }
  const denied = policy.deny.some(root => {
    try { return contains(resolve(root), canonicalCwd); } catch { return false; }
  });
  const writable = policy.allow.some(root => {
    try { return contains(resolve(root), canonicalCwd); } catch { return false; }
  });
  if (!writable || denied) return [];

  try {
    const { stdout } = await execFileAsync("git", ["-C", canonicalCwd, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"], {
      encoding: "utf8", timeout: 5000
    });
    const [gitDir, commonDir] = stdout.trim().split(/\r?\n/);
    if (!gitDir || !commonDir || !isAbsolute(gitDir) || !isAbsolute(commonDir)) return [];
    const paths = await Promise.all([gitDir, resolve(commonDir, "objects")].map(path => realpath(path)));
    return [...new Set(paths)];
  } catch {
    // Non-Git directories and incomplete repositories keep their normal policy.
    return [];
  }
}
