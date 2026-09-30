import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import type { WritePolicy } from "./filesystem-policy.js";
import { splitPureInvocation } from "./skills.js";

const execFileAsync = promisify(execFile);

export function pathContains(root: string, target: string): boolean {
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
    try { return pathContains(resolve(root), canonicalCwd); } catch { return false; }
  });
  const writable = policy.allow.some(root => {
    try { return pathContains(resolve(root), canonicalCwd); } catch { return false; }
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
  if (pathContains(paths.worktreeDir, resource) || pathContains(paths.commonDir, resource)) {
    return pathContains(paths.commonDir, paths.worktreeDir) ? [paths.commonDir] : [paths.worktreeDir, paths.commonDir];
  }
  return [];
}

/** A pure, registered `git worktree remove` needs the target's parent writable. */
export async function worktreeRemovalParent(command: string, cwd: string): Promise<{ target: string; parent: string } | undefined> {
  const words = splitPureInvocation(command);
  if (words?.[0] !== "git") return undefined;
  const args = words.slice(1);
  let gitCwd = cwd;
  while (args[0] === "-C" && args[1]) {
    gitCwd = resolve(gitCwd, args[1]);
    args.splice(0, 2);
  }
  if (args[0] !== "worktree" || args[1] !== "remove") return undefined;
  const operands = args.slice(2);
  const separator = operands.indexOf("--");
  const targets = separator >= 0
    ? [...operands.slice(0, separator).filter(arg => !arg.startsWith("-")), ...operands.slice(separator + 1)]
    : operands.filter(arg => !arg.startsWith("-"));
  if (targets.length !== 1) return undefined;
  try {
    const target = await realpath(resolve(gitCwd, targets[0]));
    const { stdout } = await execFileAsync("git", ["-C", gitCwd, "worktree", "list", "--porcelain"], { encoding: "utf8", timeout: 5000 });
    const registered = stdout.split(/\r?\n/).filter(line => line.startsWith("worktree ")).map(line => line.slice(9));
    for (const path of registered) {
      try { if (await realpath(path) === target) return { target, parent: dirname(target) }; }
      catch { /* Stale worktree records are not approval candidates. */ }
    }
  } catch { /* Invalid commands and paths keep their normal approval flow. */ }
  return undefined;
}
