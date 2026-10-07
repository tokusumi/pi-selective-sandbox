import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ProjectIdentityDependencies = {
  /** Git-reported base directory, not the current linked worktree. */
  gitRoot?(cwd: string): Promise<string>;
  canonicalize?(path: string): Promise<string>;
};

async function discoverGitRoot(cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["-C", cwd, "worktree", "list", "--porcelain", "-z"], { encoding: "utf8", timeout: 5000 });
  // Git lists its base first: normally the main worktree, or the repository
  // directory for bare repositories and --separate-git-dir layouts.
  // NUL delimiters preserve paths with whitespace/newlines without Git quoting.
  const first = stdout.split("\0", 1)[0];
  if (!first.startsWith("worktree ") || first.length === "worktree ".length) throw new Error("Git did not return a base directory");
  return first.slice("worktree ".length);
}

/** Resolves once from Pi startup cwd; absent only when its fallback cannot be canonicalized. */
export async function resolveProjectIdentity(startupCwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<string | undefined> {
  const canonicalize = dependencies.canonicalize ?? realpath;
  const gitRoot = dependencies.gitRoot ?? discoverGitRoot;
  try { return await canonicalize(await gitRoot(startupCwd)); }
  catch { try { return await canonicalize(startupCwd); } catch { return undefined; } }
}
