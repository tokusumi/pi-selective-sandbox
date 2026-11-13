import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { isAbsolute, normalize, relative, sep } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ProjectIdentityDependencies = {
  /** Git-reported base directory, not the current linked worktree. */
  gitRoot?(cwd: string): Promise<string>;
  gitWorktreeRoot?(cwd: string): Promise<string>;
  canonicalize?(path: string): Promise<string>;
};

async function runGit(cwd: string, args: string[]): Promise<string> {
  // Discovery must describe cwd, not a repository selected by inherited Git
  // environment overrides. This does not alter the command's execution env.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
  const { stdout } = await execFileAsync("git", ["-C", cwd, ...args], { encoding: "utf8", timeout: 5000, env });
  return stdout;
}

async function discoverGitRoot(cwd: string): Promise<string> {
  const stdout = await runGit(cwd, ["worktree", "list", "--porcelain", "-z"]);
  // Git lists its base first: normally the main worktree, or the repository
  // directory for bare repositories and --separate-git-dir layouts.
  // NUL delimiters preserve paths with whitespace/newlines without Git quoting.
  const first = stdout.split("\0", 1)[0];
  if (!first.startsWith("worktree ") || first.length === "worktree ".length) throw new Error("Git did not return a base directory");
  return first.slice("worktree ".length);
}

/** Strict Git identity: no cwd fallback may authorize a Git-project host grant. */
export async function resolveGitProjectIdentity(cwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<string | undefined> {
  try { return await (dependencies.canonicalize ?? realpath)(await (dependencies.gitRoot ?? discoverGitRoot)(cwd)); }
  catch { return undefined; }
}

async function discoverWorktreeRoot(cwd: string): Promise<string> {
  const stdout = await runGit(cwd, ["rev-parse", "--path-format=absolute", "--show-toplevel"]);
  // Remove only Git's record terminator, not whitespace/newlines in the path.
  if (!stdout.endsWith("\n")) throw new Error("Git did not return a worktree root");
  return stdout.slice(0, -1);
}

/** A normalized coordinate within a worktree; root is represented by '.'. */
export function isWorktreeRelativeCwd(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !isAbsolute(value)
    && value !== ".." && !value.startsWith(`..${sep}`) && normalize(value) === value;
}

/** Canonicalize both paths before deriving the coordinate; bare/metadata-only
 * directories have no worktree root and cannot acquire relative-cwd authority.
 */
export async function resolveGitWorktreeCwd(cwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<{ gitProjectId: string; relativeCwd: string } | undefined> {
  try {
    const canonicalize = dependencies.canonicalize ?? realpath;
    const canonicalCwd = await canonicalize(cwd);
    const gitProjectId = await resolveGitProjectIdentity(canonicalCwd, dependencies);
    if (gitProjectId === undefined) return undefined;
    const root = await canonicalize(await (dependencies.gitWorktreeRoot ?? discoverWorktreeRoot)(canonicalCwd));
    const relativeCwd = relative(root, canonicalCwd) || ".";
    return isWorktreeRelativeCwd(relativeCwd) ? { gitProjectId, relativeCwd } : undefined;
  } catch { return undefined; }
}

export type ProjectIdentityInfo = { projectId: string; gitProjectId?: string };

/** Preserve provenance so a fallback path equal to a Git base is not Git proof. */
export async function resolveProjectIdentityInfo(startupCwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<ProjectIdentityInfo | undefined> {
  const gitProjectId = await resolveGitProjectIdentity(startupCwd, dependencies);
  if (gitProjectId !== undefined) return { projectId: gitProjectId, gitProjectId };
  try { return { projectId: await (dependencies.canonicalize ?? realpath)(startupCwd) }; }
  catch { return undefined; }
}

/** Resolves once from Pi startup cwd; absent only when its fallback cannot be canonicalized. */
export async function resolveProjectIdentity(startupCwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<string | undefined> {
  return (await resolveProjectIdentityInfo(startupCwd, dependencies))?.projectId;
}
