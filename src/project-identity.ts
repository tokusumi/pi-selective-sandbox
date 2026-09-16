import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ProjectIdentityDependencies = {
  gitRoot?(cwd: string): Promise<string>;
  canonicalize?(path: string): Promise<string>;
};

async function discoverGitRoot(cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], { encoding: "utf8" });
  const root = stdout.trim();
  if (!root) throw new Error("Git did not return a worktree root");
  return root;
}

/** Resolves once from Pi startup cwd; absent only when its fallback cannot be canonicalized. */
export async function resolveProjectIdentity(startupCwd: string, dependencies: ProjectIdentityDependencies = {}): Promise<string | undefined> {
  const canonicalize = dependencies.canonicalize ?? realpath;
  const gitRoot = dependencies.gitRoot ?? discoverGitRoot;
  try { return await canonicalize(await gitRoot(startupCwd)); }
  catch { try { return await canonicalize(startupCwd); } catch { return undefined; } }
}
