import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { isWorktreeRelativeCwd, resolveGitWorktreeCwd } from "./project-identity.js";
import { commandIdentityKey } from "./session-host-command-grants.js";
import type { CommandIdentity } from "./types.js";

/** cwd records the approval-time path; relative authority retains its coordinate. */
export type ProjectHostCommand = CommandIdentity & (
  { cwdScope: "exact-cwd" } | { cwdScope: "git-worktree-relative"; relativeCwd: string }
);
type StoredGrants = { version: 3; projects: Record<string, ProjectHostCommand[]> };

function emptyStore(): StoredGrants { return { version: 3, projects: Object.create(null) }; }
function isCommandIdentity(value: unknown): value is CommandIdentity {
  return typeof value === "object" && value !== null
    && typeof (value as CommandIdentity).shellCommand === "string" && (value as CommandIdentity).shellCommand.length > 0
    && typeof (value as CommandIdentity).cwd === "string" && isAbsolute((value as CommandIdentity).cwd)
    && typeof (value as CommandIdentity).executionMode === "string" && (value as CommandIdentity).executionMode.length > 0;
}
function parseStore(input: string): StoredGrants {
  try {
    const parsed: unknown = JSON.parse(input);
    if (typeof parsed !== "object" || parsed === null) return emptyStore();
    const { version, projects } = parsed as { version?: unknown; projects?: unknown };
    if ((version !== 1 && version !== 2 && version !== 3) || typeof projects !== "object" || projects === null || Array.isArray(projects)) return emptyStore();
    const store = emptyStore();
    for (const [project, entries] of Object.entries(projects)) {
      if (!Array.isArray(entries)) continue;
      const valid: ProjectHostCommand[] = [];
      for (const entry of entries) {
        if (!isCommandIdentity(entry)) continue;
        // v1 never carried relative authority. v2's overly broad git-project
        // grants are deliberately rejected, not inferred from approval-time cwd.
        const scope = version === 1 ? "exact-cwd" : (entry as ProjectHostCommand).cwdScope;
        const command = { shellCommand: entry.shellCommand, cwd: entry.cwd, executionMode: entry.executionMode };
        const relativeCwd = (entry as { relativeCwd?: unknown }).relativeCwd;
        if (scope === "exact-cwd") valid.push({ ...command, cwdScope: scope });
        else if (version === 3 && scope === "git-worktree-relative" && isWorktreeRelativeCwd(relativeCwd)) {
          valid.push({ ...command, cwdScope: scope, relativeCwd });
        }
      }
      if (valid.length) store.projects[project] = valid;
    }
    return store;
  } catch { return emptyStore(); }
}

/** User-local host-replay approvals, separate from resource grants.
 * Lookups always read disk; old exact-cwd grants are never silently broadened.
 */
export class ProjectHostCommandGrantStore {
  constructor(readonly storagePath: string) {}

  /** Compatibility hook only; lookups never retain this snapshot. */
  async load(): Promise<void> { await this.readLatest(); }

  /** Both startup provenance and fresh worktree/canonical-cwd discovery are required. */
  async gitProjectCwd(projectId: string, command: CommandIdentity, startupGitProjectId?: string): Promise<string | undefined> {
    if (startupGitProjectId !== projectId) return undefined;
    const coordinate = await resolveGitWorktreeCwd(command.cwd);
    return coordinate?.gitProjectId === projectId ? coordinate.relativeCwd : undefined;
  }

  async covers(projectId: string, command: CommandIdentity, startupGitProjectId?: string): Promise<boolean> {
    const store = await this.readLatest();
    const entries = store.projects[projectId] ?? [];
    if (entries.some(entry => entry.cwdScope === "exact-cwd" && commandIdentityKey(entry) === commandIdentityKey(command))) return true;
    const candidates = entries.filter(entry => entry.cwdScope === "git-worktree-relative" && entry.shellCommand === command.shellCommand && entry.executionMode === command.executionMode);
    if (!candidates.length) return false;
    const relativeCwd = await this.gitProjectCwd(projectId, command, startupGitProjectId);
    return relativeCwd !== undefined && candidates.some(entry => entry.cwdScope === "git-worktree-relative" && entry.relativeCwd === relativeCwd);
  }

  /** Enumeration includes cwdScope: approval-time cwd is not always a constraint. */
  async commands(projectId: string): Promise<readonly ProjectHostCommand[]> {
    const store = await this.readLatest();
    return (store.projects[projectId] ?? []).map(command => ({ ...command }));
  }

  /** Existing API retains exact-cwd authority. New wider authority is explicit. */
  async grant(projectId: string, command: CommandIdentity): Promise<void> {
    await this.add(projectId, { ...command, cwdScope: "exact-cwd" });
  }

  async grantGitProject(projectId: string, command: CommandIdentity, startupGitProjectId: string | undefined, relativeCwd: string): Promise<void> {
    if (!isWorktreeRelativeCwd(relativeCwd) || await this.gitProjectCwd(projectId, command, startupGitProjectId) !== relativeCwd) {
      throw new Error("Git project and relative cwd could not be verified");
    }
    await this.add(projectId, { ...command, cwdScope: "git-worktree-relative", relativeCwd });
  }

  private async add(projectId: string, command: ProjectHostCommand): Promise<void> {
    // Merge the latest snapshot, not a previous lookup. Overlapping writers
    // remain last-writer-wins; atomic replacement is not transaction isolation.
    const store = await this.readLatest();
    const current = store.projects[projectId] ?? [];
    if (!current.some(entry => entry.cwdScope === command.cwdScope && entry.shellCommand === command.shellCommand
      && entry.executionMode === command.executionMode && (entry.cwdScope === "git-worktree-relative" && command.cwdScope === "git-worktree-relative"
        ? entry.relativeCwd === command.relativeCwd : entry.cwd === command.cwd))) current.push(command);
    store.projects[projectId] = current;
    await this.writeAtomically(store);
  }

  private async readLatest(): Promise<StoredGrants> {
    try { return parseStore(await readFile(this.storagePath, "utf8")); }
    catch { return emptyStore(); }
  }
  private async writeAtomically(store: StoredGrants): Promise<void> {
    const directory = dirname(this.storagePath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700).catch(() => undefined);
    const temporary = join(directory, "." + basename(this.storagePath) + "." + randomUUID() + ".tmp");
    await writeFile(temporary, JSON.stringify(store, null, 2) + "\n", { encoding: "utf8", mode: 0o600, flag: "wx" });
    try {
      await chmod(temporary, 0o600).catch(() => undefined);
      await rename(temporary, this.storagePath);
    } finally { await rm(temporary, { force: true }).catch(() => undefined); }
  }
}
