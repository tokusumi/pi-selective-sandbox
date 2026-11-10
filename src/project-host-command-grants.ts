import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { commandIdentityKey } from "./session-host-command-grants.js";
import type { CommandIdentity } from "./types.js";

type StoredCommandIdentity = { shellCommand: string; cwd: string; executionMode: string };
type StoredGrants = { version: 1; projects: Record<string, StoredCommandIdentity[]> };

function emptyStore(): StoredGrants { return { version: 1, projects: {} }; }
function isCommandIdentity(value: unknown): value is StoredCommandIdentity {
  return typeof value === "object" && value !== null
    && typeof (value as StoredCommandIdentity).shellCommand === "string" && (value as StoredCommandIdentity).shellCommand.length > 0
    && typeof (value as StoredCommandIdentity).cwd === "string" && isAbsolute((value as StoredCommandIdentity).cwd)
    && typeof (value as StoredCommandIdentity).executionMode === "string" && (value as StoredCommandIdentity).executionMode.length > 0;
}
function parseStore(input: string): StoredGrants {
  try {
    const parsed: unknown = JSON.parse(input);
    if (typeof parsed !== "object" || parsed === null || (parsed as { version?: unknown }).version !== 1
      || typeof (parsed as { projects?: unknown }).projects !== "object" || (parsed as { projects?: unknown }).projects === null
      || Array.isArray((parsed as { projects: unknown }).projects)) return emptyStore();
    const projects: Record<string, StoredCommandIdentity[]> = {};
    for (const [project, entries] of Object.entries((parsed as { projects: Record<string, unknown> }).projects)) {
      if (!Array.isArray(entries)) continue;
      const valid = entries.filter(isCommandIdentity).map(command => ({ ...command }));
      if (valid.length) projects[project] = valid;
    }
    return { version: 1, projects };
  } catch { return emptyStore(); }
}

/** User-local, persistent, exact project host-replay approvals.
 * Lookups always read disk: another live Pi session may add or revoke grants.
 */
export class ProjectHostCommandGrantStore {
  constructor(readonly storagePath: string) {}

  /** Compatibility hook only; lookups never retain this snapshot. */
  async load(): Promise<void> { await this.readLatest(); }

  async covers(projectId: string, command: CommandIdentity): Promise<boolean> {
    const store = await this.readLatest();
    return (store.projects[projectId] ?? []).some(entry => commandIdentityKey(entry) === commandIdentityKey(command));
  }

  async commands(projectId: string): Promise<readonly CommandIdentity[]> {
    const store = await this.readLatest();
    return (store.projects[projectId] ?? []).map(command => ({ ...command }));
  }

  async grant(projectId: string, command: CommandIdentity): Promise<void> {
    // Merge the latest snapshot, not a previous lookup. Overlapping writers
    // remain last-writer-wins; atomic replacement is not transaction isolation.
    const store = await this.readLatest();
    const current = store.projects[projectId] ?? [];
    if (!current.some(entry => commandIdentityKey(entry) === commandIdentityKey(command))) current.push({ ...command });
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
