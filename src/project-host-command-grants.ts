import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
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

/** User-local, persistent, exact project host-replay approvals. */
export class ProjectHostCommandGrantStore {
  private cache: StoredGrants | undefined;
  constructor(readonly storagePath: string) {}

  async load(): Promise<void> { this.cache = await this.readLatest(); }

  async covers(projectId: string, command: CommandIdentity): Promise<boolean> {
    const store = this.cache ?? await this.readAndCache();
    return (store.projects[projectId] ?? []).some(entry => commandIdentityKey(entry) === commandIdentityKey(command));
  }

  async commands(projectId: string): Promise<readonly CommandIdentity[]> {
    const store = this.cache ?? await this.readAndCache();
    return (store.projects[projectId] ?? []).map(command => ({ ...command }));
  }

  async grant(projectId: string, command: CommandIdentity): Promise<void> {
    const store = await this.readLatest();
    const current = store.projects[projectId] ?? [];
    if (!current.some(entry => commandIdentityKey(entry) === commandIdentityKey(command))) current.push({ ...command });
    store.projects[projectId] = current;
    await this.writeAtomically(store);
    this.cache = store;
  }

  private async readAndCache(): Promise<StoredGrants> { const store = await this.readLatest(); this.cache = store; return store; }
  private async readLatest(): Promise<StoredGrants> {
    try { return parseStore(await readFile(this.storagePath, "utf8")); }
    catch { return emptyStore(); }
  }
  private async writeAtomically(store: StoredGrants): Promise<void> {
    const directory = dirname(this.storagePath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700).catch(() => undefined);
    const temporary = join(directory, "." + basename(this.storagePath) + "." + process.pid + "." + Date.now() + ".tmp");
    await writeFile(temporary, JSON.stringify(store, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => undefined);
    await rename(temporary, this.storagePath);
  }
}
