import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { capabilityKey } from "./capability-key.js";
import type { Capability } from "./types.js";

type StoredCapability = { kind: Capability["kind"]; resource: string };
type StoredGrants = { version: 1; projects: Record<string, StoredCapability[]> };

const capabilityKinds = new Set<Capability["kind"]>(["filesystem.read", "filesystem.write", "network"]);

function isCapability(value: unknown): value is StoredCapability {
  return typeof value === "object" && value !== null
    && typeof (value as StoredCapability).kind === "string" && capabilityKinds.has((value as StoredCapability).kind)
    && typeof (value as StoredCapability).resource === "string" && (value as StoredCapability).resource.length > 0;
}

function emptyStore(): StoredGrants { return { version: 1, projects: {} }; }

function parseStore(input: string): StoredGrants {
  try {
    const parsed: unknown = JSON.parse(input);
    if (typeof parsed !== "object" || parsed === null || (parsed as { version?: unknown }).version !== 1
      || typeof (parsed as { projects?: unknown }).projects !== "object" || (parsed as { projects?: unknown }).projects === null
      || Array.isArray((parsed as { projects: unknown }).projects)) return emptyStore();
    const projects: Record<string, StoredCapability[]> = {};
    for (const [project, entries] of Object.entries((parsed as { projects: Record<string, unknown> }).projects)) {
      if (!Array.isArray(entries)) continue;
      const valid = entries.filter(isCapability).map(entry => ({ kind: entry.kind, resource: entry.resource }));
      if (valid.length) projects[project] = valid;
    }
    return { version: 1, projects };
  } catch { return emptyStore(); }
}

/** User-local, persistent, exact project/capability/resource grants.
 * Lookups always read disk: another live Pi session may add or revoke grants.
 */
export class ProjectGrantStore {
  constructor(readonly storagePath: string) {}

  /** Compatibility hook only; lookups never retain this snapshot. */
  async load(): Promise<void> { await this.readLatest(); }

  async covers(projectId: string, capabilities: readonly Capability[]): Promise<boolean> {
    if (capabilities.length === 0) return false;
    const store = await this.readLatest();
    const grants = store.projects[projectId];
    if (!grants) return false;
    const keys = new Set(grants.map(capabilityKey));
    return capabilities.every(capability => keys.has(capabilityKey(capability)));
  }

  async capabilities(projectId: string): Promise<readonly Capability[]> {
    const store = await this.readLatest();
    return (store.projects[projectId] ?? []).map(capability => ({ ...capability }));
  }

  async grant(projectId: string, capabilities: readonly Capability[]): Promise<void> {
    if (capabilities.length === 0) return;
    // Merge the latest snapshot, not a previous lookup. Overlapping writers
    // remain last-writer-wins; atomic replacement is not transaction isolation.
    const store = await this.readLatest();
    const current = store.projects[projectId] ?? [];
    const keys = new Set(current.map(capabilityKey));
    for (const capability of capabilities) {
      if (!keys.has(capabilityKey(capability))) current.push({ kind: capability.kind, resource: capability.resource });
    }
    store.projects[projectId] = current;
    await this.writeAtomically(store);
  }

  private async readLatest(): Promise<StoredGrants> {
    try { return parseStore(await readFile(this.storagePath, "utf8")); }
    catch (error: unknown) {
      if ((error as { code?: string }).code === "ENOENT") return emptyStore();
      return emptyStore();
    }
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
