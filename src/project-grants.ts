import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
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

/** User-local, persistent, exact project/capability/resource grants. */
export class ProjectGrantStore {
  private cache: StoredGrants | undefined;

  constructor(readonly storagePath: string) {}

  async load(): Promise<void> { this.cache = await this.readLatest(); }

  async covers(projectId: string, capabilities: readonly Capability[]): Promise<boolean> {
    if (capabilities.length === 0) return false;
    const store = this.cache ?? await this.readAndCache();
    const grants = store.projects[projectId];
    if (!grants) return false;
    const keys = new Set(grants.map(capabilityKey));
    return capabilities.every(capability => keys.has(capabilityKey(capability)));
  }

  async grant(projectId: string, capabilities: readonly Capability[]): Promise<void> {
    if (capabilities.length === 0) return;
    // Merge newest disk state so another Pi process is not trivially overwritten.
    const store = await this.readLatest();
    const current = store.projects[projectId] ?? [];
    const keys = new Set(current.map(capabilityKey));
    for (const capability of capabilities) {
      if (!keys.has(capabilityKey(capability))) current.push({ kind: capability.kind, resource: capability.resource });
    }
    store.projects[projectId] = current;
    await this.writeAtomically(store);
    this.cache = store;
  }

  private async readAndCache(): Promise<StoredGrants> {
    const store = await this.readLatest();
    this.cache = store;
    return store;
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
    const temporary = join(directory, "." + basename(this.storagePath) + "." + process.pid + "." + Date.now() + ".tmp");
    await writeFile(temporary, JSON.stringify(store, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    await chmod(temporary, 0o600).catch(() => undefined);
    await rename(temporary, this.storagePath);
  }
}
