import type { Capability } from "./types.js";
import { capabilityKey } from "./capability-key.js";

/** In-memory, exact capability/resource grants, partitioned by Pi session ID. */
export class SessionGrantStore {
  private readonly grants = new Map<string, Map<string, Capability>>();

  covers(sessionId: string, capabilities: readonly Capability[]): boolean {
    if (capabilities.length === 0) return false;
    const sessionGrants = this.grants.get(sessionId);
    return sessionGrants !== undefined && capabilities.every(capability => sessionGrants.has(capabilityKey(capability)));
  }

  grant(sessionId: string, capabilities: readonly Capability[]): void {
    if (capabilities.length === 0) return;
    const sessionGrants = this.grants.get(sessionId) ?? new Map<string, Capability>();
    this.grants.set(sessionId, sessionGrants);
    for (const capability of capabilities) sessionGrants.set(capabilityKey(capability), { ...capability });
  }

  capabilities(sessionId: string): readonly Capability[] { return [...(this.grants.get(sessionId)?.values() ?? [])]; }

  clear(sessionId: string): void {
    this.grants.delete(sessionId);
  }

}
