import type { Capability } from "./types.js";

/** In-memory, exact capability/resource grants, partitioned by Pi session ID. */
export class SessionGrantStore {
  private readonly grants = new Map<string, Set<string>>();

  covers(sessionId: string, capabilities: readonly Capability[]): boolean {
    if (capabilities.length === 0) return false;
    const sessionGrants = this.grants.get(sessionId);
    return sessionGrants !== undefined && capabilities.every(capability => sessionGrants.has(this.key(capability)));
  }

  grant(sessionId: string, capabilities: readonly Capability[]): void {
    if (capabilities.length === 0) return;
    const sessionGrants = this.grants.get(sessionId) ?? new Set<string>();
    this.grants.set(sessionId, sessionGrants);
    for (const capability of capabilities) sessionGrants.add(this.key(capability));
  }

  clear(sessionId: string): void {
    this.grants.delete(sessionId);
  }

  private key(capability: Capability): string {
    return `${capability.kind}\u0000${capability.resource}`;
  }
}
