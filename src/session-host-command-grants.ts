import type { CommandIdentity } from "./types.js";

export function commandIdentityKey(command: CommandIdentity): string {
  return JSON.stringify([command.shellCommand, command.cwd, command.executionMode]);
}

/** In-memory exact host-replay approvals. Deliberately separate from capability grants. */
export class SessionHostCommandGrantStore {
  private readonly grants = new Map<string, Set<string>>();

  covers(sessionId: string, command: CommandIdentity): boolean {
    return this.grants.get(sessionId)?.has(commandIdentityKey(command)) ?? false;
  }

  grant(sessionId: string, command: CommandIdentity): void {
    const sessionGrants = this.grants.get(sessionId) ?? new Set<string>();
    sessionGrants.add(commandIdentityKey(command));
    this.grants.set(sessionId, sessionGrants);
  }

  clear(sessionId: string): void { this.grants.delete(sessionId); }
}
