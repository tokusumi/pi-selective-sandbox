import { realpath } from "node:fs/promises";
import { join } from "node:path";
import { readBridgeJson, writeBridgeJson, validBridgeBinding, type ApprovalBridgeBinding } from "./subagent-approval.js";

export type SandboxSwitches = { enabled: boolean; network: boolean; socket: boolean };
export const DEFAULT_SANDBOX_SWITCHES: Readonly<SandboxSwitches> = { enabled: true, network: true, socket: true };
const FILE = "switches.json";

async function checkOwner(binding: ApprovalBridgeBinding): Promise<void> {
  if (!validBridgeBinding(binding) || await realpath(binding.directory) !== binding.directory) throw new Error("Invalid switch binding");
  const alive = await readBridgeJson(join(binding.directory, "alive.json"));
  if (!validBridgeBinding(alive) || alive.parentSessionId !== binding.parentSessionId || alive.nonce !== binding.nonce || alive.directory !== binding.directory) {
    throw new Error("Invalid switch owner");
  }
}

/** No stale-cache/default fallback: an unverifiable off switch must never run on host. */
export async function readSandboxSwitches(binding: ApprovalBridgeBinding): Promise<SandboxSwitches> {
  try {
    await checkOwner(binding);
    const value = await readBridgeJson(join(binding.directory, FILE)) as Record<string, unknown> | null;
    if (!value || value.version !== 1 || value.parentSessionId !== binding.parentSessionId || value.nonce !== binding.nonce
      || typeof value.enabled !== "boolean" || typeof value.network !== "boolean" || typeof value.socket !== "boolean") throw new Error("Invalid switch record");
    return { enabled: value.enabled, network: value.network, socket: value.socket };
  } catch {
    throw new Error("Parent sandbox switch state is unavailable or invalid; execution is blocked. Reload the owning parent and relaunch the child.");
  }
}

/** Called only by the owning parent, before acknowledging the user's command. */
export async function publishSandboxSwitches(binding: ApprovalBridgeBinding, switches: SandboxSwitches): Promise<void> {
  await checkOwner(binding);
  await writeBridgeJson(join(binding.directory, FILE), { version: 1, parentSessionId: binding.parentSessionId, nonce: binding.nonce, ...switches });
}
