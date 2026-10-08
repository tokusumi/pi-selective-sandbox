import { readFile } from "node:fs/promises";
import { DEFAULT_NETWORK_PROFILES, normalizeNetworkPattern } from "./network-policy.js";

export type SelectiveSandboxConfig = {
  network?: { extraAllowedDomains: string[]; disabledDefaultProfiles?: string[]; allowLocalBinding?: boolean };
  filesystem: {
    extraWritableRoots: string[];
    disabledDefaultProfiles: string[];
  };
};

export const DEFAULT_WRITE_PROFILES = ["workspace", "tmp", "cargo-cache", "runtime-home"] as const;
export type DefaultWriteProfile = typeof DEFAULT_WRITE_PROFILES[number];
export type ConfigLoadResult = { valid: true; config: SelectiveSandboxConfig } | { valid: false };

export const DEFAULT_CONFIG: SelectiveSandboxConfig = {
  filesystem: { extraWritableRoots: [], disabledDefaultProfiles: [] }
};

function stringArray(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some(item => typeof item !== "string" || item.length === 0)) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
  return value;
}

function rejectUnknownFields(value: Record<string, unknown>, allowed: readonly string[], scope: string): void {
  const unknown = Object.keys(value).find(key => !allowed.includes(key));
  if (unknown) throw new Error(`unknown ${scope} field: ${unknown}`);
}

export function parseConfig(value: unknown): SelectiveSandboxConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("config must be an object");
  rejectUnknownFields(value as Record<string, unknown>, ["filesystem", "network"], "config");
  const filesystem = (value as { filesystem?: unknown }).filesystem;
  if (filesystem !== undefined && (typeof filesystem !== "object" || filesystem === null || Array.isArray(filesystem))) {
    throw new Error("filesystem must be an object");
  }
  const fields = (filesystem ?? {}) as { extraWritableRoots?: unknown; disabledDefaultProfiles?: unknown };
  rejectUnknownFields(fields as Record<string, unknown>, ["extraWritableRoots", "disabledDefaultProfiles"], "filesystem");
  const disabledDefaultProfiles = stringArray(fields.disabledDefaultProfiles, "filesystem.disabledDefaultProfiles");
  const knownProfiles: readonly string[] = DEFAULT_WRITE_PROFILES;
  const unknown = disabledDefaultProfiles.find(profile => !knownProfiles.includes(profile));
  if (unknown) throw new Error(`unknown default write profile: ${unknown}`);
  const network = (value as { network?: unknown }).network;
  if (network !== undefined && (typeof network !== "object" || network === null || Array.isArray(network))) throw new Error("network must be an object");
  const networkFields = (network ?? {}) as { extraAllowedDomains?: unknown; disabledDefaultProfiles?: unknown; allowLocalBinding?: unknown };
  rejectUnknownFields(networkFields as Record<string, unknown>, ["extraAllowedDomains", "disabledDefaultProfiles", "allowLocalBinding"], "network");
  if (networkFields.allowLocalBinding !== undefined && typeof networkFields.allowLocalBinding !== "boolean") {
    throw new Error("network.allowLocalBinding must be a boolean");
  }
  const disabledNetworkProfiles = stringArray(networkFields.disabledDefaultProfiles, "network.disabledDefaultProfiles");
  const knownNetworkProfiles: readonly string[] = DEFAULT_NETWORK_PROFILES;
  const unknownNetworkProfile = disabledNetworkProfiles.find(profile => !knownNetworkProfiles.includes(profile));
  if (unknownNetworkProfile) throw new Error(`unknown default network profile: ${unknownNetworkProfile}`);
  const extraAllowedDomains = [...new Set(stringArray(networkFields.extraAllowedDomains, "network.extraAllowedDomains").map(normalizeNetworkPattern))];
  const parsed: SelectiveSandboxConfig = { filesystem: {
    extraWritableRoots: stringArray(fields.extraWritableRoots, "filesystem.extraWritableRoots"),
    disabledDefaultProfiles
  } };
  if (network !== undefined) {
    parsed.network = { extraAllowedDomains };
    if (networkFields.disabledDefaultProfiles !== undefined) parsed.network.disabledDefaultProfiles = disabledNetworkProfiles;
    if (networkFields.allowLocalBinding !== undefined) parsed.network.allowLocalBinding = networkFields.allowLocalBinding as boolean;
  }
  return parsed;
}

/** A missing file uses defaults; an existing invalid security config is reported as invalid. */
export async function loadConfig(path: string, diagnostic: (message: string) => void = console.warn): Promise<ConfigLoadResult> {
  try {
    return { valid: true, config: parseConfig(JSON.parse(await readFile(path, "utf8"))) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { valid: true, config: DEFAULT_CONFIG };
    diagnostic(`Invalid pi-selective-sandbox config at ${path}; using a deny-by-default write policy, empty network allowlist, and disabled local binding: ${error instanceof Error ? error.message : String(error)}`);
    return { valid: false };
  }
}
