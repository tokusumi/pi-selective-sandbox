import { readFile } from "node:fs/promises";

export type SelectiveSandboxConfig = {
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
  rejectUnknownFields(value as Record<string, unknown>, ["filesystem"], "config");
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
  return { filesystem: {
    extraWritableRoots: stringArray(fields.extraWritableRoots, "filesystem.extraWritableRoots"),
    disabledDefaultProfiles
  } };
}

/** A missing file uses defaults; an existing invalid security config is reported as invalid. */
export async function loadConfig(path: string, diagnostic: (message: string) => void = console.warn): Promise<ConfigLoadResult> {
  try {
    return { valid: true, config: parseConfig(JSON.parse(await readFile(path, "utf8"))) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { valid: true, config: DEFAULT_CONFIG };
    diagnostic(`Invalid pi-selective-sandbox config at ${path}; using a deny-by-default write policy: ${error instanceof Error ? error.message : String(error)}`);
    return { valid: false };
  }
}
