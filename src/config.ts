import { readFile } from "node:fs/promises";

export type SelectiveSandboxConfig = {
  filesystem: {
    extraWritableRoots: string[];
    disabledDefaultProfiles: string[];
  };
};

export const DEFAULT_CONFIG: SelectiveSandboxConfig = {
  filesystem: { extraWritableRoots: [], disabledDefaultProfiles: [] }
};

function stringArray(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some(item => typeof item !== "string")) {
    throw new Error(`${field} must be an array of strings`);
  }
  return value;
}

export function parseConfig(value: unknown): SelectiveSandboxConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("config must be an object");
  const filesystem = (value as { filesystem?: unknown }).filesystem;
  if (filesystem !== undefined && (typeof filesystem !== "object" || filesystem === null || Array.isArray(filesystem))) {
    throw new Error("filesystem must be an object");
  }
  const fields = (filesystem ?? {}) as { extraWritableRoots?: unknown; disabledDefaultProfiles?: unknown };
  return { filesystem: {
    extraWritableRoots: stringArray(fields.extraWritableRoots, "filesystem.extraWritableRoots"),
    disabledDefaultProfiles: stringArray(fields.disabledDefaultProfiles, "filesystem.disabledDefaultProfiles")
  } };
}

/** Missing and malformed configuration retain safe defaults; malformed input is diagnosed. */
export async function loadConfig(path: string, diagnostic: (message: string) => void = console.warn): Promise<SelectiveSandboxConfig> {
  try {
    return parseConfig(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      diagnostic(`Ignoring invalid pi-selective-sandbox config at ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
    return DEFAULT_CONFIG;
  }
}
