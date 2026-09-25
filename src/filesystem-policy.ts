import { homedir } from "node:os";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { SelectiveSandboxConfig } from "./config.js";

export type WritePolicy = { allow: readonly string[]; deny: readonly string[] };

export function expandPath(input: string, cwd: string, home = homedir()): string {
  if (input === "~") return home;
  if (input.startsWith("~/")) return join(home, input.slice(2));
  return isAbsolute(input) ? input : resolve(cwd, input);
}

function unique(paths: readonly string[]): string[] { return [...new Set(paths)]; }

/** Canonicalizes even a not-yet-created target through its nearest existing ancestor. */
export async function canonicalPath(path: string): Promise<string> {
  const suffix: string[] = [];
  let candidate = path;
  for (;;) {
    try { return suffix.length === 0 ? await realpath(candidate) : join(await realpath(candidate), ...suffix.reverse()); }
    catch {
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`Cannot resolve path: ${path}`);
      suffix.push(candidate.slice(parent.length + (parent.endsWith("/") ? 0 : 1)));
      candidate = parent;
    }
  }
}

/** Resolves the immutable filesystem policy shared by every execution surface. */
export async function resolveWritePolicy(options: { cwd: string; config: SelectiveSandboxConfig; env: NodeJS.ProcessEnv; home?: string }): Promise<WritePolicy> {
  const home = options.home ?? homedir();
  const disabled = new Set(options.config.filesystem.disabledDefaultProfiles);
  const allow: string[] = [];
  const deny: string[] = [];
  if (!disabled.has("workspace")) allow.push(options.cwd);
  if (!disabled.has("tmp")) allow.push("/tmp");
  if (!disabled.has("cargo-cache")) {
    const cargoHome = expandPath(options.env.CARGO_HOME || join(home, ".cargo"), options.cwd, home);
    allow.push(cargoHome);
    deny.push(...["bin", "config", "config.toml", "credentials", "credentials.toml", "env"].map(name => join(cargoHome, name)));
  }
  allow.push(...options.config.filesystem.extraWritableRoots.map(path => expandPath(path, options.cwd, home)));
  return {
    allow: unique(await Promise.all(allow.map(path => canonicalPath(expandPath(path, options.cwd, home))))),
    deny: unique(await Promise.all(deny.map(path => canonicalPath(path))))
  };
}
