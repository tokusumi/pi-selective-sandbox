import { dirname, isAbsolute } from "node:path";
import { canonicalPath } from "./filesystem-policy.js";
import { pathContains } from "./git-write-paths.js";
import type { Capability } from "./types.js";

/** Exact canonical target first, followed by every ancestor through the filesystem root. */
export function ancestorPaths(target: string): string[] {
  if (!isAbsolute(target) || /[\x00-\x1f\x7f-\x9f]/.test(target)) return [];
  const paths = [target];
  let current = target;
  while (dirname(current) !== current) {
    current = dirname(current);
    paths.push(current);
  }
  return paths;
}

/** Validate again after interaction: neither a forged answer nor a moved symlink may widen to a sibling. */
export async function validateWideningSelection(required: readonly Capability[], selected: readonly Capability[]): Promise<boolean> {
  if (required.length === 0 || selected.length === 0) return false;
  if (required.some(capability => capability.kind !== "filesystem.write" || ancestorPaths(capability.resource).length === 0)) return false;
  if (selected.some(capability => capability.kind !== "filesystem.write"
    || !required.some(target => ancestorPaths(target.resource).includes(capability.resource)))) return false;
  if (!required.every(target => selected.some(scope => pathContains(scope.resource, target.resource)))) return false;
  // An ancestor selected from a canonical path must still have that identity.
  // Resolving both sides also detects retargeting while the dialog was open.
  for (const capability of [...required, ...selected]) {
    if (await canonicalPath(capability.resource) !== capability.resource) return false;
  }
  return true;
}

export function collapseWriteScopes(capabilities: readonly Capability[]): Capability[] {
  const unique = [...new Map(capabilities.map(capability => [capability.resource, { kind: capability.kind, resource: capability.resource }])).values()];
  return unique.filter(capability => !unique.some(other => other.resource !== capability.resource && pathContains(other.resource, capability.resource)));
}
