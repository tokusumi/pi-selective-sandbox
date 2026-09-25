import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve } from "node:path";
import { canonicalPath, type WritePolicy } from "./filesystem-policy.js";

/** The single default write policy shared by subprocess and in-process tools. */
export function defaultWritableRoots(cwd: string): readonly string[] {
  return [cwd, "/tmp"];
}

export type MutationTarget = { requested: string; canonical: string; allowed: boolean; denied: boolean };

function contains(root: string, target: string): boolean {
  const path = relative(root, target);
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

/** Resolves targets through their nearest existing ancestor, closing symlink escapes. */
export class MutationBoundary {
  private constructor(private readonly cwd: string, private readonly allow: readonly string[], private readonly deny: readonly string[]) {}

  static async create(cwd: string, policy: WritePolicy | readonly string[] = defaultWritableRoots(cwd)): Promise<MutationBoundary> {
    const resolved: WritePolicy = "allow" in policy ? policy : { allow: policy, deny: [] };
    return new MutationBoundary(
      await canonicalPath(cwd),
      await Promise.all(resolved.allow.map(root => canonicalPath(resolve(cwd, root)))),
      await Promise.all(resolved.deny.map(root => canonicalPath(resolve(cwd, root))))
    );
  }

  async resolve(requested: string): Promise<MutationTarget> {
    const canonical = await canonicalPath(resolve(this.cwd, requested));
    const denied = this.deny.some(root => contains(root, canonical));
    const allowed = this.allow.some(root => contains(root, canonical)) && !denied;
    return { requested, canonical, allowed, denied };
  }
}

/** Stable digest of the entire native-tool input, for a one-time approval. */
export function inputDigest(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
