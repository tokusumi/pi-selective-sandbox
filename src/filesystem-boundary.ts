import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

/** The single default write policy shared by subprocess and in-process tools. */
export function defaultWritableRoots(cwd: string): readonly string[] {
  return [cwd, "/tmp"];
}

export type MutationTarget = { requested: string; canonical: string; allowed: boolean };

async function canonicalPath(path: string): Promise<string> {
  const suffix: string[] = [];
  let candidate = path;
  for (;;) {
    try {
      return suffix.length === 0 ? await realpath(candidate) : join(await realpath(candidate), ...suffix.reverse());
    } catch {
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`Cannot resolve mutation path: ${path}`);
      suffix.push(candidate.slice(parent.length + (parent.endsWith("/") ? 0 : 1)));
      candidate = parent;
    }
  }
}

function contains(root: string, target: string): boolean {
  const path = relative(root, target);
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

/** Resolves targets through their nearest existing ancestor, closing symlink escapes. */
export class MutationBoundary {
  private constructor(private readonly cwd: string, private readonly roots: readonly string[]) {}

  static async create(cwd: string, writableRoots = defaultWritableRoots(cwd)): Promise<MutationBoundary> {
    return new MutationBoundary(await canonicalPath(cwd), await Promise.all(writableRoots.map(root => canonicalPath(resolve(cwd, root)))));
  }

  async resolve(requested: string): Promise<MutationTarget> {
    const canonical = await canonicalPath(resolve(this.cwd, requested));
    return { requested, canonical, allowed: this.roots.some(root => contains(root, canonical)) };
  }
}

/** Stable digest of the entire native-tool input, for a one-time approval. */
export function inputDigest(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}
