import { realpath } from "node:fs/promises";
import { relative, resolve } from "node:path";
import type { ActiveSkill, SkillAuthority } from "./types.js";

const CONTROL_OPERATOR = /[|;&`$<>()[\]{}*?]/;
const INTERPRETERS = new Set(["python", "python3", "node", "bash", "sh"]);

/**
 * Deliberately small parser: it accepts only a single, literal argv-style invocation.
 * Shell operators, expansions and subshells are rejected before trust is considered.
 */
export function splitPureInvocation(command: string): string[] | undefined {
  if (!command.trim() || CONTROL_OPERATOR.test(command)) return undefined;
  const words: string[] = [];
  const matcher = /(?:[^\s"']+|"[^"]*"|'[^']*')+/g;
  let cursor = 0;
  for (const match of command.matchAll(matcher)) {
    if (match.index !== cursor && !/^\s+$/.test(command.slice(cursor, match.index))) return undefined;
    cursor = match.index + match[0].length;
    words.push(match[0].replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, "$1$2"));
  }
  if (cursor !== command.length && !/^\s+$/.test(command.slice(cursor))) return undefined;
  return words.length ? words : undefined;
}

function helperCandidate(words: readonly string[]): string | undefined {
  if (words.length === 0) return undefined;
  if (INTERPRETERS.has(words[0]) && words[1]) return words[1];
  if (words[0] === "uv" && words[1] === "run" && words[2]) return words[2];
  return words[0];
}

function isInside(root: string, child: string): boolean {
  const rel = relative(root, child);
  return rel !== "" && !rel.startsWith("..") && !rel.startsWith("../");
}

export async function findTrustedHelper(command: string, authority: SkillAuthority): Promise<ActiveSkill | undefined> {
  const words = splitPureInvocation(command);
  const candidate = words && helperCandidate(words);
  if (!candidate) return undefined;
  let helper: string;
  try { helper = await realpath(candidate); } catch { return undefined; }
  for (const skill of await authority.getActiveSkills()) {
    if (!skill.active || !skill.trusted) continue;
    try {
      const root = await realpath(skill.root);
      for (const helperRoot of skill.helperRoots ?? ["scripts"]) {
        const canonicalHelperRoot = await realpath(resolve(root, helperRoot));
        if (isInside(root, canonicalHelperRoot) && isInside(canonicalHelperRoot, helper)) {
          return skill;
        }
      }
    } catch { /* A missing root is never trusted. */ }
  }
  return undefined;
}
