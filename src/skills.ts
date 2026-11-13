import { realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";
import type { ActiveSkill, SkillAuthority } from "./types.js";

// Conservative even inside quotes: unsupported shell syntax never acquires trust.
const UNSUPPORTED = /[|;&`$<>()[\]{}*?\\\n\r\0]/;
const INTERPRETERS = new Set(["python", "python3", "node", "bash", "sh"]);
type LiteralWord = { value: string; expandHome: boolean };

/** A single literal argv invocation, not a general shell parser. */
function literalWords(command: string): LiteralWord[] | undefined {
  if (!command.trim() || UNSUPPORTED.test(command)) return undefined;
  const words: LiteralWord[] = [];
  let value = "", quote: string | undefined, started = false, expandHome = false;
  for (const char of command) {
    if (quote) {
      if (char === quote) quote = undefined;
      else value += char;
    } else if (char === "'" || char === '"') {
      if (value === "~") expandHome = false;
      quote = char;
      started = true;
    } else if (char === " " || char === "\t") {
      if (started) words.push({ value, expandHome });
      value = ""; started = false; expandHome = false;
    } else {
      // Shell comments can hide what appeared to be the helper operand.
      if ((char === "#" && !started) || (char === "~" && started)) return undefined;
      if (!started) expandHome = char === "~";
      value += char;
      started = true;
    }
  }
  if (quote) return undefined;
  if (started) words.push({ value, expandHome });
  return words.length ? words : undefined;
}

export function splitPureInvocation(command: string): string[] | undefined {
  return literalWords(command)?.map(word => word.value);
}

function helperCandidate(words: readonly LiteralWord[]): LiteralWord | undefined {
  // Quote removal can disguise a shell assignment (A=''"/path/helper").
  // Reject even quoted assignment-shaped names rather than authorizing the
  // unrelated executable that follows an environment assignment.
  if (words.length === 0 || /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(words[0].value)) return undefined;
  if (INTERPRETERS.has(words[0].value)) return words[1];
  if (words[0].value === "uv" && words[1]?.value === "run") return words[2];
  return words[0];
}

function isInside(root: string, child: string): boolean {
  const rel = relative(root, child);
  return rel !== "" && rel !== ".." && !rel.startsWith("../") && !isAbsolute(rel);
}

export async function findTrustedHelper(command: string, authority: SkillAuthority, cwd = process.cwd()): Promise<ActiveSkill | undefined> {
  const words = literalWords(command);
  const candidate = words && helperCandidate(words);
  // A bare command is resolved via PATH by the shell, not relative to cwd.
  if (!candidate?.value.includes("/") || candidate.value.startsWith("-") || !words) return undefined;
  if (words.some(word => word.expandHome && (word !== candidate || !word.value.startsWith("~/")))) return undefined;
  // Do not use resolve()/join(): lexical removal of symlink/.. would inspect
  // a different file from the one the shell/interpreter opens.
  const path = candidate.expandHome
    ? `${process.env.HOME ?? homedir()}${candidate.value.slice(1)}`
    : isAbsolute(candidate.value) ? candidate.value : `${cwd}/${candidate.value}`;
  let helper: string;
  try {
    helper = await realpath(path);
    if (!(await stat(helper)).isFile()) return undefined;
  } catch { return undefined; }
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
