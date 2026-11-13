import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { create_skills_manager, type SkillsManager } from "@spences10/pi-skills";
import type { ActiveSkill, SkillAuthority } from "./types.js";

type LoadedCommand = { name: string; source: string; sourceInfo: { path: string; scope: string } };
type Enablement = Pick<SkillsManager, "discover" | "is_enabled_by_skill">;

async function canonical(path: string): Promise<string | undefined> {
  try { return await realpath(path); } catch { return undefined; }
}

/**
 * User-local host authority, independent of resource-discovery contributions.
 * Pin canonical identities at setup so retargeting a configured symlink cannot
 * silently authorize a different skill during this extension lifetime.
 */
export async function createSkillAuthority(options: {
  trustedSkillPaths: readonly string[];
  getCommands: () => readonly LoadedCommand[];
  cwd: string;
  createManager?: () => Enablement;
}): Promise<SkillAuthority> {
  const trusted = new Map<string, string[]>();
  for (const path of options.trustedSkillPaths) {
    const expanded = path.startsWith("~/") ? `${process.env.HOME ?? homedir()}${path.slice(1)}` : path;
    const target = await canonical(expanded);
    if (target) trusted.set(target, [...(trusted.get(target) ?? []), expanded]);
  }
  return {
    async getActiveSkills() {
      if (trusted.size === 0) return [];
      try {
        // Recreate per lookup: completed profile enable/disable changes take effect
        // without relying on another extension's cached manager or discovery list.
        const manager = options.createManager?.() ?? create_skills_manager({ cwd: options.cwd });
        const discovered = await Promise.all(manager.discover().map(async skill => ({ skill, path: await canonical(skill.skillPath) })));
        const active: ActiveSkill[] = [];
        for (const command of options.getCommands()) {
          if (command.source !== "skill" || command.sourceInfo.scope !== "user" || !command.name.startsWith("skill:")) continue;
          const skillPath = command.sourceInfo.path;
          const path = await canonical(skillPath);
          if (!path || !trusted.has(path)) continue;
          const name = command.name.slice("skill:".length);
          const matches = discovered.filter(entry => entry.path === path);
          if (matches.length > 0) {
            // Use canonical identity for selection, but original manager paths for
            // enablement. Never inherit the enabled state of a same-name neighbor.
            // An ancestor ~/.agents skill can be labelled project by this
            // manager; Pi's actual user provenance above is authoritative.
            if (!matches.every(({ skill }) => skill.enabled
              && manager.is_enabled_by_skill(skill.name, skill.skillPath))) continue;
          } else {
            // pi-skills 0.0.36 doesn't scan ~/.agents/skills. Its unknown-source
            // evaluator supports native profile rules, but first falls back by
            // name. Refuse that ambiguous fallback rather than borrowing trust.
            if (discovered.some(entry => entry.skill.name === name)) continue;
            const aliases = new Set([path, skillPath, ...(trusted.get(path) ?? [])]);
            if (![...aliases].every(alias => manager.is_enabled_by_skill(name, alias))) continue;
          }
          active.push({ id: path, root: dirname(path), helperRoots: ["scripts"], active: true, trusted: true });
        }
        return active;
      } catch { return []; } // Missing provenance/failed discovery never creates host authority.
    }
  };
}
