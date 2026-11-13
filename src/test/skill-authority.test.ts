import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { create_skills_manager, type ManagedSkill } from "@spences10/pi-skills";
import { loadSkills } from "@earendil-works/pi-coding-agent";
import { createSkillAuthority } from "../skill-authority.js";
import { parseConfig } from "../config.js";
import { findTrustedHelper } from "../skills.js";

async function fixture(t: test.TestContext) {
  const base = await realpath(await mkdtemp(join(tmpdir(), "skill-authority-")));
  const agentDir = join(base, "agent"), cwd = join(base, "project");
  await mkdir(agentDir); await mkdir(cwd);
  const old = process.env.PI_CODING_AGENT_DIR;
  const oldProfile = process.env.MY_PI_SKILLS_PROFILE;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  delete process.env.MY_PI_SKILLS_PROFILE;
  t.after(async () => {
    if (old === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = old;
    if (oldProfile === undefined) delete process.env.MY_PI_SKILLS_PROFILE; else process.env.MY_PI_SKILLS_PROFILE = oldProfile;
    await rm(base, { recursive: true, force: true });
  });
  async function skill(root: string, name = "demo") {
    await mkdir(join(root, "scripts"), { recursive: true });
    const path = join(root, "SKILL.md");
    await writeFile(path, `---\nname: ${name}\ndescription: fixture skill\n---\nFixture\n`);
    await writeFile(join(root, "scripts", "finish.sh"), "#!/bin/sh\necho fixture\n");
    return path;
  }
  const command = (path: string, name = "demo", scope = "user") => ({ name: `skill:${name}`, source: "skill", sourceInfo: { path, scope } });
  return { base, agentDir, cwd, skill, command };
}

test("config accepts only explicit SKILL.md paths, never names, roots or patterns", () => {
  const paths = ["~/.agents/skills/worktree-finish/SKILL.md", "/user/skills/demo/SKILL.md"];
  assert.deepEqual(parseConfig({ skills: { trustedSkillPaths: [...paths, paths[0]] } }).skills, { trustedSkillPaths: paths });
  assert.equal(parseConfig({}).skills, undefined);
  assert.deepEqual(parseConfig({ skills: {} }).skills, { trustedSkillPaths: [] });
  for (const trustedSkillPaths of ["demo", ["demo"], ["./SKILL.md"], ["/skills"], ["/skills/*/SKILL.md"], ["/skills/a\n/SKILL.md"], [null], null]) {
    assert.throws(() => parseConfig({ skills: { trustedSkillPaths } }));
  }
  for (const skills of [null, [], "demo", { extraPaths: paths }]) assert.throws(() => parseConfig({ skills }));
});

test("pi-native enabled skill is trusted only with explicit user approval and actual Pi loading", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.agentDir, "skills", "demo"));
  const manager = create_skills_manager({ cwd: f.cwd });
  const discovered = manager.discover().find(skill => skill.skillPath === path)!;
  assert.equal(discovered.source, "pi-native");
  manager.enable(discovered.key);
  assert.deepEqual(manager.get_enabled_skill_paths(), []); // A discovery contribution, not an authority list.
  const loaded = loadSkills({ cwd: f.cwd, agentDir: f.agentDir, skillPaths: [], includeDefaults: true }).skills;
  let commands = loaded.map(skill => ({ name: `skill:${skill.name}`, source: "skill", sourceInfo: skill.sourceInfo }));
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => commands });
  assert.equal((await authority.getActiveSkills()).length, 1);
  assert.ok(await findTrustedHelper(`bash '${join(dirname(path), "scripts", "finish.sh")}' --message "変更内容"`, authority));
  assert.deepEqual(await (await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [], getCommands: () => commands })).getActiveSkills(), []);
  commands = [];
  assert.deepEqual(await authority.getActiveSkills(), []);
  commands = [f.command(path) as typeof commands[number]];
  manager.disable(discovered.key);
  assert.deepEqual(await authority.getActiveSkills(), []); // Fresh manager, no reload required.
  manager.enable(discovered.key);
  assert.equal((await authority.getActiveSkills()).length, 1);
  for (const scope of ["project", "temporary"]) {
    commands = [f.command(path, "demo", scope) as typeof commands[number]];
    assert.deepEqual(await authority.getActiveSkills(), []);
  }
});

test("user .agents skill uses Pi provenance even though pi-skills doesn't discover its root", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.base, "separate-home", ".agents", "skills", "demo"));
  const manager = create_skills_manager({ cwd: f.cwd });
  assert.equal(manager.discover().some(skill => skill.skillPath === path), false);
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => [f.command(path)] });
  assert.equal((await authority.getActiveSkills()).length, 1);
  manager.disable("demo@pi-native");
  assert.deepEqual(await authority.getActiveSkills(), []);
  manager.enable("demo@pi-native");
  assert.equal((await authority.getActiveSkills()).length, 1);
  manager.exclude_from_profile("default", path);
  assert.deepEqual(await authority.getActiveSkills(), []);
});

test("ancestor user .agents provenance wins over manager project classification, including linked worktrees", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.base, ".agents", "skills", "demo"));
  let scope = "user";
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => [f.command(path, "demo", scope)] });
  for (const linked of [false, true]) {
    if (linked) await writeFile(join(f.cwd, ".git"), "gitdir: /fixture/nonexistent\n");
    const manager = create_skills_manager({ cwd: f.cwd });
    const discovered = manager.discover().find(skill => skill.skillPath === path)!;
    assert.equal(discovered.scope, "project");
    assert.equal((await authority.getActiveSkills()).length, 1);
    manager.disable(discovered.key);
    assert.deepEqual(await authority.getActiveSkills(), []);
    manager.enable(discovered.key);
    assert.equal((await authority.getActiveSkills()).length, 1);
    scope = "project";
    assert.deepEqual(await authority.getActiveSkills(), []);
    scope = "user";
  }
  await rm(join(f.cwd, ".git"), { force: true });
  await mkdir(join(f.cwd, ".git"));
  assert.equal(create_skills_manager({ cwd: f.cwd }).discover().some(skill => skill.skillPath === path), false);
});

test("unknown user aliases cannot bypass a profile exclusion of the approved path", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.base, "separate-home", ".agents", "skills", "demo"));
  const alias = join(f.base, "alias");
  await symlink(dirname(path), alias);
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => [f.command(join(alias, "SKILL.md"))] });
  assert.equal((await authority.getActiveSkills()).length, 1);
  create_skills_manager({ cwd: f.cwd }).exclude_from_profile("default", path);
  assert.deepEqual(await authority.getActiveSkills(), []);
});

test("same-name project skills and unloaded collision losers cannot inherit user trust", async t => {
  const f = await fixture(t);
  const user = await f.skill(join(f.agentDir, "skills", "demo"));
  const project = await f.skill(join(f.cwd, ".agents", "skills", "demo"));
  const manager = create_skills_manager({ cwd: f.cwd });
  manager.enable("demo@pi-native");
  manager.enable("demo@project:.agents/skills");
  let commands = [f.command(user), f.command(project, "demo", "project")];
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [user, project], getCommands: () => commands });
  assert.deepEqual((await authority.getActiveSkills()).map(skill => skill.root), [dirname(user)]);
  assert.equal(await findTrustedHelper(`'${join(dirname(project), "scripts", "finish.sh")}'`, authority), undefined);
  const loser = await f.skill(join(f.base, "loser"));
  const loserAuthority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [loser], getCommands: () => commands });
  assert.deepEqual(await loserAuthority.getActiveSkills(), []);
  // An unknown user path must never use the manager's by-name global/project fallback.
  commands = [f.command(loser)];
  assert.deepEqual(await loserAuthority.getActiveSkills(), []);
  manager.disable("demo@pi-native");
  assert.deepEqual(await authority.getActiveSkills(), []);
});

test("canonical directory aliases work; retargeted aliases and SKILL.md-only links don't transfer helper roots", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.agentDir, "skills", "demo"));
  create_skills_manager({ cwd: f.cwd }).enable("demo@pi-native");
  const alias = join(f.base, "alias");
  await symlink(dirname(path), alias);
  const commands = [f.command(join(alias, "SKILL.md"))];
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [join(alias, "SKILL.md")], getCommands: () => commands });
  assert.equal((await authority.getActiveSkills()).length, 1);
  const other = await f.skill(join(f.base, "other"), "other");
  await rename(alias, join(f.base, "old-alias"));
  await symlink(dirname(other), alias);
  assert.deepEqual(await authority.getActiveSkills(), []);
  await symlink(path, join(dirname(other), "linked.md"));
  const linked = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => [f.command(join(dirname(other), "linked.md"))] });
  assert.equal((await linked.getActiveSkills())[0].root, dirname(path));
  assert.equal(await findTrustedHelper(`'${join(dirname(other), "scripts", "finish.sh")}'`, linked), undefined);
});

test("home-relative approval paths preserve symlink/dot-dot identity", async t => {
  const f = await fixture(t);
  const lexical = await f.skill(join(f.base, "lexical"), "lexical");
  const actual = await f.skill(join(f.base, "evil", "alias"), "actual");
  await mkdir(join(f.base, "evil", "subdir"));
  await symlink(dirname(lexical), join(f.base, "alias"));
  await symlink(join(f.base, "evil", "subdir"), join(f.base, "jump"));
  const home = process.env.HOME;
  process.env.HOME = f.base;
  t.after(() => { if (home === undefined) delete process.env.HOME; else process.env.HOME = home; });
  let commands = [f.command(actual, "actual")];
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: ["~/jump/../alias/SKILL.md"], getCommands: () => commands });
  assert.deepEqual((await authority.getActiveSkills()).map(skill => skill.root), [dirname(actual)]);
  commands = [f.command(lexical, "lexical")];
  assert.deepEqual(await authority.getActiveSkills(), []);
});

test("authority failures and ambiguous unknown-name evaluation stay closed", async t => {
  const f = await fixture(t);
  const path = await f.skill(join(f.base, "unknown"));
  let checked = false;
  const authority = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => [f.command(path)],
    createManager: () => ({ discover: () => [{ name: "demo", skillPath: "/not-this-skill", enabled: true, scope: "global" } as ManagedSkill],
      is_enabled_by_skill: () => { checked = true; return true; } }) });
  assert.deepEqual(await authority.getActiveSkills(), []);
  assert.equal(checked, false);
  const failed = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [path], getCommands: () => { throw new Error("unavailable"); } });
  assert.deepEqual(await failed.getActiveSkills(), []);
  const missing = await createSkillAuthority({ cwd: f.cwd, trustedSkillPaths: [join(f.base, "missing", "SKILL.md")], getCommands: () => [f.command(path)] });
  assert.deepEqual(await missing.getActiveSkills(), []);
});
