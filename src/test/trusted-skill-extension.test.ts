import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { create_skills_manager } from "@spences10/pi-skills";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";

test("replacement bash uses explicit loaded-user authority, not discovery paths or project grants", async t => {
  const base = await realpath(await mkdtemp(join(tmpdir(), "trusted-skill-extension-")));
  const agent = join(base, "agent"), cwd = join(base, "project");
  const old = process.env.PI_CODING_AGENT_DIR, oldProfile = process.env.MY_PI_SKILLS_PROFILE;
  process.env.PI_CODING_AGENT_DIR = agent;
  delete process.env.MY_PI_SKILLS_PROFILE;
  t.after(async () => {
    if (old === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = old;
    if (oldProfile === undefined) delete process.env.MY_PI_SKILLS_PROFILE; else process.env.MY_PI_SKILLS_PROFILE = oldProfile;
    await rm(base, { recursive: true, force: true });
  });
  await mkdir(cwd, { recursive: true });
  const root = join(agent, "skills", "worktree-finish");
  await mkdir(join(root, "scripts"), { recursive: true });
  const skillPath = join(root, "SKILL.md"), helper = join(root, "scripts", "finish-worktree.sh");
  await writeFile(skillPath, "---\nname: worktree-finish\ndescription: fixture\n---\nFixture\n");
  // Harmless fixture only; does not perform a real worktree finish.
  await writeFile(helper, "#!/bin/sh\nprintf 'host-helper:%s:%s' \"$1\" \"$2\"\n");
  await chmod(helper, 0o700);
  const folder = join(agent, "pi-selective-sandbox");
  await mkdir(folder);
  const manager = create_skills_manager({ cwd });
  manager.enable("worktree-finish@pi-native");
  assert.deepEqual(manager.get_enabled_skill_paths(), []);
  let wraps = 0;
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({
    logMonitorEnabled: true, wrap: async () => { wraps++; return "printf sandbox-fixture"; },
    getViolationsForCommand: () => [], forgetCommand: () => {}
  } as unknown as AnthropicSandboxRuntime));
  for (const scenario of ["missing-config", "allowed", "disabled", "project", "unloaded", "invalid-config"] as const) {
    await rm(join(folder, "config.json"), { force: true });
    if (scenario !== "missing-config") await writeFile(join(folder, "config.json"), JSON.stringify({ skills: {
      trustedSkillPaths: [scenario === "invalid-config" ? "worktree-finish" : skillPath]
    } }));
    if (scenario === "disabled") manager.disable("worktree-finish@pi-native");
    else manager.enable("worktree-finish@pi-native");
    const tools = new Map<string, ToolDefinition>();
    await selectiveSandboxExtension({ on: () => {}, registerCommand: () => {},
      getCommands: () => scenario === "unloaded" ? [] : [{ name: "skill:worktree-finish", source: "skill", sourceInfo: { path: skillPath, scope: scenario === "project" ? "project" : "user" } }],
      registerTool: (tool: ToolDefinition) => tools.set(tool.name, tool)
    } as never);
    const before = wraps;
    const output = await tools.get("bash")!.execute(scenario, { command: `'${helper}' --message "変更 内容"` }, new AbortController().signal, () => {}, { cwd, hasUI: false } as never);
    const allowed = scenario === "allowed";
    assert.match(JSON.stringify(output.content), allowed ? /host-helper:--message:変更 内容/ : /sandbox-fixture/, scenario);
    assert.equal(wraps - before, allowed ? 0 : 1, scenario);
  }
});
