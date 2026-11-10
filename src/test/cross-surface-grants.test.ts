import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { DEFAULT_WRITE_PROFILES } from "../config.js";
import { pathContains } from "../git-write-paths.js";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import type { Capability } from "../types.js";

// Exercise the registered tools and real providers/stores. Only the OS sandbox
// is simulated: wrap returns fixed success/failure shell commands, never the
// requested write command. Native tools do real, isolated fixture mutations.
for (const duration of ["session", "project"] as const) {
  test(`${duration}: bash/native exact-target reuse and isolation`, async t => {
    const base = await realpath(await mkdtemp(join(tmpdir(), "pi-cross-grants-")));
    const cwd = join(base, "workspace"), outside = join(base, "outside");
    const agent = join(base, "agent");
    await Promise.all([mkdir(cwd), mkdir(outside), mkdir(join(agent, "pi-selective-sandbox"), { recursive: true })]);
    await writeFile(join(agent, "pi-selective-sandbox", "config.json"), JSON.stringify({
      filesystem: { disabledDefaultProfiles: DEFAULT_WRITE_PROFILES }
    }));
    const original = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = agent;
    t.after(async () => {
      if (original === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = original;
      await rm(base, { recursive: true, force: true });
    });
    let bashTarget = "";
    const attempts: Capability[][] = [];
    t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({
      logMonitorEnabled: true,
      wrap: async (_command: string, context: { extraCapabilities?: Capability[] }) => {
        const caps = context.extraCapabilities ?? [];
        attempts.push([...caps]);
        return caps.some(cap => cap.kind === "filesystem.write" && pathContains(cap.resource, bashTarget)) ? "true" : "exit 1";
      },
      getViolationsForCommand: () => [{ kind: "filesystem.write", resource: bashTarget }],
      forgetCommand: () => undefined
    } as unknown as AnthropicSandboxRuntime));
    const start = async (sessionCwd = cwd) => {
      const tools = new Map<string, ToolDefinition>();
      await selectiveSandboxExtension({ on: () => undefined, registerCommand: () => undefined,
        registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); }
      } as never);
      const answers: string[] = [], prompts: string[] = [];
      let session = "child-A";
      const execute = (name: string, params: unknown) => tools.get(name)!.execute(name, params,
        new AbortController().signal, () => {}, {
          cwd: sessionCwd, hasUI: true, sessionManager: { getSessionId: () => session }, ui: {
            select: async (title: string, choices: string[]) => {
              prompts.push(title);
              const answer = answers.shift() ?? "Deny";
              assert.ok(choices.includes(answer), `Unexpected choice ${answer}: ${choices.join(", ")}`);
              return answer;
            }
          }
        } as never);
      return { execute, answers, prompts, session: (id: string) => { session = id; } };
    };
    const run = await start();
    const sandboxDuration = duration === "session" ? "This session" : "This project";
    const nativeDuration = duration === "session" ? "Allow for session" : "Allow for project";
    const parent = join(outside, "cache"); await mkdir(parent);
    const target = join(parent, "file"), sibling = join(parent, "sibling");
    bashTarget = target;
    run.answers.push(parent, sandboxDuration, "Allow and retry");
    assert.notEqual((await run.execute("bash", { command: "simulated write" })).isError, true);
    assert.equal(attempts.length, 2);
    assert.deepEqual(attempts[1], [{ kind: "filesystem.write", resource: parent }]);
    const prompts = run.prompts.length;
    bashTarget = sibling;
    assert.notEqual((await run.execute("bash", { command: "simulated sibling write" })).isError, true);
    assert.equal(run.prompts.length, prompts, "bash reuses the parent for another descendant");
    // Directory approval is not an exact native file approval.
    await assert.rejects(run.execute("write", { path: target, content: "denied" }), /Permission denied/);
    await assert.rejects(readFile(target));
    assert.match(run.prompts.at(-1)!, /exact canonical target/);
    assert.match(run.prompts.at(-1)!, /not inherited/);
    run.answers.push(nativeDuration);
    await run.execute("write", { path: target, content: "before" });
    const afterNative = run.prompts.length;
    await run.execute("edit", { path: target, edits: [{ oldText: "before", newText: "after" }] });
    assert.equal(run.prompts.length, afterNative, "write and edit share an exact grant");
    await assert.rejects(run.execute("write", { path: sibling, content: "no" }), /Permission denied/);
    assert.equal(await readFile(target, "utf8"), "after");

    // Bash exact leaf -> native reuses the same canonical capability.
    const bashLeaf = join(outside, "bash-leaf");
    await writeFile(bashLeaf, "before");
    bashTarget = bashLeaf;
    run.answers.push(bashLeaf, sandboxDuration, "Allow and retry");
    await run.execute("bash", { command: "simulated leaf approval" });
    const afterBashLeaf = run.prompts.length;
    await run.execute("edit", { path: bashLeaf, edits: [{ oldText: "before", newText: "after" }] });
    assert.equal(run.prompts.length, afterBashLeaf);

    // Native -> bash: only the exact leaf, never its parent or sibling.
    const leaf = join(outside, "native-leaf");
    run.answers.push(nativeDuration);
    await run.execute("write", { path: leaf, content: "native" });
    const beforeBash = run.prompts.length;
    bashTarget = leaf;
    assert.notEqual((await run.execute("bash", { command: "simulated exact write" })).isError, true);
    assert.equal(run.prompts.length, beforeBash);
    bashTarget = `${leaf}-sibling`;
    // Deny the first scope selection rather than approving a wider path.
    run.answers.push("/"); // choose a valid ancestor, then deny duration
    run.answers.push("Once", "Deny");
    assert.equal((await run.execute("bash", { command: "simulated unapproved write" })).isError, true);
    await assert.rejects(run.execute("write", { path: `${leaf}-sibling`, content: "no" }), /Permission denied/);

    // A different child ID never inherits Session. Project reuse is deliberate.
    run.session("child-B");
    const beforeChild = run.prompts.length;
    if (duration === "session") {
      await assert.rejects(run.execute("write", { path: leaf, content: "no" }), /Permission denied/);
      bashTarget = target; run.answers.push(target, "Once", "Deny");
      assert.equal((await run.execute("bash", { command: "simulated other child" })).isError, true);
    } else {
      await run.execute("write", { path: leaf, content: "project child" });
      bashTarget = target;
      assert.notEqual((await run.execute("bash", { command: "simulated project child" })).isError, true);
      assert.equal(run.prompts.length, beforeChild);
    }

    // Reload loses memory grants, but a new ProjectGrantStore reads saved ones.
    const reloaded = await start();
    if (duration === "session") {
      await assert.rejects(reloaded.execute("write", { path: leaf, content: "no" }), /Permission denied/);
    } else {
      await reloaded.execute("write", { path: leaf, content: "persisted" });
      assert.equal(reloaded.prompts.length, 0);
    }
    bashTarget = target;
    if (duration === "session") reloaded.answers.push(target, "Once", "Deny");
    assert.equal((await reloaded.execute("bash", { command: "simulated after reload" })).isError === true, duration === "session");
    // Another non-Git project cannot use this project's grants.
    const otherCwd = join(base, "other-workspace"); await mkdir(otherCwd);
    const otherProject = await start(otherCwd);
    await assert.rejects(otherProject.execute("write", { path: leaf, content: "no" }), /Permission denied/);

    // Once approvals are absent from the next operation, on both surfaces.
    const onceLeaf = join(outside, "once-leaf");
    run.answers.push("Allow once");
    await run.execute("write", { path: onceLeaf, content: "once" });
    await assert.rejects(run.execute("write", { path: onceLeaf, content: "no" }), /Permission denied/);
    bashTarget = join(outside, "once-bash");
    run.answers.push(bashTarget, "Once", "Allow and retry");
    await run.execute("bash", { command: "simulated once" });
    run.answers.push(bashTarget, "Once", "Deny");
    assert.equal((await run.execute("bash", { command: "simulated once expired" })).isError, true);

    // Canonical symlink aliases reuse an exact target, but retargeting does not.
    run.session("child-A");
    const alias = join(cwd, "alias"); await symlink(leaf, alias);
    await run.execute("write", { path: alias, content: "canonical" });
    await rm(alias); await symlink(`${leaf}-different`, alias);
    await assert.rejects(run.execute("write", { path: alias, content: "no" }), /Permission denied/);

    // A historical leaf replaced by a directory gains no native descendants.
    await rm(leaf); await mkdir(leaf);
    await assert.rejects(run.execute("write", { path: join(leaf, "child"), content: "no" }), /Permission denied/);

    if (duration === "project") {
      // Main's freshness contract applies to existing providers as well as new
      // ones: quiescent disk removal affects the next native lookup/bash call.
      await writeFile(join(agent, "pi-selective-sandbox", "project-grants.json"), JSON.stringify({ version: 1, projects: {} }));
      for (const revoked of [run, reloaded, await start()]) {
        await assert.rejects(revoked.execute("write", { path: target, content: "no" }), /Permission denied/);
        bashTarget = target;
        revoked.answers.push(target, "Once", "Deny");
        assert.equal((await revoked.execute("bash", { command: "simulated revoked" })).isError, true);
      }
    }

    // Even a stored broad ancestor cannot authorize the private bridge root.
    bashTarget = join(outside, "root-probe");
    run.answers.push("/", sandboxDuration, "Allow and retry");
    await run.execute("bash", { command: "simulated stored root approval" });
    const beforePrivate = run.prompts.length;
    await assert.rejects(run.execute("write", { path: join(agent, "pi-selective-sandbox", "approvals", "tamper"), content: "no" }), /configured deny root/);
    assert.equal(run.prompts.length, beforePrivate);
  });
}
