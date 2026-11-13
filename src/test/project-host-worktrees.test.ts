import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension, { createApprovalProvider } from "../pi-extension.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";
import { ProjectGrantStore } from "../project-grants.js";
import { resolveGitProjectIdentity, resolveProjectIdentityInfo } from "../project-identity.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SessionGrantStore } from "../session-grants.js";
import { SessionHostCommandGrantStore } from "../session-host-command-grants.js";
import type { CommandIdentity, EscalationApprovalRequest } from "../types.js";

const exec = promisify(execFile);
const identity = (cwd: string, shellCommand = "sh /trusted/fixed.sh", executionMode = "shell"): CommandIdentity => ({ cwd, shellCommand, executionMode });
const request = (command: CommandIdentity): EscalationApprovalRequest => ({
  kind: "escalation", toolCallId: "call", toolName: "bash", inputDigest: "digest", command: command.shellCommand,
  commandIdentity: command, capabilities: [], observedCapabilities: [{ kind: "filesystem.read", resource: "/outside" }],
  replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true
});
async function fixture(t: test.TestContext) {
  const base = await mkdtemp(join(tmpdir(), "pi-project-host-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const main = join(base, "main repo\nroot"), a = join(base, "a"), b = join(base, "b");
  await exec("git", ["init", "-q", main]);
  await exec("git", ["-C", main, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "initial"]);
  await exec("git", ["-C", main, "worktree", "add", "--detach", a]);
  await exec("git", ["-C", main, "worktree", "add", "--detach", b]);
  const project = await resolveProjectIdentityInfo(a);
  assert.ok(project?.gitProjectId);
  const hosts = new ProjectHostCommandGrantStore(join(base, "hosts.json"));
  return { base, main, a: await realpath(a), b: await realpath(b), project, hosts };
}

function hostUI(titles: string[], duration = "This project") {
  return { select: async (title: string, choices: string[]) => {
    titles.push(title);
    return choices.includes("Run outside sandbox…") ? "Run outside sandbox…"
      : title === "Run outside sandbox — duration" ? duration : "Run on host";
  } };
}

test("explicit Git project host approval reuses command/mode across worktree roots and aliases, not arbitrary subdirs", async t => {
  const f = await fixture(t);
  const nested = join(f.b, "subdir"); await mkdir(nested);
  const alias = join(f.base, "alias"); await symlink(f.b, alias);
  const clone = join(f.base, "clone"); await exec("git", ["clone", "-q", f.main, clone]);
  const other = join(f.base, "other"); await exec("git", ["init", "-q", other]);
  const nestedRepo = join(f.b, "independent-repo"); await exec("git", ["init", "-q", nestedRepo]);
  const outside = join(f.base, "plain"); await mkdir(outside);
  const titles: string[] = [];
  const grants = new ProjectGrantStore(join(f.base, "resources.json"));
  const project = { ...f.project, hostGrants: f.hosts, grants };
  const provider = createApprovalProvider({ hasUI: true, ui: hostUI(titles) }, new SessionGrantStore(), project);
  assert.equal(await provider.request(request(identity(f.a))), "host-allow-project");
  assert.match(titles.at(-1)!, /same canonical worktree-relative cwd/);
  assert.match(titles.at(-1)!, /NOT changed to the project base/);
  assert.match(titles.at(-1)!, /Relative paths, local scripts, configuration/);
  assert.match(titles.at(-1)!, /exact command and execution mode/);
  assert.match(titles.at(-1)!, /not a resource permission, command prefix, or general shell permission/);
  const reload = new ProjectHostCommandGrantStore(f.hosts.storagePath);
  for (const cwd of [f.main, f.a, f.b, alias]) {
    const info = await resolveProjectIdentityInfo(cwd); assert.ok(info);
    const future = createApprovalProvider({ hasUI: false }, new SessionGrantStore(), { ...info, grants, hostGrants: reload });
    assert.equal(await future.request(request(identity(await realpath(cwd)))), "host-allow-project");
  }
  for (const cwd of [clone, other, nestedRepo, outside, nested]) {
    const info = await resolveProjectIdentityInfo(cwd); assert.ok(info);
    const future = createApprovalProvider({ hasUI: false }, new SessionGrantStore(), { ...info, grants, hostGrants: reload });
    assert.equal(await future.request(request(identity(await realpath(cwd)))), "deny");
    // Even a provider fixed to A's project must not authorize another cwd.
    assert.equal(await reload.covers(f.project.projectId, identity(await realpath(cwd)), f.project.gitProjectId), false);
    await assert.rejects(reload.grantGitProject(f.project.projectId, identity(await realpath(cwd)), f.project.gitProjectId, "."));
  }
  await rm(alias); await symlink(outside, alias);
  assert.equal(await reload.covers(f.project.projectId, identity(await realpath(alias)), f.project.gitProjectId), false);
  for (const command of [identity(f.b, "sh /trusted/fixed.sh --extra"), identity(f.b, "sh /trusted/other.sh"), identity(f.b, "sh /trusted/fixed.sh", "login-shell")]) {
    assert.equal(await reload.covers(f.project.projectId, command, f.project.gitProjectId), false);
  }
  assert.deepEqual(await grants.capabilities(f.project.projectId), []);
  assert.equal(await grants.covers(f.project.projectId, [{ kind: "filesystem.write", resource: f.b }]), false);
  await rm(f.hosts.storagePath);
  assert.equal(await reload.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), false);
});

test("Project host approval retains canonical relative cwd in both the original and other worktrees", async t => {
  const f = await fixture(t), titles: string[] = [];
  for (const root of [f.main, f.a, f.b]) await mkdir(join(root, "src", "child"), { recursive: true });
  for (const root of [f.a, f.b]) await mkdir(join(root, "tests"));
  const alias = join(f.a, "src-alias"); await symlink(join(f.a, "src"), alias);
  const project = { ...f.project, hostGrants: f.hosts, grants: new ProjectGrantStore(join(f.base, "resources.json")) };
  const provider = createApprovalProvider({ hasUI: true, ui: hostUI(titles) }, new SessionGrantStore(), project);
  assert.equal(await provider.request(request(identity(await realpath(alias)))), "host-allow-project");
  assert.match(titles.at(-1)!, /Worktree-relative cwd: src/);
  assert.match(titles.at(-1)!, /does not approve every cwd or descendants/);
  const future = createApprovalProvider({ hasUI: false }, new SessionGrantStore(), project);
  for (const cwd of [join(f.main, "src"), join(f.a, "src"), join(f.b, "src"), alias, join(f.b, "src", "..", "src")]) {
    assert.equal(await future.request(request(identity(await realpath(cwd)))), "host-allow-project");
  }
  for (const cwd of [f.a, f.b, join(f.a, "tests"), join(f.b, "tests"), join(f.a, "src", "child"), join(f.b, "src", "child")]) {
    assert.equal(await future.request(request(identity(await realpath(cwd)))), "deny");
    await assert.rejects(f.hosts.grantGitProject(project.projectId, identity(await realpath(cwd)), project.gitProjectId, "src"));
  }
  await rm(alias); await symlink(join(f.a, "tests"), alias);
  assert.equal(await future.request(request(identity(await realpath(alias)))), "deny");
  assert.deepEqual((await f.hosts.commands(project.projectId)).map(entry => entry.cwdScope === "git-worktree-relative" ? entry.relativeCwd : undefined), ["src"]);
});

test("relative cwd must still match after confirmation even when Git project membership is unchanged", async t => {
  const f = await fixture(t), cwd = join(f.a, "subdir"); await mkdir(cwd);
  const project = { ...f.project, hostGrants: f.hosts, grants: new ProjectGrantStore(join(f.base, "resources.json")) };
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async (title, choices) => {
    if (choices.includes("Run on host")) {
      assert.match(title, /Worktree-relative cwd: subdir/);
      // The same absolute cwd becomes another worktree root of the same repo.
      await exec("git", ["-C", f.main, "worktree", "add", "--detach", cwd]);
    }
    return hostUI([]).select(title, choices);
  } } }, new SessionGrantStore(), project);
  assert.equal(await provider.request(request(identity(await realpath(cwd)))), "deny");
  assert.equal(await f.hosts.gitProjectCwd(project.projectId, identity(await realpath(cwd)), project.gitProjectId), ".");
  assert.deepEqual(await f.hosts.commands(project.projectId), []);
});

test("legacy v1 grants stay exact through v3 writes; invalid scope/version never broadens them", async t => {
  const f = await fixture(t), original = identity(f.a);
  await writeFile(f.hosts.storagePath, JSON.stringify({ version: 1, projects: { [f.project.projectId]: [{ ...original, cwdScope: "git-project" }] } }));
  assert.equal(await f.hosts.covers(f.project.projectId, original, f.project.gitProjectId), true);
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), false);
  await f.hosts.grant(f.project.projectId, identity(f.b, "another command"));
  const saved = JSON.parse(await readFile(f.hosts.storagePath, "utf8"));
  assert.equal(saved.version, 3);
  assert.ok(saved.projects[f.project.projectId].every((entry: any) => entry.cwdScope === "exact-cwd"));
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), false);
  // Both v1 and the earlier v2 reader reject the v3 envelope.
  assert.notEqual(saved.version, 1);
  assert.notEqual(saved.version, 2);
  await f.hosts.grantGitProject(f.project.projectId, original, f.project.gitProjectId, ".");
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), true);
  assert.equal((await f.hosts.commands(f.project.projectId)).filter(entry => entry.cwdScope === "git-worktree-relative").length, 1);
  await f.hosts.grantGitProject(f.project.projectId, identity(f.b), f.project.gitProjectId, ".");
  assert.equal((await f.hosts.commands(f.project.projectId)).filter(entry => entry.cwdScope === "git-worktree-relative").length, 1);
  for (const entry of [original, { ...original, cwdScope: "unknown" }, { ...original, cwdScope: "git-project" },
    { ...original, cwdScope: "git-worktree-relative", relativeCwd: ".", cwd: "relative" },
    ...[undefined, "", "../src", "/src", "src/../src", "src/", "./src"].map(relativeCwd => ({ ...original, cwdScope: "git-worktree-relative", relativeCwd }))]) {
    await writeFile(f.hosts.storagePath, JSON.stringify({ version: 3, projects: { [f.project.projectId]: [entry] } }));
    assert.equal(await f.hosts.covers(f.project.projectId, original, f.project.gitProjectId), false);
    assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), false);
  }
});

test("v2 exact-cwd entries survive v3 writes but broad git-project entries require fresh approval", async t => {
  const f = await fixture(t), command = identity(f.a);
  await writeFile(f.hosts.storagePath, JSON.stringify({ version: 2, projects: { [f.project.projectId]: [
    { ...command, cwdScope: "git-project" },
    { ...identity(f.a, "legacy exact"), cwdScope: "exact-cwd" },
    { ...command, cwdScope: "git-worktree-relative", relativeCwd: "." }
  ] } }));
  for (const cwd of [f.a, f.b]) assert.equal(await f.hosts.covers(f.project.projectId, identity(cwd), f.project.gitProjectId), false);
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.a, "legacy exact"), f.project.gitProjectId), true);
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b, "legacy exact"), f.project.gitProjectId), false);
  await f.hosts.grantGitProject(f.project.projectId, command, f.project.gitProjectId, ".");
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), true);
  const entries = await f.hosts.commands(f.project.projectId);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map(entry => entry.cwdScope).sort(), ["exact-cwd", "git-worktree-relative"]);
});

test("Git failure and fallback string equality are not proof for relative-cwd host authority", async t => {
  const f = await fixture(t);
  await f.hosts.grantGitProject(f.project.projectId, identity(f.a), f.project.gitProjectId, ".");
  const failGit = { gitRoot: async () => { throw new Error("Git unavailable"); } };
  const fallback = await resolveProjectIdentityInfo(f.main, failGit); assert.ok(fallback);
  assert.equal(fallback.projectId, f.project.projectId);
  assert.equal(fallback.gitProjectId, undefined);
  assert.equal(await resolveGitProjectIdentity(f.main, failGit), undefined);
  assert.equal(await resolveGitProjectIdentity(f.main, { canonicalize: async () => { throw new Error("canonicalization failed"); } }), undefined);
  assert.equal(await f.hosts.covers(fallback.projectId, identity(f.b), fallback.gitProjectId), false);
  await assert.rejects(f.hosts.grantGitProject(fallback.projectId, identity(f.b), fallback.gitProjectId, "."));
  // Fresh command-cwd lookup must also fail closed when the repository disappears.
  await rm(join(f.b, ".git"));
  assert.equal(await resolveGitProjectIdentity(f.b), undefined);
  assert.equal(await f.hosts.covers(f.project.projectId, identity(f.b), f.project.gitProjectId), false);
  await assert.rejects(f.hosts.grantGitProject(f.project.projectId, identity(f.b), f.project.gitProjectId, "."));
  const outside = join(f.base, "outside"); await mkdir(outside);
  const info = await resolveProjectIdentityInfo(outside); assert.ok(info);
  const titles: string[] = [];
  const provider = createApprovalProvider({ hasUI: true, ui: hostUI(titles) }, new SessionGrantStore(), {
    ...info, hostGrants: f.hosts, grants: new ProjectGrantStore(join(f.base, "resources.json"))
  });
  assert.equal(await provider.request(request(identity(await realpath(outside)))), "host-allow-project");
  assert.match(titles.at(-1)!, /this exact canonical working directory only/);
  assert.match(titles.at(-1)!, /NOT be shared across working directories/);
  assert.equal((await f.hosts.commands(info.projectId))[0].cwdScope, "exact-cwd");
});

test("Git-project authority is revalidated after confirmation, never downgraded or saved on failure", async t => {
  const f = await fixture(t);
  const project = { ...f.project, hostGrants: f.hosts, grants: new ProjectGrantStore(join(f.base, "resources.json")) };
  let confirmations = 0;
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async (title, choices) => {
    if (choices.includes("Run on host")) {
      confirmations++;
      assert.match(title, /same canonical worktree-relative cwd/);
      await rm(join(f.a, ".git"));
    }
    return hostUI([]).select(title, choices);
  } } }, new SessionGrantStore(), project);
  assert.equal(await provider.request(request(identity(f.a))), "deny");
  assert.equal(confirmations, 1);
  assert.deepEqual(await f.hosts.commands(project.projectId), []);
});

test("Once and Session host approvals keep exact cwd and session boundaries in Git projects", async t => {
  const f = await fixture(t), hosts = new SessionHostCommandGrantStore();
  let duration = "Once";
  const project = { ...f.project, hostGrants: f.hosts, grants: new ProjectGrantStore(join(f.base, "resources.json")) };
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "a" }, ui: {
    select: async (title, choices) => hostUI([], duration).select(title, choices)
  } }, new SessionGrantStore(), project, hosts);
  assert.equal(await provider.request(request(identity(f.a))), "host-allow-once");
  assert.equal(hosts.covers("a", identity(f.a)), false);
  assert.deepEqual(await f.hosts.commands(project.projectId), []);
  duration = "This session";
  assert.equal(await provider.request(request(identity(f.a))), "host-allow-session");
  assert.equal(hosts.covers("a", identity(f.a)), true);
  assert.equal(hosts.covers("a", identity(f.b)), false);
  assert.equal(hosts.covers("b", identity(f.a)), false);
  assert.deepEqual(await f.hosts.commands(project.projectId), []);
});

test("registered bash reuses A/src approval in B/src, not A/tests or B/tests, and retains execution cwd", async t => {
  const f = await fixture(t);
  for (const root of [f.a, f.b]) for (const subdir of ["src", "tests"]) await mkdir(join(root, subdir));
  const cwdA = await realpath(join(f.a, "src")), cwdB = await realpath(join(f.b, "src"));
  const agentDir = join(f.base, "agent");
  const environment = { PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR, GIT_DIR: process.env.GIT_DIR };
  process.env.PI_CODING_AGENT_DIR = agentDir;
  // Discovery ignores this override; the actual approved host command must
  // still receive it. Do not conflate identity normalization with execution.
  const gitDir = join(f.main, ".git");
  process.env.GIT_DIR = gitDir;
  t.after(() => { for (const [key, value] of Object.entries(environment)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  } });
  let sandboxExit = 19, denials = true;
  const order: string[] = [];
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({
    logMonitorEnabled: true, dispose: async () => {},
    wrap: async () => { order.push("sandbox"); return `exit ${sandboxExit}`; },
    getViolationsForCommand: () => denials ? [{ kind: "filesystem.read", resource: "/outside" }] : []
  } as unknown as AnthropicSandboxRuntime));
  const helper = join(f.base, "fixed.sh"); await writeFile(helper, "printf '%s\\n' \"$PWD\" \"git-dir=$GIT_DIR\"\n");
  const command = `sh '${helper}'`;
  const titles: string[] = [];
  async function session(cwd: string, hasUI: boolean) {
    let bash: ToolDefinition | undefined;
    const handlers = new Map<string, (...args: any[]) => any>();
    await selectiveSandboxExtension({
      on: (event: string, handler: (...args: any[]) => any) => { handlers.set(event, handler); },
      appendEntry: () => {}, registerCommand: () => {},
      registerTool: (tool: ToolDefinition) => { if (tool.name === "bash") bash = tool; }
    } as never, { loadSubagentApi: async () => undefined });
    const context = { cwd, hasUI, sessionManager: { getSessionId: () => cwd }, ui: hostUI(titles) };
    await handlers.get("session_start")!({}, context);
    t.after(() => handlers.get("session_shutdown")?.());
    return (intent = false) => bash!.execute("call", { command, retryOnSandboxDenial: intent }, new AbortController().signal, () => {}, context as never);
  }
  const a = await session(cwdA, true);
  const first = await a(true);
  assert.equal((first.details as any).selectiveSandbox.disposition, "host");
  assert.ok((first.structuredContent as any).output.includes(cwdA));
  assert.equal(titles.length, 3);
  const b = await session(cwdB, false);
  const defaultResult = await b();
  assert.equal((defaultResult.details as any).selectiveSandbox.retryNotRequested, true);
  assert.equal((defaultResult.structuredContent as any).exit_code, 19);
  const second = await b(true);
  assert.equal((second.details as any).selectiveSandbox.disposition, "host");
  assert.equal((second.structuredContent as any).exit_code, 0);
  assert.ok((second.structuredContent as any).output.includes(cwdB));
  assert.ok((second.structuredContent as any).output.includes(`git-dir=${gitDir}`), "the host subprocess retains inherited Git environment overrides");
  assert.ok(!(second.structuredContent as any).output.includes(cwdA));
  assert.equal(titles.length, 3, "stored Project approval must not prompt in B/src");
  for (const root of [f.a, f.b]) {
    const otherCwd = await session(join(root, "tests"), false);
    const denied = await otherCwd(true);
    assert.equal((denied.details as any).selectiveSandbox.disposition, "denied");
    assert.equal((denied.structuredContent as any).exit_code, 19);
  }
  denials = false;
  assert.equal(((await b(true)).details as any).selectiveSandbox.disposition, "sandbox");
  sandboxExit = 0; denials = true;
  assert.equal(((await b(true)).details as any).selectiveSandbox.disposition, "sandbox");
  assert.equal(order.length, 7, "every invocation starts sandboxed, even with a reusable host grant");
});
