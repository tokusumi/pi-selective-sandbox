import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { createApprovalProvider } from "../pi-extension.js";
import { ProjectGrantStore } from "../project-grants.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";
import { resolveGitProjectIdentity, resolveGitWorktreeCwd, resolveProjectIdentity, resolveProjectIdentityInfo } from "../project-identity.js";
import { SessionGrantStore } from "../session-grants.js";
import type { ApprovalRequest } from "../types.js";

const exec = promisify(execFile);

async function initialize(repo: string, gitDir?: string): Promise<void> {
  await exec("git", ["init", "-q", ...(gitDir ? ["--separate-git-dir", gitDir] : []), repo]);
  await exec("git", ["-C", repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "initial"]);
}

test("project identity is the main directory across linked worktrees, nested cwd, and aliases", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-worktrees-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  // Porcelain -z must preserve whitespace and newlines in directory names.
  const main = join(base, "main repo\nroot");
  const one = join(base, "one"); const two = join(base, "two");
  await initialize(main);
  await exec("git", ["-C", main, "worktree", "add", "--detach", one]);
  await exec("git", ["-C", main, "worktree", "add", "--detach", two]);
  const nested = join(one, "a", "b"); await mkdir(nested, { recursive: true });
  const alias = join(base, "alias"); await symlink(two, alias);
  const expected = await realpath(main);
  for (const cwd of [main, one, two, nested, alias]) {
    assert.equal(await resolveProjectIdentity(cwd), expected);
  }
  const clone = join(base, "clone");
  await exec("git", ["clone", "-q", main, clone]);
  assert.equal(await resolveProjectIdentity(clone), await realpath(clone));
  assert.notEqual(await resolveProjectIdentity(clone), expected);
});

test("project capability approvals persist across worktrees without broadening resource or host identity", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-worktree-grants-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const main = join(base, "main"); const one = join(base, "one"); const two = join(base, "two");
  await initialize(main);
  await exec("git", ["-C", main, "worktree", "add", "--detach", one]);
  await exec("git", ["-C", main, "worktree", "add", "--detach", two]);
  const capabilitiesPath = join(base, "state", "capabilities.json");
  const hostsPath = join(base, "state", "hosts.json");
  const project = async (cwd: string) => {
    const projectId = await resolveProjectIdentity(cwd);
    assert.ok(projectId);
    return { projectId, grants: new ProjectGrantStore(capabilitiesPath), hostGrants: new ProjectHostCommandGrantStore(hostsPath) };
  };
  const resource = join(base, "outside", "file.txt");
  const request: ApprovalRequest = {
    toolCallId: "write", toolName: "write", inputDigest: "digest", command: "write " + resource,
    capabilities: [{ kind: "filesystem.write", resource }], replayWarning: false,
    sessionGrantEligible: true, projectGrantEligible: true
  };
  // Legacy worktree-keyed grants must not silently become shared grants.
  await new ProjectGrantStore(capabilitiesPath).grant(await realpath(one), request.capabilities);
  let prompts = 0;
  const firstProject = await project(one);
  const first = createApprovalProvider({
    hasUI: true, sessionManager: { getSessionId: () => "one" },
    ui: { select: async () => { prompts++; return "Allow for project"; } }
  }, new SessionGrantStore(), firstProject);
  assert.equal(await first.request(request), "sandbox-allow-project");
  for (const cwd of [main, two]) {
    const future = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "future" } }, new SessionGrantStore(), await project(cwd));
    assert.equal(await future.request({ ...request, toolName: "edit", inputDigest: "changed" }), "sandbox-allow-project");
    assert.equal(await future.request({ ...request, capabilities: [{ kind: "filesystem.write", resource: resource + ".other" }] }), "deny");
    assert.equal(await future.request({ ...request, capabilities: [{ kind: "filesystem.read", resource }] }), "deny");
  }
  assert.equal(prompts, 1);
  const unrelated = join(base, "unrelated"); await initialize(unrelated);
  const other = createApprovalProvider({ hasUI: false }, new SessionGrantStore(), await project(unrelated));
  assert.equal(await other.request(request), "deny");

  const identity = { shellCommand: "echo test", cwd: await realpath(one), executionMode: "shell" };
  await firstProject.hostGrants.grant(firstProject.projectId, identity);
  const future = createApprovalProvider({ hasUI: false }, new SessionGrantStore(), await project(two));
  const hostRequest: ApprovalRequest = { ...request, kind: "escalation", toolName: "bash", command: identity.shellCommand, capabilities: [], commandIdentity: identity, replayWarning: true };
  assert.equal(await future.request(hostRequest), "host-allow-project");
  assert.equal(await future.request({ ...hostRequest, commandIdentity: { ...identity, cwd: await realpath(two) } }), "deny");
});

test("separate Git metadata is the Git-reported base identity shared with linked worktrees", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-separate-git-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const main = join(base, "main"); const metadata = join(base, "metadata"); const linked = join(base, "linked");
  await initialize(main, metadata);
  await exec("git", ["-C", main, "worktree", "add", "--detach", linked]);
  // With --separate-git-dir Git reports the metadata directory as its base.
  assert.equal(await resolveProjectIdentity(main), await realpath(metadata));
  assert.equal(await resolveProjectIdentity(linked), await realpath(metadata));
  const hosts = new ProjectHostCommandGrantStore(join(base, "hosts.json"));
  const projectId = await realpath(metadata);
  const command = { shellCommand: "sh /trusted/fixed.sh", cwd: await realpath(main), executionMode: "shell" };
  await hosts.grantGitProject(projectId, command, projectId, ".");
  for (const cwd of [main, linked]) {
    assert.equal(await resolveGitProjectIdentity(cwd), projectId);
    assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(cwd) }, projectId), true);
  }
  assert.equal(await resolveGitWorktreeCwd(metadata), undefined);
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(metadata) }, projectId), false);
  await assert.rejects(hosts.grantGitProject(projectId, { ...command, cwd: await realpath(metadata) }, projectId, "."));
});

test("worktrees of a bare repository share the bare base directory identity", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-bare-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const source = join(base, "source"); const bare = join(base, "bare.git"); const linked = join(base, "linked");
  await initialize(source);
  await exec("git", ["clone", "-q", "--bare", source, bare]);
  await exec("git", ["-C", bare, "worktree", "add", "--detach", linked]);
  assert.equal(await resolveProjectIdentity(bare), await realpath(bare));
  assert.equal(await resolveProjectIdentity(linked), await realpath(bare));
  assert.notEqual(await resolveProjectIdentity(source), await resolveProjectIdentity(bare));
  const hosts = new ProjectHostCommandGrantStore(join(base, "hosts.json"));
  const projectId = await realpath(bare);
  const command = { shellCommand: "sh /trusted/fixed.sh", cwd: await realpath(linked), executionMode: "shell" };
  await hosts.grantGitProject(projectId, command, projectId, ".");
  const linkedTwo = join(base, "linked-two");
  await exec("git", ["-C", bare, "worktree", "add", "--detach", linkedTwo]);
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(linkedTwo) }, projectId), true);
  assert.equal(await resolveGitWorktreeCwd(bare), undefined);
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(bare) }, projectId), false);
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(source) }, projectId), false);
  const bareCommand = { ...command, cwd: await realpath(bare) };
  await hosts.grant(projectId, bareCommand);
  assert.equal(await hosts.covers(projectId, bareCommand, projectId), true);
});

test("identity discovery ignores inherited Git overrides without altering the execution environment", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-project-git-env-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const main = join(base, "main"), other = join(base, "other"), plain = join(base, "plain");
  await initialize(main); await initialize(other); await mkdir(plain);
  const overrides = { GIT_DIR: join(main, ".git"), GIT_COMMON_DIR: join(main, ".git"), GIT_WORK_TREE: main,
    GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.bare", GIT_CONFIG_VALUE_0: "true" };
  const original = Object.fromEntries(Object.keys(overrides).map(key => [key, process.env[key]]));
  Object.assign(process.env, overrides);
  t.after(() => { for (const [key, value] of Object.entries(original)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  } });
  assert.equal(await resolveGitProjectIdentity(other), await realpath(other));
  assert.equal(await resolveGitProjectIdentity(plain), undefined);
  assert.deepEqual(await resolveProjectIdentityInfo(plain), { projectId: await realpath(plain) });
  const hosts = new ProjectHostCommandGrantStore(join(base, "hosts.json"));
  const projectId = await realpath(main);
  const command = { shellCommand: "fixed", cwd: projectId, executionMode: "shell" };
  await hosts.grantGitProject(projectId, command, projectId, ".");
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(other) }, projectId), false);
  assert.equal(await hosts.covers(projectId, { ...command, cwd: await realpath(plain) }, projectId), false);
  for (const [key, value] of Object.entries(overrides)) assert.equal(process.env[key], value);
});
