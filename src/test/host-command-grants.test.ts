import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SelectiveSandboxExecutor } from "../executor.js";
import { createApprovalProvider } from "../pi-extension.js";
import { CapabilityPolicy } from "../policy.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";
import { SessionGrantStore } from "../session-grants.js";
import { commandIdentityKey, SessionHostCommandGrantStore } from "../session-host-command-grants.js";
import type { ApprovalRequest, CommandIdentity, CommandResult, SandboxRuntime } from "../types.js";

const command = (cwd = "/project", shellCommand = "npm run build", executionMode = "shell"): CommandIdentity => ({ shellCommand, cwd, executionMode });
const capability = { kind: "filesystem.write" as const, resource: "/observed/foo" };
const escalation = (identity?: CommandIdentity): ApprovalRequest => ({
  kind: "escalation", toolCallId: "call", toolName: "bash", inputDigest: "digest", capabilities: [capability],
  command: identity?.shellCommand ?? "npm run build", replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true, commandIdentity: identity
});
const result = (exitCode = 0): CommandResult => ({ exitCode, stdout: "", stderr: "" });

function executorFixture(violations: readonly { kind: "filesystem.write"; resource: string }[], sandbox: () => CommandResult, approvals: (request: ApprovalRequest) => Promise<any>) {
  const calls = { sandbox: 0, host: 0, ui: 0 };
  const runtime: SandboxRuntime = { wrap: async command => command, getViolationsForCommand: () => violations };
  const runner = { runSandbox: async () => { calls.sandbox++; return sandbox(); }, runHost: async () => { calls.host++; return result(); } };
  return { calls, executor: new SelectiveSandboxExecutor({ runtime, runner, policy: new CapabilityPolicy([]), approvals: { request: approvals }, commandIdentity: async shellCommand => command("/canonical/project", shellCommand) }) };
}

test("CommandIdentity matches only exact command, canonical cwd, and execution mode", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-host-identity-")); const target = join(base, "target"); const alias = join(base, "alias");
  await mkdir(target); await symlink(target, alias);
  const direct = command(await realpath(target)); const viaLink = command(await realpath(alias));
  assert.equal(commandIdentityKey(direct), commandIdentityKey(viaLink));
  assert.notEqual(commandIdentityKey(direct), commandIdentityKey(command(direct.cwd, "npm test")));
  assert.notEqual(commandIdentityKey(direct), commandIdentityKey(command("/another/project")));
  assert.notEqual(commandIdentityKey(direct), commandIdentityKey(command(direct.cwd, direct.shellCommand, "login-shell")));
});

test("host once is not stored, while a session host grant is exact and session-local", async () => {
  const sessionCapabilities = new SessionGrantStore(); const hosts = new SessionHostCommandGrantStore(); let selected = "Run command on host once";
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => selected } }, sessionCapabilities, undefined, hosts);
  assert.equal(await provider.request(escalation(command())), "host-allow-once");
  assert.equal(hosts.covers("A", command()), false);
  selected = "Run command on host for session";
  assert.equal(await provider.request(escalation(command())), "host-allow-session");
  assert.equal(hosts.covers("A", command()), true);
  assert.equal(await createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "A" } }, sessionCapabilities, undefined, hosts).request(escalation(command())), "host-allow-session");
  assert.equal(await createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "B" } }, sessionCapabilities, undefined, hosts).request(escalation(command())), "deny");
  assert.equal(hosts.covers("A", command("/project", "npm test")), false);
});

test("project host grant persists by project and stores command identity, not observed resource", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-host-project-")); const path = join(base, "host-command-grants.json");
  const store = new ProjectHostCommandGrantStore(path); const hostSessions = new SessionHostCommandGrantStore();
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => "Run command on host for project" } }, new SessionGrantStore(), { projectId: "/project-a", grants: new (await import("../project-grants.js")).ProjectGrantStore(join(base, "caps.json")), hostGrants: store }, hostSessions);
  assert.equal(await provider.request(escalation(command())), "host-allow-project");
  assert.equal(await new ProjectHostCommandGrantStore(path).covers("/project-a", command()), true);
  const future = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "B" } }, new SessionGrantStore(), { projectId: "/project-a", grants: new (await import("../project-grants.js")).ProjectGrantStore(join(base, "caps.json")), hostGrants: new ProjectHostCommandGrantStore(path) }, new SessionHostCommandGrantStore());
  assert.equal(await future.request(escalation(command())), "host-allow-project");
  assert.equal(await new ProjectHostCommandGrantStore(path).covers("/project-b", command()), false);
  const persisted = await readFile(path, "utf8");
  assert.match(persisted, /shellCommand/); assert.doesNotMatch(persisted, /"resource"/); assert.doesNotMatch(persisted, /observed\/foo/);
});

test("malformed host project grants fail closed", async () => {
  const base = await mkdtemp(join(tmpdir(), "pi-host-invalid-")); const path = join(base, "grants.json");
  await writeFile(path, "{bad json");
  assert.equal(await new ProjectHostCommandGrantStore(path).covers("/project", command()), false);
  await writeFile(path, JSON.stringify({ version: 9, projects: { "/project": [command()] } }));
  assert.equal(await new ProjectHostCommandGrantStore(path).covers("/project", command()), false);
});

test("matching host grant still succeeds in sandbox without host replay", async () => {
  const f = executorFixture([{ kind: "filesystem.write", resource: "/observed/foo" }], () => result(), async () => { throw new Error("must not ask"); });
  assert.equal((await f.executor.execute("npm run build", "success")).disposition, "sandbox");
  assert.deepEqual(f.calls, { sandbox: 1, host: 0, ui: 0 });
});

test("ordinary sandbox failure never replays on host even if approval would allow it", async () => {
  const f = executorFixture([], () => result(2), async () => "host-allow-project");
  assert.equal((await f.executor.execute("npm run build", "ordinary-failure")).disposition, "sandbox");
  assert.equal(f.calls.host, 0);
});

test("a stored host grant replays exactly once only after a sandbox violation and without UI", async () => {
  const hosts = new SessionHostCommandGrantStore(); hosts.grant("A", command("/canonical/project"));
  const provider = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "A" } }, new SessionGrantStore(), undefined, hosts);
  const f = executorFixture([{ kind: "filesystem.write", resource: "/observed/foo" }], () => result(1), request => provider.request(request));
  assert.equal((await f.executor.execute("npm run build", "violation")).disposition, "host");
  assert.equal(f.calls.sandbox, 1); assert.equal(f.calls.host, 1);
});

test("sandbox capability grants never match host commands and host grants never widen sandbox capabilities", async () => {
  const capabilities = new SessionGrantStore(); capabilities.grant("A", [capability]); const hosts = new SessionHostCommandGrantStore();
  const provider = createApprovalProvider({ hasUI: false, sessionManager: { getSessionId: () => "A" } }, capabilities, undefined, hosts);
  assert.equal(await provider.request(escalation(command())), "sandbox-allow-session");
  hosts.grant("A", command());
  assert.equal(capabilities.covers("A", [capability]), true);
  assert.equal(capabilities.covers("A", [{ kind: "filesystem.write", resource: "/different" }]), false);
});

test("uncanonicalizable cwd offers host once but never reusable host scopes", async () => {
  const choices: string[][] = [];
  const provider = createApprovalProvider({
    hasUI: true, sessionManager: { getSessionId: () => "A" },
    ui: { select: async (_message, options) => { choices.push(options); return "Deny"; } }
  }, new SessionGrantStore(), {
    projectId: "/project", grants: new (await import("../project-grants.js")).ProjectGrantStore(join(tmpdir(), "unused-caps.json")),
    hostGrants: new ProjectHostCommandGrantStore(join(tmpdir(), "unused-hosts.json"))
  }, new SessionHostCommandGrantStore());
  await provider.request(escalation(undefined));
  assert.ok(choices[0].includes("Run command on host once"));
  assert.ok(!choices[0].includes("Run command on host for session"));
  assert.ok(!choices[0].includes("Run command on host for project"));
});
