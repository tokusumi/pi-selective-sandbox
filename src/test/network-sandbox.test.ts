import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";
import { ProjectGrantStore } from "../project-grants.js";
import { collapseWriteScopes, validateWideningSelection } from "../resource-selection.js";
import type { ApprovalRequest, Capability, CommandResult } from "../types.js";

const exec = promisify(execFile);
const endpoint = "registry.npmjs.org:443";
const cap: Capability = { kind: "network", resource: endpoint };
const request: ApprovalRequest = {
  kind: "escalation", toolCallId: "network", toolName: "bash", inputDigest: "digest", capabilities: [cap],
  command: "npm view package", replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true
};

test("network approval scopes remain exact, sandbox-only, and project-persistent", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-network-grants-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const path = join(base, "grants.json");
  for (const [duration, decision] of [
    ["Once", "sandbox-allow-once"],
    ["This session", "sandbox-allow-session"],
    ["This project", "sandbox-allow-project"],
    ["Once", "deny"]
  ]) {
    const session = new SessionGrantStore();
    const project = new ProjectGrantStore(path);
    await rm(path, { force: true });
    let prompts = 0;
    const provider = createApprovalProvider({ hasUI: true, mode: "tui", sessionManager: { getSessionId: () => "A" }, ui: {
      custom: async () => { throw new Error("Network endpoints must not use filesystem ancestor selection"); },
      select: async (message, choices) => {
        assert.match(message, /network: registry\.npmjs\.org:443/);
        assert.match(message, /Approving a resource never approves leaving the sandbox/);
        if (++prompts === 1) {
          assert.deepEqual(choices, ["Once", "This session", "This project"]);
          return duration;
        }
        assert.deepEqual(choices, ["Allow and retry", "Deny", "Run outside sandbox…"]);
        return decision === "deny" ? "Deny" : "Allow and retry";
      }
    } }, session, { projectId: "/project", grants: project });
    assert.deepEqual(await provider.request(request), decision === "deny" ? "deny" : { decision, capabilities: [cap] });
    assert.equal(prompts, 2);
    assert.equal(session.covers("A", [cap]), decision === "sandbox-allow-session");
    assert.equal(await new ProjectGrantStore(path).covers("/project", [cap]), decision === "sandbox-allow-project");
    assert.equal(session.covers("B", [cap]), false);
    for (const resource of ["registry.npmjs.org:80", "other.npmjs.org:443", "*.npmjs.org:443"]) {
      const other: Capability = { kind: "network", resource };
      assert.equal(session.covers("A", [other]), false);
      assert.equal(await project.covers("/project", [other]), false);
    }
    assert.equal(await project.covers("/another-project", [cap]), false);
  }
});

test("network selection cannot forge neighboring endpoints or replace them with filesystem grants", async () => {
  assert.equal(await validateWideningSelection([cap], [cap]), true);
  for (const resource of ["registry.npmjs.org:80", "other.npmjs.org:443", "*.npmjs.org:443", "Registry.npmjs.org:443", "/"]) {
    assert.equal(await validateWideningSelection([cap], [{ kind: "network", resource }]), false, resource);
  }
  assert.equal(await validateWideningSelection([{ kind: "network", resource: "unknown" }], [cap]), false);
  const leaf: Capability = { kind: "filesystem.write", resource: "/outside/file" };
  const parent: Capability = { kind: "filesystem.write", resource: "/outside" };
  assert.equal(await validateWideningSelection([leaf, cap], [parent, cap]), true);
  assert.equal(await validateWideningSelection([leaf, cap], [parent]), false);
  assert.equal(await validateWideningSelection([leaf, cap], [{ kind: "filesystem.write", resource: "/" }]), false);
  assert.deepEqual(collapseWriteScopes([cap, leaf, parent, cap]), [cap, parent]);
});

test("macOS real Seatbelt retains filesystem isolation during endpoint widening", { skip: process.platform !== "darwin" }, async t => {
  const base = await realpath(await mkdtemp(join(tmpdir(), "pi-network-sandbox-")));
  const cwd = join(base, "workspace"), blocked = join(base, "blocked");
  await Promise.all([mkdir(cwd), mkdir(blocked)]);
  const server = http.createServer((_req, res) => res.end("sandbox-network-ok"));
  t.after(async () => {
    await AnthropicSandboxRuntime.reset();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(base, { recursive: true, force: true });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as { port: number }).port;
  const resource = `127.0.0.1:${port}`;
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd, writePolicy: { allow: [cwd], deny: [blocked] }, allowedDomains: [] });
  const runSandbox = async (wrapped: string): Promise<CommandResult> => {
    try {
      const output = await exec("/bin/bash", ["-c", wrapped], { cwd, timeout: 10000 });
      return { ...output, exitCode: 0 };
    } catch (error) {
      const failed = error as Error & { code: number; stdout: string; stderr: string };
      if (typeof failed.code !== "number") throw error;
      return { exitCode: failed.code, stdout: failed.stdout, stderr: failed.stderr };
    }
  };
  let prompts = 0;
  const markers: string[] = [];
  const runner = { runSandbox, runHost: async () => { throw new Error("Unexpected host execution"); } };
  const command = `/usr/bin/curl --noproxy '' -fsS --max-time 3 http://127.0.0.1:${port}/`;
  const executor = new SelectiveSandboxExecutor({ runtime, cwd, runner, onStatus: marker => markers.push(marker), policy: new CapabilityPolicy([]), approvals: {
    request: async request => {
      prompts++;
      assert.deepEqual(request.capabilities, [{ kind: "network", resource }], JSON.stringify(request));
      return "sandbox-allow-once";
    }
  } });
  const output = await executor.execute(command, "real-network");
  assert.equal(output.disposition, "sandbox");
  assert.equal(output.exitCode, 0, output.stderr);
  assert.equal(output.stdout, "sandbox-network-ok");
  assert.equal(prompts, 1);
  assert.deepEqual(markers, ["<sandbox: approval-required network>", "<sandbox: approved widen retry>", "<sandbox: retry exit=0>"]);

  // Once grants disappear on the next invocation, even for the same endpoint.
  const unapproved = new SelectiveSandboxExecutor({ runtime, cwd, runner, policy: new CapabilityPolicy([]) });
  const denied = await unapproved.execute(command, "real-once-expired");
  assert.equal(denied.disposition, "denied");
  assert.notEqual(denied.exitCode, 0);

  // A stored endpoint is applied on the first attempt, but filesystem denies
  // and direct (non-proxy) networking remain kernel-enforced.
  const stored = new SelectiveSandboxExecutor({ runtime, cwd, runner, policy: new CapabilityPolicy([]), getSandboxCapabilities: async () => [{ kind: "network", resource }] });
  assert.equal((await stored.execute(command, "real-stored")).stdout, "sandbox-network-ok");
  assert.equal((await stored.execute(`/usr/bin/curl --noproxy '' --proxy "$ALL_PROXY" -fsS --max-time 3 http://127.0.0.1:${port}/`, "real-socks-stored")).stdout, "sandbox-network-ok");
  const file = join(blocked, "file");
  await writeFile(file, "unchanged");
  const deniedWrite = await stored.execute(`${command} && printf changed > '${file}'`, "real-file-denied");
  assert.notEqual(deniedWrite.exitCode, 0);
  assert.equal(await readFile(file, "utf8"), "unchanged");
  const direct = await stored.execute(`/usr/bin/curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:${port}/`, "real-direct-denied");
  assert.notEqual(direct.exitCode, 0);
});
