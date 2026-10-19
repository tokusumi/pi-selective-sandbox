import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { join } from "node:path";
import { promisify } from "node:util";
import { AnthropicSandboxRuntime, sandboxInitializationError } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";

const exec = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
const longId = `call_${"a".repeat(24)}|fc_${"b".repeat(64)}`;

test("real macOS sequential file denials reach each approval UI for ordinary and child invocations", { skip: process.platform !== "darwin" }, async t => {
  // Do not use tmpdir(): SDK default allows /tmp/claude, including descendants.
  const base = await realpath(await mkdtemp(join(process.cwd(), ".macos-attempt-")));
  const cwd = join(base, "workspace");
  await mkdir(cwd);
  const resources = ["first.txt", "second.txt", "third.txt"].map(name => join(base, name));
  await Promise.all(resources.map(resource => writeFile(resource, "fixture")));
  t.after(async () => { await AnthropicSandboxRuntime.reset(); await rm(base, { recursive: true, force: true }); });
  const runSandbox = async (command: string) => {
    try { return { ...await exec("/bin/bash", ["-c", command], { cwd, timeout: 15000 }), exitCode: 0 }; }
    catch (error) {
      const failed = error as Error & { code: number; stdout: string; stderr: string };
      if (typeof failed.code !== "number") throw error;
      return { exitCode: failed.code, stdout: failed.stdout, stderr: failed.stderr };
    }
  };
  // /usr/bin/python3 is an Xcode shim on hosted macOS runners. Its first
  // invocation can write unrelated NSIRD_xcodebuild temporary files. Use only
  // shell builtins so each attempt's first denied operation is a fixture file.
  const command = `for target in ${resources.map(quote).join(" ")}; do : >> "$target" || exit $?; done; printf 'opened-all\\n'`;
  for (const [index, id] of [longId, `subagent:reviewer:${longId}`].entries()) {
    const runtime = await AnthropicSandboxRuntime.initialize({ cwd, commandNamespace: `12345678-1234-1234-1234-123456789ab${index}`, writePolicy: { allow: [cwd], deny: [] }, allowedDomains: [] });
    let attempts = 0, rounds = 0;
    const markers: string[] = [];
    const executor = new SelectiveSandboxExecutor({ runtime, cwd, sandboxUnavailableMessage: sandboxInitializationError, policy: new CapabilityPolicy([], "ask"), onStatus: marker => markers.push(marker),
      runner: { runSandbox: async wrapped => { attempts++; return runSandbox(wrapped); }, runHost: async () => { throw new Error("Unexpected host replay"); } },
      approvals: createApprovalProvider({ hasUI: true, ui: { select: async (message, choices) => {
        const expected = resources[rounds];
        if (choices.includes(expected)) return expected;
        if (choices.includes("Once")) return "Once";
        assert.ok(choices.includes("Allow and retry"), `Unexpected approval after ${rounds} approvals: ${JSON.stringify({ expected, message, choices })}`);
        rounds++;
        return "Allow and retry";
      } } }, new SessionGrantStore())
    });
    const result = await executor.execute(command, id);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout.trim(), "opened-all");
    assert.equal(result.disposition, "sandbox");
    assert.equal(attempts, 4);
    assert.equal(rounds, 3);
    assert.equal(markers.filter(marker => marker.includes("approval-required")).length, 3);
    await runtime.dispose();
  }
});

test("macOS attempts include baseline Mach services even when the shared SDK started without them", { skip: process.platform !== "darwin" }, async t => {
  const cwd = process.cwd();
  await SandboxManager.initialize({ filesystem: { allowRead: [], denyRead: [], allowWrite: [cwd], denyWrite: [] },
    network: { allowedDomains: [], deniedDomains: [], allowMachLookup: [] } }, undefined, false);
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd, writePolicy: { allow: [cwd], deny: [] }, allowedDomains: [] }, false);
  t.after(() => runtime.dispose());
  const id = "platform-trust-after-shared-startup";
  const wrapped = await runtime.wrap("true", { commandId: id, commandText: "true" });
  t.after(() => runtime.forgetCommand(id));
  for (const service of ["com.apple.trustd.agent", "com.apple.sysmond", "com.apple.FSEvents"]) {
    assert.equal(wrapped.split(`(global-name "${service}")`).length - 1, 1);
  }
  assert.doesNotMatch(wrapped, /\(allow mach-lookup\)/);
  assert.doesNotMatch(wrapped, /\(allow network\*\)/);
  assert.doesNotMatch(wrapped, /\(allow system-socket \(socket-domain AF_UNIX\)\)/);
});

test("macOS platform certificate verification succeeds offline without approvals or host replay", { skip: process.platform !== "darwin" }, async t => {
  const base = await realpath(await mkdtemp(join(tmpdir(), "pi-platform-trust-")));
  t.after(async () => { await AnthropicSandboxRuntime.reset(); await rm(base, { recursive: true, force: true }); });
  // Use a currently valid public root as an explicit anchor, never import it
  // into a keychain. -l permits a CA as the leaf; -L/-R offline forbid fetching.
  const bundle = await readFile("/etc/ssl/cert.pem", "utf8");
  const root = bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)?.find(pem => {
    const certificate = new X509Certificate(pem);
    return certificate.ca && certificate.checkIssued(certificate) && certificate.verify(certificate.publicKey)
      && Date.parse(certificate.validFrom) < Date.now() && Date.now() < Date.parse(certificate.validTo);
  });
  assert.ok(root, "macOS public CA bundle must contain a valid root");
  const path = join(base, "public-root.pem");
  await writeFile(path, root);
  const args = ["verify-cert", "-c", path, "-r", path, "-p", "basic", "-l", "-L", "-R", "offline"];
  await exec("/usr/bin/security", args, { timeout: 10000 }); // Validate the fixture on the host first.
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: base, writePolicy: { allow: [base], deny: [] }, allowedDomains: [], allowLocalBinding: false });
  const executor = new SelectiveSandboxExecutor({ runtime, cwd: base, policy: new CapabilityPolicy([], "ask"),
    approvals: { request: async () => { throw new Error("Platform certificate verification must not request approval"); } },
    runner: {
      runSandbox: async command => {
        try { return { ...await exec("/bin/bash", ["-c", command], { cwd: base, timeout: 10000 }), exitCode: 0 }; }
        catch (error) {
          const failed = error as Error & { code: number; stdout: string; stderr: string };
          if (typeof failed.code !== "number") throw error;
          return { exitCode: failed.code, stdout: failed.stdout, stderr: failed.stderr };
        }
      },
      runHost: async () => { throw new Error("Platform certificate verification must remain sandboxed"); }
    }
  });
  const result = await executor.execute(["/usr/bin/security", ...args].map(quote).join(" "), "platform-trust-offline");
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.disposition, "sandbox");
});
