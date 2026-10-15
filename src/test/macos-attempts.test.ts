import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
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
  const command = `/usr/bin/python3 -c ${quote(`import os\nfor p in ${JSON.stringify(resources)}:\n    fd = os.open(p, os.O_RDWR)\n    os.close(fd)\nprint('opened-all')`)}`;
  for (const [index, id] of [longId, `subagent:reviewer:${longId}`].entries()) {
    const runtime = await AnthropicSandboxRuntime.initialize({ cwd, commandNamespace: `12345678-1234-1234-1234-123456789ab${index}`, writePolicy: { allow: [cwd], deny: [] }, allowedDomains: [] });
    let attempts = 0, rounds = 0;
    const markers: string[] = [];
    const executor = new SelectiveSandboxExecutor({ runtime, cwd, sandboxUnavailableMessage: sandboxInitializationError, policy: new CapabilityPolicy([], "ask"), onStatus: marker => markers.push(marker),
      runner: { runSandbox: async wrapped => { attempts++; return runSandbox(wrapped); }, runHost: async () => { throw new Error("Unexpected host replay"); } },
      approvals: createApprovalProvider({ hasUI: true, ui: { select: async (_message, choices) => {
        const expected = resources[rounds];
        if (choices.includes(expected)) return expected;
        if (choices.includes("Once")) return "Once";
        assert.ok(choices.includes("Allow and retry"));
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
