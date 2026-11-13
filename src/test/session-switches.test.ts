import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { link, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { startApprovalBridge } from "../subagent-approval.js";
import { DEFAULT_SANDBOX_SWITCHES, publishSandboxSwitches, readSandboxSwitches } from "../session-switches.js";

const exec = promisify(execFile);
async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), "pi-switch-state-"));
  const bridge = await startApprovalBridge({ root, parentSessionId: "switch-owner", select: async () => undefined });
  t.after(async () => { await bridge.close(); await rm(root, { recursive: true, force: true }); });
  await publishSandboxSwitches(bridge.binding, DEFAULT_SANDBOX_SWITCHES);
  return { root, bridge, path: join(bridge.binding.directory, "switches.json") };
}

test("switch records reflect atomic updates across process boundaries and expire on close", async t => {
  const { bridge, path } = await fixture(t);
  const module = fileURLToPath(new URL("../session-switches.js", import.meta.url));
  const readFromProcess = async () => JSON.parse((await exec(process.execPath, ["--input-type=module", "-e",
    `import { readSandboxSwitches } from ${JSON.stringify(module)}; process.stdout.write(JSON.stringify(await readSandboxSwitches(JSON.parse(process.argv[1]))));`,
    JSON.stringify(bridge.binding)])).stdout);
  assert.deepEqual(await readFromProcess(), DEFAULT_SANDBOX_SWITCHES);
  const off = { enabled: false, network: false, socket: false };
  await publishSandboxSwitches(bridge.binding, off);
  assert.deepEqual(await readFromProcess(), off);
  const on = { enabled: true, network: false, socket: true };
  await publishSandboxSwitches(bridge.binding, on);
  assert.deepEqual(await readFromProcess(), on);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  await bridge.close();
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await assert.rejects(publishSandboxSwitches(bridge.binding, off));
});

test("missing, malformed, wrong-identity and non-boolean records never reuse an old off switch", async t => {
  const { bridge, path } = await fixture(t);
  await publishSandboxSwitches(bridge.binding, { enabled: false, network: false, socket: false });
  const good = JSON.parse(await readFile(path, "utf8"));
  for (const value of [null, [], { ...good, version: 2 }, { ...good, parentSessionId: "other" }, { ...good, nonce: "0".repeat(64) },
    { ...good, enabled: "false" }, { ...good, network: undefined }, { ...good, socket: 0 }]) {
    await writeFile(path, JSON.stringify(value));
    await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  }
  await writeFile(path, "{broken");
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await unlink(path);
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await publishSandboxSwitches(bridge.binding, DEFAULT_SANDBOX_SWITCHES);
  assert.deepEqual(await readSandboxSwitches(bridge.binding), DEFAULT_SANDBOX_SWITCHES);
});

test("switch transport rejects symlinks, hardlinks, oversized records and replaced owner identities", async t => {
  const { root, bridge, path } = await fixture(t);
  const copy = join(root, "copy.json");
  await rename(path, copy);
  await symlink(copy, path);
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await unlink(path);
  await link(copy, path);
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await unlink(path);
  await writeFile(path, " ".repeat(256 * 1024 + 1));
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await publishSandboxSwitches(bridge.binding, DEFAULT_SANDBOX_SWITCHES);
  await writeFile(join(bridge.binding.directory, "alive.json"), JSON.stringify({ ...bridge.binding, nonce: "0".repeat(64) }));
  await assert.rejects(readSandboxSwitches(bridge.binding), /execution is blocked/);
  await assert.rejects(publishSandboxSwitches(bridge.binding, DEFAULT_SANDBOX_SWITCHES), /owner/);
});

test("separate owning parents cannot inherit each other's switches", async t => {
  const first = await fixture(t), second = await fixture(t);
  await publishSandboxSwitches(first.bridge.binding, { enabled: false, network: false, socket: false });
  assert.deepEqual(await readSandboxSwitches(second.bridge.binding), DEFAULT_SANDBOX_SWITCHES);
  await assert.rejects(readSandboxSwitches({ ...second.bridge.binding, nonce: first.bridge.binding.nonce }), /execution is blocked/);
});

test("failed publication cannot silently replace a valid switch snapshot", async t => {
  const { bridge, path } = await fixture(t);
  const saved = path + ".saved";
  await rename(path, saved);
  await mkdir(path);
  await assert.rejects(publishSandboxSwitches(bridge.binding, { enabled: false, network: false, socket: false }));
  await rm(path, { recursive: true });
  await rename(saved, path);
  assert.deepEqual(await readSandboxSwitches(bridge.binding), DEFAULT_SANDBOX_SWITCHES);
});
