import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { parseConfig } from "../config.js";
import { resolveWritePolicy } from "../filesystem-policy.js";

const exec = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
async function run(command: string, cwd: string) {
  try { return { ...await exec("/bin/bash", ["-c", command], { cwd, timeout: 15000 }), exitCode: 0 }; }
  catch (error) {
    const failed = error as Error & { code: number; stdout: string; stderr: string };
    if (typeof failed.code !== "number") throw error;
    return { exitCode: failed.code, stdout: failed.stdout, stderr: failed.stderr };
  }
}

for (const mode of ["default", "opt-out", "canonical-env-deny"] as const) {
  test(`native macOS cache profiles: ${mode}`, { skip: process.platform !== "darwin" }, async t => {
    const root = await realpath(await mkdtemp(join(process.cwd(), ".cache-policy-")));
    t.after(() => rm(root, { recursive: true, force: true }));
    const cwd = join(root, "project"), home = join(root, "home");
    await Promise.all([mkdir(cwd), mkdir(home)]);
    const cacheProfiles = ["npm-cache", "uv-cache", "gh-cache", "go-cache"];
    const env: NodeJS.ProcessEnv = {};
    let targets = [join(home, ".npm", "_cacache"), join(home, ".cache", "uv"), join(home, ".cache", "gh"),
      join(home, "Library", "Caches", "go-build"), join(home, "go", "pkg", "mod"), join(home, "go", "pkg", "sumdb")];
    const cargo = join(home, ".cargo");
    if (mode === "canonical-env-deny") {
      const storage = join(root, "storage"), alias = join(root, "alias");
      await mkdir(storage); await symlink(storage, alias);
      Object.assign(env, { npm_config_cache: join(alias, "npm"), UV_CACHE_DIR: join(alias, "uv"),
        XDG_CACHE_HOME: join(alias, "xdg"), GOCACHE: join(alias, "go-build"), GOPATH: join(alias, "go") });
      targets = [join(alias, "npm", "_cacache"), env.UV_CACHE_DIR!, join(alias, "xdg", "gh"), env.GOCACHE!,
        join(alias, "go", "pkg", "mod"), join(alias, "go", "pkg", "sumdb")];
      // Existing Cargo deny must survive an explicit cache-adjacent allow.
      await mkdir(cargo, { recursive: true });
    }
    // Pre-create only fixture dirs, never any real user cache.
    for (const target of targets) await mkdir(target, { recursive: true });
    const policy = await resolveWritePolicy({ cwd, home, env, config: parseConfig({ filesystem: {
      disabledDefaultProfiles: ["tmp", ...(mode === "opt-out" ? cacheProfiles : [])],
      extraWritableRoots: mode === "canonical-env-deny" ? [cargo] : []
    } }) });
    const runtime = await AnthropicSandboxRuntime.initialize({ cwd, writePolicy: policy, allowedDomains: [], allowLocalBinding: false });
    t.after(() => runtime.dispose());
    const denied = [join(home, "go", "bin", "tool"), join(home, ".config", "gh", "hosts.yml"),
      join(home, ".local", "share", "uv", "tools", "tool"), join(cargo, "credentials.toml")];
    const source = `
      const fs = require('node:fs'); const path = require('node:path');
      const targets = ${JSON.stringify(targets.map(target => join(target, "tmp", "uuid")))};
      const denied = ${JSON.stringify(denied)};
      const results = [...targets, ...denied].map(file => {
        try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, 'cache'); return true; }
        catch (error) { if (!['EPERM', 'EACCES', 'EROFS'].includes(error.code)) throw error; return false; }
      }); console.log(JSON.stringify(results));
    `;
    const command = `${quote(process.execPath)} -e ${quote(source)}`;
    const executor = new SelectiveSandboxExecutor({ runtime, cwd, policy: new CapabilityPolicy([]),
      runner: { runSandbox: wrapped => run(wrapped, cwd), runHost: async () => { throw new Error("Cache test must stay sandboxed"); } },
      approvals: { request: async () => { throw new Error("Cache fixture must not request approval"); } }
    });
    const result = await executor.execute(command, `cache-${mode}`);
    assert.equal(result.disposition, "sandbox");
    assert.equal(result.exitCode, 0, JSON.stringify(result));
    assert.deepEqual(JSON.parse(result.stdout), [...targets.map(() => mode !== "opt-out"), ...denied.map(() => false)]);
  });
}

// Fresh native processes, no watcher/pgrep doubles or polling fallbacks.
const probes = {
  pgrep: `
    const { spawn, spawnSync } = require('node:child_process');
    const child = spawn('/bin/sleep', ['30']);
    child.on('error', error => { console.error(error); process.exitCode = 1; });
    child.on('spawn', () => {
      try {
        const result = spawnSync('/usr/bin/pgrep', ['-P', String(process.pid), '-f', 'sleep'], { encoding: 'utf8' });
        const noMatch = spawnSync('/usr/bin/pgrep', ['-P', String(child.pid)], { encoding: 'utf8' });
        const matched = result.stdout?.trim().split(/\\s+/).includes(String(child.pid));
        console.log(JSON.stringify({ status: result.status, matched, noMatchStatus: noMatch.status }));
        if (result.status !== 0 || !matched || noMatch.status !== 1) process.exitCode = 1;
      } finally { child.kill(); }
    });
  `,
  file: watchProbe(false),
  directory: watchProbe(true)
};
function watchProbe(directory: boolean): string {
  return `
    const { mkdtempSync, realpathSync, writeFileSync, watch, rmSync } = require('node:fs');
    const { join } = require('node:path');
    const root = realpathSync(mkdtempSync(join(process.cwd(), '.pi-native-watch-')));
    const target = join(root, 'notification.txt');
    writeFileSync(target, 'before');
    const observe = directory => new Promise(resolve => {
      let handle, writer, timer, finished = false, writes = 0;
      const finish = (outcome, error) => {
        if (finished) return;
        finished = true;
        clearInterval(writer); clearTimeout(timer); handle?.close();
        console.log(JSON.stringify({ directory, outcome, code: error?.code }));
        resolve(outcome === 'notification');
      };
      try {
        handle = watch(directory ? root : target, (event, filename) => {
          if (writes > 0 && String(filename) === 'notification.txt') finish('notification');
        });
        handle.on('error', error => finish('async-error', error));
        writer = setInterval(() => { try { writeFileSync(target, String(directory) + '-after-' + ++writes); } catch (error) { finish('write-error', error); } }, 500);
        timer = setTimeout(() => finish('timeout'), 5000);
      } catch (error) { finish('sync-error', error); }
    });
    (async () => {
      try {
        // Compare a file and its directory in the same process/temporary root;
        // close the file handle before starting the directory watcher.
        for (const directory of ${directory ? "[false, true]" : "[false]"}) {
          if (!await observe(directory)) { process.exitCode = 1; break; }
        }
      } finally { rmSync(root, { recursive: true, force: true }); }
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
}

for (const [name, probe] of Object.entries(probes)) {
  test(`native macOS ${name} succeeds without approval after shared SDK startup without Mach allowances`, { skip: process.platform !== "darwin" }, async t => {
    const cwd = process.cwd();
    const command = `${quote(process.execPath)} -e ${quote(probe)}`;
    const host = await run(command, cwd);
    assert.equal(host.exitCode, 0, JSON.stringify(host));
    // A foreground sibling can initialize the shared SDK before this runtime.
    // Native success must depend on our invocation policy, not its startup list.
    t.after(() => AnthropicSandboxRuntime.reset());
    await SandboxManager.initialize({ filesystem: { allowRead: [], denyRead: [], allowWrite: [cwd], denyWrite: [] },
      network: { allowedDomains: [], deniedDomains: [], allowLocalBinding: false, allowMachLookup: [] } }, undefined, true);
    const runtime = await AnthropicSandboxRuntime.initialize({ cwd, writePolicy: { allow: [cwd], deny: [] }, allowedDomains: [], allowLocalBinding: false });
    t.after(() => runtime.dispose());
    const executor = new SelectiveSandboxExecutor({ runtime, cwd, policy: new CapabilityPolicy([]),
      runner: { runSandbox: wrapped => run(wrapped, cwd), runHost: async () => { throw new Error("Native operations must stay sandboxed"); } },
      approvals: { request: async () => { throw new Error("Baseline native operations must not request approval"); } }
    });
    const result = await executor.execute(command, `native-${name}`);
    t.diagnostic(`${name}: ${result.stdout.trim()}`);
    assert.equal(result.disposition, "sandbox");
    assert.equal(result.exitCode, 0, JSON.stringify(result));
  });
}

test("default macOS Mach allowances retain outside-write and explicit-deny enforcement", { skip: process.platform !== "darwin" }, async t => {
  const root = await realpath(await mkdtemp(join(process.cwd(), ".ipc-write-boundary-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const allowed = join(root, "allowed"), outside = join(root, "outside"), denied = join(allowed, "denied");
  await mkdir(outside);
  await mkdir(denied, { recursive: true });
  for (const directory of [outside, denied]) {
    for (const name of ["existing", "unlink", "rename-from"]) await writeFile(join(directory, name), "sentinel");
    await chmod(join(directory, "existing"), 0o600);
  }
  await symlink(join(outside, "existing"), join(allowed, "outside-link"));
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd: allowed, writePolicy: { allow: [allowed], deny: [denied] }, allowedDomains: [], allowLocalBinding: false });
  t.after(() => runtime.dispose());
  const source = `
    const fs = require('node:fs');
    const { join } = require('node:path');
    const [allowed, outside, denied] = process.argv.slice(1);
    const results = [];
    const attempt = (operation, fn) => { try { fn(); results.push({ operation, denied: false }); } catch (error) { results.push({ operation, denied: true, code: error.code }); } };
    for (const [label, directory] of [['outside', outside], ['deny', denied]]) {
      fs.writeFileSync(join(allowed, label + '-source'), 'allowed-source');
      const existing = join(directory, 'existing');
      attempt(label + ':overwrite', () => fs.writeFileSync(existing, 'changed'));
      attempt(label + ':append', () => fs.appendFileSync(existing, 'changed'));
      attempt(label + ':create', () => fs.writeFileSync(join(directory, 'new-file'), 'changed'));
      attempt(label + ':mkdir', () => fs.mkdirSync(join(directory, 'new-directory')));
      attempt(label + ':unlink', () => fs.unlinkSync(join(directory, 'unlink')));
      attempt(label + ':rename-out', () => fs.renameSync(join(directory, 'rename-from'), join(allowed, label + '-moved')));
      attempt(label + ':rename-in', () => fs.renameSync(join(allowed, label + '-source'), join(directory, 'renamed-in')));
      attempt(label + ':chmod', () => fs.chmodSync(existing, 0o777));
      attempt(label + ':symlink', () => fs.symlinkSync(join(allowed, 'allowed-write'), join(directory, 'new-link')));
    }
    attempt('outside:symlink-follow', () => fs.writeFileSync(join(allowed, 'outside-link'), 'changed'));
    fs.writeFileSync(join(allowed, 'allowed-write'), 'works');
    console.log(JSON.stringify(results));
  `;
  const command = `${quote(process.execPath)} -e ${quote(source)} ${[allowed, outside, denied].map(quote).join(" ")}`;
  const id = "default-mach-write-boundary";
  const wrapped = await runtime.wrap(command, { commandId: id, commandText: command, cwd: allowed });
  const result = await run(wrapped, allowed);
  assert.equal(result.exitCode, 0, JSON.stringify(result));
  const attempts = JSON.parse(result.stdout) as { operation: string; denied: boolean; code?: string }[];
  assert.equal(attempts.length, 19);
  assert.ok(attempts.every(probe => probe.denied && ["EPERM", "EACCES", "EROFS"].includes(probe.code ?? "")), JSON.stringify(attempts));
  assert.equal(await readFile(join(allowed, "allowed-write"), "utf8"), "works");
  for (const directory of [outside, denied]) {
    assert.deepEqual((await readdir(directory)).sort(), ["existing", "rename-from", "unlink"]);
    for (const name of ["existing", "unlink", "rename-from"]) assert.equal(await readFile(join(directory, name), "utf8"), "sentinel");
    assert.equal((await stat(join(directory, "existing"))).mode & 0o777, 0o600);
  }
  const violations = await runtime.getViolationsForCommand(id);
  assert.ok(violations.some(violation => violation.kind === "filesystem.write"));
  t.diagnostic("All 19 outside-write/deny-carve-out operations denied; allowed write succeeded; host snapshots unchanged.");
});
