import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createMacOSTestTool, isLocalMacOS } from "../macos-test-tool.js";

const approval = "Run macOS integration tests once on host";
const script = "scripts/run-local-macos-tests.mjs";
function localMacOS(t: TestContext) {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const env = { CI: process.env.CI, GITHUB_ACTIONS: process.env.GITHUB_ACTIONS };
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  delete process.env.CI;
  delete process.env.GITHUB_ACTIONS;
  t.after(() => {
    Object.defineProperty(process, "platform", platform);
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
}
async function fixture(t: TestContext) {
  localMacOS(t);
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "pi-macos-host-test-")));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  await mkdir(join(cwd, "scripts"));
  await writeFile(join(cwd, script), "// fixture: never executed\n");
  await writeFile(join(cwd, "package.json"), JSON.stringify({ name: "pi-selective-sandbox", scripts: { "test:macos": `node ${script}` } }));
  const calls: unknown[][] = [];
  const tool = createMacOSTestTool(async (...args) => {
    calls.push(args);
    return { content: [{ type: "text", text: "integration-group-only" }], details: {} };
  });
  const controller = new AbortController();
  const select = async (_title: string, _choices: string[]) => approval;
  const context = { cwd, hasUI: true, ui: { select } };
  const execute = (params = {}) => tool.execute("test-id", params, controller.signal, undefined, context as never);
  return { cwd, tool, calls, context, controller, execute };
}

function runtimeEnvironment(t: TestContext, execPath: string, path: string) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "execPath")!;
  const previousPath = process.env.PATH;
  Object.defineProperty(process, "execPath", { ...descriptor, value: execPath });
  process.env.PATH = path;
  t.after(() => {
    Object.defineProperty(process, "execPath", descriptor);
    if (previousPath === undefined) delete process.env.PATH; else process.env.PATH = previousPath;
  });
}
async function executable(path: string) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, "fixture interpreter: never executed\n", { mode: 0o755 });
  return path;
}

test("the local macOS path excludes Linux and every CI invocation", t => {
  localMacOS(t);
  assert.equal(isLocalMacOS(), true);
  for (const key of ["CI", "GITHUB_ACTIONS"]) {
    process.env[key] = "true";
    assert.equal(isLocalMacOS(), false);
    delete process.env[key];
  }
  Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
  assert.equal(isLocalMacOS(), false);
});

test("host integration tests require a fresh exact-command, canonical-cwd approval on every call", async t => {
  const f = await fixture(t);
  let prompts = 0;
  f.context.ui.select = async (title, choices) => {
    prompts++;
    assert.match(title, /host user's permissions/);
    assert.match(title, /credentials, and network access/);
    assert.match(title, /Bash\/write\/edit enforcement is unchanged/);
    assert.match(title, /not the full npm test suite/);
    assert.ok(title.includes(f.cwd));
    assert.ok(title.includes(process.execPath));
    assert.ok(title.includes(script));
    assert.deepEqual(choices, ["Deny", approval]);
    return approval;
  };
  for (let n = 0; n < 2; n++) {
    const result = await f.execute();
    assert.match(JSON.stringify(result), /integration-group-only/);
    assert.equal(f.calls.length, n + 1);
    const [id, cwd, command, signal] = f.calls[n];
    assert.equal(id, "test-id");
    assert.equal(cwd, f.cwd);
    assert.equal(command, `'${process.execPath.replaceAll("'", "'\\''")}' ${script}`);
    assert.equal(signal, f.controller.signal);
  }
  assert.equal(prompts, 2, "neither prior host grants nor this tool's previous approval can skip UI");
});

test("denial, cancellation, malformed replies and headless execution never run the host", async t => {
  const f = await fixture(t);
  for (const choice of ["Deny", undefined, "Allow", "Run macOS integration tests once on host; echo injected"]) {
    f.context.ui.select = async () => choice as string;
    await assert.rejects(f.execute(), /not approved/);
  }
  f.context.hasUI = false;
  f.context.ui.select = async () => { throw new Error("No headless prompt should be issued"); };
  await assert.rejects(f.execute(), /interactive human approval/);
  assert.equal(f.calls.length, 0);
});

test("arbitrary commands, paths, test names, timeouts and extra arguments are rejected", async t => {
  const f = await fixture(t);
  for (const params of [{ command: "npm test; echo injected" }, { cwd: "/" }, { tests: "*" }, { timeout: 99999 }, { args: ["--test"] }]) {
    await assert.rejects(f.execute(params), /accepts no/);
  }
  assert.equal(f.calls.length, 0);
});

test("abort before or during approval cannot authorize a host test", async t => {
  const f = await fixture(t);
  f.context.ui.select = async () => { f.controller.abort(); return approval; };
  await assert.rejects(f.execute(), /cancelled/);
  await assert.rejects(f.execute(), /cancelled/);
  assert.equal(f.calls.length, 0);
});

test("UI failure denies execution and does not leave subsequent requests locked", async t => {
  const f = await fixture(t);
  f.context.ui.select = async () => { throw new Error("UI unavailable"); };
  await assert.rejects(f.execute(), /UI unavailable/);
  assert.equal(f.calls.length, 0);
  f.context.ui.select = async () => approval;
  await f.execute();
  assert.equal(f.calls.length, 1);
});

test("non-macOS and CI guards are rechecked at execution, even for a previously created tool", async t => {
  const f = await fixture(t);
  process.env.CI = "true";
  await assert.rejects(f.execute(), /outside CI/);
  delete process.env.CI;
  f.context.ui.select = async () => { process.env.GITHUB_ACTIONS = "true"; return approval; };
  await assert.rejects(f.execute(), /outside CI/);
  assert.equal(f.calls.length, 0);
});

test("wrong projects and malformed manifests cannot request or receive host execution", async t => {
  const f = await fixture(t);
  f.context.ui.select = async () => { throw new Error("Should reject before requesting approval"); };
  for (const content of ["null", "{", JSON.stringify({ name: "another-project" }), JSON.stringify({ name: "pi-selective-sandbox", scripts: { "test:macos": "echo injected" } })]) {
    await writeFile(join(f.cwd, "package.json"), content);
    await assert.rejects(f.execute(), /checkout/);
  }
  assert.equal(f.calls.length, 0);
});

test("runner symlinks outside the approved checkout are rejected", async t => {
  const f = await fixture(t);
  const outside = await mkdtemp(join(tmpdir(), "pi-outside-macos-test-"));
  t.after(() => rm(outside, { recursive: true, force: true }));
  await writeFile(join(outside, "runner.mjs"), "// never executed");
  await unlink(join(f.cwd, script));
  await symlink(join(outside, "runner.mjs"), join(f.cwd, script));
  await assert.rejects(f.execute(), /inside the checkout/);
  assert.equal(f.calls.length, 0);
});

test("a runner symlink retargeted while approval is pending requires a new request", async t => {
  const f = await fixture(t);
  await writeFile(join(f.cwd, "scripts", "different.mjs"), "// never executed");
  f.context.ui.select = async () => {
    await unlink(join(f.cwd, script));
    await symlink(join(f.cwd, "scripts", "different.mjs"), join(f.cwd, script));
    return approval;
  };
  await assert.rejects(f.execute(), /changed during approval/);
  assert.equal(f.calls.length, 0);
});

test("a removed Node execPath falls back to a canonical executable from absolute PATH entries", async t => {
  const f = await fixture(t);
  const binary = await executable(join(f.cwd, "version ' current", "node"));
  const bin = join(f.cwd, "stable-bin");
  await mkdir(bin);
  await symlink(binary, join(bin, "node"));
  runtimeEnvironment(t, join(f.cwd, "removed-version", "node"), bin);
  const command = `'${binary.replaceAll("'", "'\\''")}' ${script}`;
  f.context.ui.select = async title => {
    assert.ok(title.includes(command), "approval must show the canonical fallback, not a shell PATH lookup");
    return approval;
  };
  await f.execute();
  assert.equal(f.calls[0][2], command);
});

test("an existing Node execPath takes precedence over a different PATH interpreter", async t => {
  const f = await fixture(t);
  const binary = await executable(join(f.cwd, "current", "node"));
  const other = await executable(join(f.cwd, "other", "node"));
  runtimeEnvironment(t, binary, dirname(other));
  await f.execute();
  assert.equal(f.calls[0][2], `'${binary}' ${script}`);
});

test("missing Node with only empty or relative PATH entries fails before approval", async t => {
  const f = await fixture(t);
  runtimeEnvironment(t, join(f.cwd, "removed", "node"), ":.:relative-bin");
  f.context.ui.select = async () => { throw new Error("No executable means no approval prompt"); };
  await assert.rejects(f.execute(), /Cannot find an executable Node runtime/);
  assert.equal(f.calls.length, 0);
});

test("Node resolution skips non-executable files and directories", async t => {
  const f = await fixture(t);
  const nonExecutable = await executable(join(f.cwd, "not-executable", "node"));
  await chmod(nonExecutable, 0o644);
  const directory = join(f.cwd, "not-file", "node");
  await mkdir(directory, { recursive: true });
  const binary = await executable(join(f.cwd, "valid", "node"));
  runtimeEnvironment(t, nonExecutable, [dirname(directory), dirname(binary)].join(":"));
  await f.execute();
  assert.equal(f.calls[0][2], `'${binary}' ${script}`);
});

test("Node symlink retargeting during approval cannot change the approved executable", async t => {
  const f = await fixture(t);
  const first = await executable(join(f.cwd, "first", "node"));
  const second = await executable(join(f.cwd, "second", "node"));
  const bin = join(f.cwd, "bin"), link = join(bin, "node");
  await mkdir(bin);
  await symlink(first, link);
  runtimeEnvironment(t, join(f.cwd, "removed", "node"), bin);
  f.context.ui.select = async () => {
    await unlink(link);
    await symlink(second, link);
    return approval;
  };
  await assert.rejects(f.execute(), /Node runtime changed during approval/);
  assert.equal(f.calls.length, 0);
});

test("replacing a Node executable in place during approval requires a new request", async t => {
  const f = await fixture(t);
  const binary = await executable(join(f.cwd, "bin", "node"));
  runtimeEnvironment(t, binary, "");
  f.context.ui.select = async () => { await writeFile(binary, "replacement interpreter\n"); return approval; };
  await assert.rejects(f.execute(), /Node runtime changed during approval/);
  assert.equal(f.calls.length, 0);
});

test("losing the original Node during approval cannot silently approve a PATH fallback", async t => {
  const f = await fixture(t);
  const original = await executable(join(f.cwd, "original", "node"));
  const fallback = await executable(join(f.cwd, "fallback", "node"));
  runtimeEnvironment(t, original, dirname(fallback));
  f.context.ui.select = async () => { await unlink(original); return approval; };
  await assert.rejects(f.execute(), /Node runtime changed during approval/);
  assert.equal(f.calls.length, 0);
  f.context.ui.select = async title => { assert.ok(title.includes(fallback)); return approval; };
  await f.execute();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][2], `'${fallback}' ${script}`);
});

test("removing the interpreter during approval never starts host execution", async t => {
  const f = await fixture(t);
  const binary = await executable(join(f.cwd, "bin", "node"));
  runtimeEnvironment(t, binary, "");
  f.context.ui.select = async () => { await unlink(binary); return approval; };
  await assert.rejects(f.execute(), /Cannot find an executable Node runtime/);
  assert.equal(f.calls.length, 0);
});

test("parallel requests cannot overlap approval or host test execution", async t => {
  const f = await fixture(t);
  let release!: () => void;
  let entered!: () => void;
  const waiting = new Promise<void>(resolve => { entered = resolve; });
  const blocked = new Promise<void>(resolve => { release = resolve; });
  f.context.ui.select = async () => { entered(); await blocked; return approval; };
  const first = f.execute();
  await waiting;
  await assert.rejects(f.execute(), /already pending or running/);
  release();
  await first;
  assert.equal(f.calls.length, 1);
});
