import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const project = fileURLToPath(new URL("../../", import.meta.url));
const names = ["sandbox-manager.js", "sandbox-manager.d.ts", "macos-sandbox-utils.js", "macos-sandbox-utils.d.ts", "sandbox-violation-store.js"];

async function installFixture(t: TestContext, nested = false) {
  const base = await mkdtemp(join(tmpdir(), "pi-sdk-patch-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  if (nested) await run("git", ["init", "-q", base]);
  const root = nested ? join(base, "package") : base;
  const runtime = join(root, "node_modules", "@anthropic-ai", "sandbox-runtime");
  const dist = join(runtime, "dist", "sandbox");
  const script = join(root, "scripts", "apply-sandbox-runtime-patch.mjs");
  const patch = join(root, "patches", "sandbox-runtime-0.0.76.patch");
  for (const directory of [dist, dirname(script), dirname(patch)]) await mkdir(directory, { recursive: true });
  await copyFile(join(project, "scripts", "apply-sandbox-runtime-patch.mjs"), script);
  await copyFile(join(project, "patches", "sandbox-runtime-0.0.76.patch"), patch);
  for (const name of names) await copyFile(join(project, "node_modules", "@anthropic-ai", "sandbox-runtime", "dist", "sandbox", name), join(dist, name));
  await writeFile(join(runtime, "package.json"), JSON.stringify({ version: "0.0.76" }));
  return { root, runtime, dist, script, patch, install: () => run(process.execPath, [script], { cwd: root }) };
}

test("SDK patch installs on pristine files and reinstallation is idempotent", async t => {
  const fixture = await installFixture(t);
  await run("git", ["apply", "--reverse", "--", fixture.patch], { cwd: fixture.root });
  const first = await fixture.install();
  assert.match(first.stdout, /Applied sandbox-runtime/);
  const installed = await Promise.all(names.map(name => readFile(join(fixture.dist, name), "utf8")));
  assert.match((await fixture.install()).stdout, /already applied/);
  assert.deepEqual(await Promise.all(names.map(name => readFile(join(fixture.dist, name), "utf8"))), installed);
});

test("SDK patch applies to a package nested inside another Git repository", async t => {
  const fixture = await installFixture(t, true);
  await run("git", ["apply", "--reverse", "--", fixture.patch], {
    cwd: fixture.root, env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(fixture.root) }
  });
  assert.doesNotMatch(await readFile(join(fixture.dist, "macos-sandbox-utils.js"), "utf8"), /new StringDecoder/);
  assert.match((await fixture.install()).stdout, /Applied sandbox-runtime/);
});

test("SDK patch refuses version drift before modifying dependencies", async t => {
  const fixture = await installFixture(t);
  await writeFile(join(fixture.runtime, "package.json"), JSON.stringify({ version: "0.0.78" }));
  await assert.rejects(fixture.install(), /Expected sandbox-runtime 0\.0\.76, found 0\.0\.78/);
});

test("SDK patch refuses locally modified or partially patched files", async t => {
  const fixture = await installFixture(t);
  const file = join(fixture.dist, "macos-sandbox-utils.js");
  const modified = await readFile(file, "utf8") + "\n// local modification\n";
  await writeFile(file, modified);
  await assert.rejects(fixture.install(), /refusing to apply a partial patch/);
  assert.equal(await readFile(file, "utf8"), modified);
});
