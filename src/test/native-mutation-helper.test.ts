import assert from "node:assert/strict";
import { copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test, { type TestContext } from "node:test";

async function fixture(t: TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "pi-native-helper-test-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  await Promise.all(["scripts", "runtime"].map(name => mkdir(join(root, name))));
  const script = join(root, "scripts/native-mutation-helper.mjs");
  await copyFile(new URL("../../scripts/native-mutation-helper.mjs", import.meta.url), script);
  const modulePath = join(root, "runtime/native-mutation-io.mjs");
  await copyFile(new URL("../native-mutation-io.js", import.meta.url), modulePath);
  const { NativeMutationIO } = await import(pathToFileURL(modulePath).href);
  return { root, script, NativeMutationIO };
}

test("package helper works without a compiler, PATH tools, inherited Node loaders or generated binaries", async t => {
  const { root, NativeMutationIO } = await fixture(t);
  const path = join(root, "fixture.txt");
  await writeFile(path, "original");
  const cwd = process.cwd();
  const keys = ["PATH", "CC", "NODE_OPTIONS", "NODE_PATH"] as const;
  const original = keys.map(key => process.env[key]);
  let io;
  try {
    process.env.PATH = "";
    process.env.CC = "/nonexistent/compiler";
    process.env.NODE_OPTIONS = "--require=/nonexistent/preload";
    process.env.NODE_PATH = "/nonexistent/modules";
    io = await NativeMutationIO.prepare("edit", path);
    assert.equal((await io.readFile()).toString(), "original");
    await io.writeFile("updated");
    assert.equal((await io.readFile()).toString(), "updated");
    assert.equal((await io.readFile()).toString(), "updated");
  } finally {
    for (const [i, key] of keys.entries()) {
      if (original[i] === undefined) delete process.env[key];
      else process.env[key] = original[i];
    }
    await io?.close();
  }
  assert.equal(process.cwd(), cwd);
  assert.equal(await readFile(path, "utf8"), "updated");
  await assert.rejects(lstat(join(root, ".native")), { code: "ENOENT" });
});

test("missing package helper gives an actionable refusal without touching existing or new targets", async t => {
  const { root, script, NativeMutationIO } = await fixture(t);
  await rm(script);
  const path = join(root, "fixture.txt");
  await writeFile(path, "original");
  await assert.rejects(NativeMutationIO.prepare("write", path), /backend unavailable.*reinstall the package.*Refusing path-only I\/O/);
  assert.equal(await readFile(path, "utf8"), "original");
  const absent = join(root, "absent.txt");
  await assert.rejects(NativeMutationIO.prepare("write", absent), /backend unavailable/);
  await assert.rejects(lstat(absent), { code: "ENOENT" });
});

test("parallel helpers isolate cwd and independent target handles from Pi and each other", async t => {
  const { root, NativeMutationIO } = await fixture(t);
  const cwd = process.cwd();
  const paths = [join(root, "one/fixture.txt"), join(root, "two/fixture.txt")];
  const backends = await Promise.all(paths.map(path => NativeMutationIO.prepare("write", path)));
  try {
    assert.equal(process.cwd(), cwd);
    await Promise.all(backends.map(async (io, i) => {
      await io.mkdir();
      await io.writeFile(`content ${i}`);
    }));
    assert.equal(process.cwd(), cwd);
    assert.deepEqual(await Promise.all(paths.map(path => readFile(path, "utf8"))), ["content 0", "content 1"]);
  } finally { await Promise.all(backends.map(io => io.close())); }
});
