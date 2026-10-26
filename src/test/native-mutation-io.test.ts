import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { NativeMutationIO } from "../native-mutation-io.js";

async function directory(t: TestContext) {
  const path = await mkdtemp(join(tmpdir(), "pi-native-io-test-"));
  t.after(() => rm(path, { recursive: true, force: true }));
  return realpath(path);
}

test("descriptor protocol preserves Unicode, NUL bytes, empty and multi-chunk content", async t => {
  const root = await directory(t);
  const path = join(root, "Unicode 日本語.txt");
  await writeFile(path, "original");
  const io = await NativeMutationIO.prepare("edit", path);
  t.after(() => io.close());
  const content = "日本語\u0000\n".repeat(300_000);
  await io.writeFile(content);
  assert.equal((await io.readFile()).toString("utf8"), content);
  assert.equal(await readFile(path, "utf8"), content);
  await io.writeFile("");
  assert.equal((await io.readFile()).length, 0);
  assert.equal((await lstat(path)).size, 0);
});

test("existing file mode is preserved and preparation does not truncate", async t => {
  const root = await directory(t);
  const path = join(root, "fixture.txt");
  await writeFile(path, "original");
  await chmod(path, 0o600);
  const mode = (await lstat(path)).mode;
  const io = await NativeMutationIO.prepare("write", path);
  t.after(() => io.close());
  assert.equal(await readFile(path, "utf8"), "original");
  await io.writeFile("replacement");
  assert.equal((await lstat(path)).mode, mode);
});

test("closing a prepared backend twice is safe and later I/O refuses", async t => {
  const root = await directory(t);
  const path = join(root, "absent.txt");
  const io = await NativeMutationIO.prepare("write", path);
  await io.close();
  await io.close();
  await assert.rejects(io.writeFile("no"), /closed/);
  await assert.rejects(lstat(path), { code: "ENOENT" });
});

test("aborting a prepared backend refuses I/O and leaves contents untouched", async t => {
  const root = await directory(t);
  const path = join(root, "fixture.txt");
  await writeFile(path, "original");
  const controller = new AbortController();
  const io = await NativeMutationIO.prepare("edit", path, controller.signal);
  t.after(() => io.close());
  controller.abort();
  await assert.rejects(io.readFile(), /cancelled/);
  assert.equal(await readFile(path, "utf8"), "original");
});

test("unsupported backend never falls back to native path I/O", async t => {
  const root = await directory(t);
  const path = join(root, "absent.txt");
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  try {
    Object.defineProperty(process, "platform", { value: "unsupported" });
    await assert.rejects(NativeMutationIO.prepare("write", path), /unavailable on this platform/);
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
  await assert.rejects(lstat(path), { code: "ENOENT" });
});
