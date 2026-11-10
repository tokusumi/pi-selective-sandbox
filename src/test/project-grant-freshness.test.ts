import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, readFile, readdir, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { ProjectGrantStore } from "../project-grants.js";
import { ProjectHostCommandGrantStore } from "../project-host-command-grants.js";

const exec = promisify(execFile);
const project = "/project";
const resource = (index: number) => ({ kind: "filesystem.write" as const, resource: `/outside/${index}` });
const command = (index: number) => ({ shellCommand: `echo ${index}`, cwd: project, executionMode: "shell" });
const fixtures = [
  {
    name: "resource", module: new URL("../project-grants.js", import.meta.url).href, className: "ProjectGrantStore",
    value: (index: number) => [resource(index)],
    create(path: string) {
      const store = new ProjectGrantStore(path);
      return { load: () => store.load(), grant: (index: number) => store.grant(project, [resource(index)]),
        covers: (index: number) => store.covers(project, [resource(index)]), entries: () => store.capabilities(project) };
    }
  },
  {
    name: "host", module: new URL("../project-host-command-grants.js", import.meta.url).href, className: "ProjectHostCommandGrantStore",
    value: command,
    create(path: string) {
      const store = new ProjectHostCommandGrantStore(path);
      return { load: () => store.load(), grant: (index: number) => store.grant(project, command(index)),
        covers: (index: number) => store.covers(project, command(index)), entries: () => store.commands(project) };
    }
  }
];

for (const fixture of fixtures) {
  test(`${fixture.name}: preloaded stores see additions, replacement, revocation and read failure recovery`, async t => {
    const base = await mkdtemp(join(tmpdir(), "pi-grant-freshness-"));
    t.after(() => rm(base, { recursive: true, force: true }));
    const path = join(base, "grants.json");
    const a = fixture.create(path), b = fixture.create(path);
    await Promise.all([a.load(), b.load()]);
    assert.equal(await b.covers(1), false);
    assert.deepEqual(await b.entries(), []);
    await a.grant(1);
    assert.equal(await b.covers(1), true);
    assert.equal((await b.entries()).length, 1);
    await b.grant(2);
    assert.equal(await a.covers(2), true);
    assert.equal((await a.entries()).length, 2);

    // No timestamp/size shortcut may retain an old authorization snapshot.
    await utimes(path, 123456789, 123456789);
    const before = await stat(path);
    const snapshot = await readFile(path, "utf8");
    const replacement = join(base, "replacement.json");
    await writeFile(replacement, snapshot.replaceAll(fixture.name === "resource" ? "/outside/1" : "echo 1", fixture.name === "resource" ? "/outside/3" : "echo 3"));
    await utimes(replacement, before.atime, before.mtime);
    assert.equal((await stat(replacement)).size, before.size);
    assert.equal((await stat(replacement)).mtimeMs, before.mtimeMs);
    await rename(replacement, path);
    assert.equal(await b.covers(1), false);
    assert.equal(await b.covers(3), true);
    assert.equal(await a.covers(1), false);

    // An update must not merge its previous in-memory view back onto disk.
    await a.grant(4);
    assert.equal(await b.covers(1), false);
    assert.equal(await b.covers(4), true);
    for (const invalid of ["{bad json", JSON.stringify({ version: 99, projects: {} }), JSON.stringify({ version: 1, projects: { [project]: [] } })]) {
      await writeFile(path, invalid);
      for (const store of [a, b]) {
        assert.equal(await store.covers(3), false);
        assert.deepEqual(await store.entries(), []);
      }
      await writeFile(path, snapshot);
      assert.equal(await b.covers(1), true);
    }
    await rm(path);
    assert.equal(await b.covers(1), false);
    assert.deepEqual(await a.entries(), []);
    // EISDIR is a portable read failure even when tests run as root.
    await mkdir(path);
    assert.equal(await a.covers(1), false);
    assert.deepEqual(await b.entries(), []);
    await rm(path, { recursive: true });
    await writeFile(path, snapshot);
    assert.equal(await a.covers(1), true);
    assert.equal(await b.covers(2), true);
  });

  test(`${fixture.name}: overlapping writers publish whole snapshots, never unapproved entries`, { timeout: 15_000 }, async t => {
    const base = await mkdtemp(join(tmpdir(), "pi-grant-writers-"));
    t.after(() => rm(base, { recursive: true, force: true }));
    const path = join(base, "grants.json");
    const reader = fixture.create(path);
    await reader.load();
    const indices = [1, 2, 3, 4];
    await Promise.all(indices.map(index => exec(process.execPath, ["--input-type=module", "-e", `
      import { ${fixture.className} } from ${JSON.stringify(fixture.module)};
      await new ${fixture.className}(${JSON.stringify(path)}).grant(${JSON.stringify(project)}, ${JSON.stringify(fixture.value(index))});
    `])));
    // Last-writer-wins, not a lossless transaction: only a nonempty subset is guaranteed.
    const expected = indices.flatMap<unknown>(index => fixture.value(index));
    const entries = await reader.entries();
    assert.ok(entries.length > 0);
    for (const entry of entries) assert.ok(expected.some(value => JSON.stringify(value) === JSON.stringify(entry)));
    assert.equal(JSON.parse(await readFile(path, "utf8")).version, 1);

    // Same-process writers must also use distinct temporary files even in one millisecond.
    t.mock.method(Date, "now", () => 12345);
    await Promise.all(indices.map(index => fixture.create(path).grant(index)));
    assert.deepEqual(await readdir(base), ["grants.json"]);
    await rm(path);
    assert.deepEqual(await reader.entries(), []);
    for (const index of indices) assert.equal(await reader.covers(index), false);
  });

  test(`${fixture.name}: an already-running child and parent observe each other's persisted changes`, { timeout: 15_000 }, async t => {
    const base = await mkdtemp(join(tmpdir(), "pi-grant-process-"));
    t.after(() => rm(base, { recursive: true, force: true }));
    const path = join(base, "grants.json");
    const parent = fixture.create(path);
    await parent.load();
    const child = spawn(process.execPath, ["--input-type=module", "-e", `
      import { ${fixture.className} } from ${JSON.stringify(fixture.module)};
      const store = new ${fixture.className}(${JSON.stringify(path)});
      await store.load();
      process.on("message", async ({ action, value }) => {
        try {
          const result = action === "grant" ? await store.grant(${JSON.stringify(project)}, value)
            : await store.covers(${JSON.stringify(project)}, value);
          process.send({ result: result ?? null });
        } catch (error) { process.send({ error: String(error) }); }
      });
      process.send({ ready: true });
    `], { stdio: ["ignore", "ignore", "pipe", "ipc"] });
    t.after(async () => { const exited = once(child, "close"); child.kill(); await exited; });
    assert.deepEqual((await once(child, "message"))[0], { ready: true });
    const ask = async (action: string, index: number) => {
      const reply = once(child, "message");
      child.send({ action, value: fixture.value(index) });
      return (await reply)[0];
    };
    await parent.grant(1);
    assert.deepEqual(await ask("covers", 1), { result: true });
    assert.deepEqual(await ask("grant", 2), { result: null });
    assert.equal(await parent.covers(2), true);
    await writeFile(path, "{bad json");
    assert.deepEqual(await ask("covers", 1), { result: false });
    assert.equal(await parent.covers(2), false);
    await rm(path);
    assert.deepEqual(await ask("covers", 2), { result: false });
    await parent.grant(3);
    assert.deepEqual(await ask("covers", 3), { result: true });
    assert.deepEqual(await ask("covers", 1), { result: false });
  });
}
