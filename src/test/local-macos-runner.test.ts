import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const runner = new URL("../../scripts/run-local-macos-tests.mjs", import.meta.url).href;
async function simulate(options: { platform?: string; env?: Record<string, string | undefined>; statuses?: number[]; manifest?: string; error?: boolean; signal?: boolean } = {}) {
  const { stdout } = await exec(process.execPath, ["--input-type=module", "-e", `
    import { runLocalMacOSTests } from ${JSON.stringify(runner)};
    const options = ${JSON.stringify(options)};
    const calls = [], logs = [];
    const code = runLocalMacOSTests({ platform: options.platform ?? 'darwin', env: options.env ?? {},
      cwd: '/approved/checkout', readManifest: () => options.manifest ?? '{"name":"pi-selective-sandbox"}',
      run: (command, args) => {
        calls.push([command, args]);
        if (options.error) return { status: null, error: new Error('fixture spawn error') };
        if (options.signal) return { status: null, signal: 'SIGTERM' };
        return { status: options.statuses?.[calls.length - 1] ?? 0 };
      }, log: message => logs.push(message)
    });
    console.log(JSON.stringify({code, calls, logs}));
  `]);
  return JSON.parse(stdout) as { code: number; calls: [string, string[]][]; logs: string[] };
}

test("local runner probes Seatbelt, builds, and executes the fixed integration files in order", async () => {
  const result = await simulate();
  assert.equal(result.code, 0);
  assert.deepEqual(result.calls, [
    ["/usr/bin/sandbox-exec", ["-p", "(version 1) (allow default)", "/usr/bin/true"]],
    [process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]],
    [process.execPath, ["--test", "dist/test/loopback-sandbox.test.js", "dist/test/macos-attempts.test.js", "dist/test/network-sandbox.test.js"]]
  ]);
  assert.match(result.logs.join("\n"), /not the full npm test suite/);
});

test("the local runner refuses non-macOS and CI before any process is started", async () => {
  for (const options of [{ platform: "linux" }, { platform: "win32" }, { env: { CI: "true" } }, { env: { GITHUB_ACTIONS: "true" } }]) {
    const result = await simulate(options);
    assert.equal(result.code, 1);
    assert.deepEqual(result.calls, []);
    assert.match(result.logs.join("\n"), /CI must continue using npm test/);
  }
});

test("sandbox application failure blocks the suite without skipping tests or running the build", async () => {
  const result = await simulate({ statuses: [71] });
  assert.equal(result.code, 71);
  assert.equal(result.calls.length, 1);
  assert.match(result.logs.join("\n"), /not an already sandboxed process/);
  assert.match(result.logs.join("\n"), /No tests were run, no tests were skipped, and no sandbox was disabled/);
});

test("local runner propagates build failures, test failures, spawn errors, and signals", async () => {
  for (const [options, code, processes] of [
    [{ statuses: [0, 2] }, 2, 2],
    [{ statuses: [0, 0, 7] }, 7, 3],
    [{ error: true }, 1, 1],
    [{ signal: true }, 1, 1]
  ] as const) {
    const result = await simulate(options as Parameters<typeof simulate>[0]);
    assert.equal(result.code, code);
    assert.equal(result.calls.length, processes);
  }
});

test("malformed or unrelated checkout manifests fail before any host process is started", async () => {
  for (const manifest of ["null", "{", '{"name":"another-project"}']) {
    const result = await simulate({ manifest });
    assert.equal(result.code, 1);
    assert.deepEqual(result.calls, []);
  }
});
