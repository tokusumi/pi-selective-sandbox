import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Keep the existing npm test command and CI unchanged. This explicit local
// entrypoint runs the Seatbelt/platform-trust tests and related network approval checks.
export const macOSTestFiles = [
  "dist/test/loopback-sandbox.test.js",
  "dist/test/macos-attempts.test.js",
  "dist/test/git-credentials.test.js",
  "dist/test/native-macos.test.js",
  "dist/test/network-sandbox.test.js"
];

export function runLocalMacOSTests({ platform = process.platform, env = process.env, cwd = process.cwd(),
  run = (command, args) => spawnSync(command, args, { cwd, stdio: "inherit" }),
  readManifest = () => readFileSync(resolve(cwd, "package.json"), "utf8"),
  log = console.error
} = {}) {
  if (platform !== "darwin" || env.CI || env.GITHUB_ACTIONS) {
    log("Local macOS integration tests require macOS outside CI. CI must continue using npm test.");
    return 1;
  }
  try {
    if (JSON.parse(readManifest()).name !== "pi-selective-sandbox") {
      log("Run local macOS integration tests from this repository's checkout root.");
      return 1;
    }
  } catch {
    log("Cannot read a valid package.json in the checkout root. No test process was started.");
    return 1;
  }
  const execute = (command, args) => {
    const result = run(command, args);
    if (result.error) log(`Could not start test process: ${result.error.message}`);
    if (result.signal) log(`Test process terminated by ${result.signal}.`);
    return result.status ?? 1;
  };
  const probe = execute("/usr/bin/sandbox-exec", ["-p", "(version 1) (allow default)", "/usr/bin/true"]);
  if (probe !== 0) {
    log("Cannot create a macOS sandbox from this runner. Start Pi or this command from a normal host terminal, not an already sandboxed process. No tests were run, no tests were skipped, and no sandbox was disabled.");
    return probe;
  }
  const build = execute(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]);
  if (build !== 0) return build;
  log("Running the local macOS integration group, including network approval checks (not the full npm test suite).");
  return execute(process.execPath, ["--test", ...macOSTestFiles]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = runLocalMacOSTests(); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
