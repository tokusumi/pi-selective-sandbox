import { readFile, realpath } from "node:fs/promises";
import { join, relative, isAbsolute } from "node:path";
import { Type } from "@earendil-works/pi-ai";
import type { createBashTool, ToolDefinition } from "@earendil-works/pi-coding-agent";

const parameters = Type.Object({}, { additionalProperties: false });
const approve = "Run macOS integration tests once on host";
const script = "scripts/run-local-macos-tests.mjs";
type BashTool = ReturnType<typeof createBashTool>;
export type MacOSTestRunner = (id: string, cwd: string, command: string,
  signal: Parameters<BashTool["execute"]>[2], onUpdate: Parameters<BashTool["execute"]>[3]) => ReturnType<BashTool["execute"]>;

export function isLocalMacOS(): boolean {
  return process.platform === "darwin" && !process.env.CI && !process.env.GITHUB_ACTIONS;
}

async function checkout(cwd: string): Promise<{ cwd: string; script: string }> {
  const canonical = await realpath(cwd);
  let manifest;
  try { manifest = JSON.parse(await readFile(join(canonical, "package.json"), "utf8")); }
  catch { throw new Error("Cannot read a valid development checkout package.json; host execution was not started."); }
  if (manifest?.name !== "pi-selective-sandbox" || manifest.scripts?.["test:macos"] !== `node ${script}`) {
    throw new Error("macos_sandbox_test is only available in a pi-selective-sandbox development checkout with test:macos configured.");
  }
  const target = await realpath(join(canonical, script));
  const path = relative(canonical, target);
  if (isAbsolute(path) || path === ".." || path.startsWith("../")) throw new Error("The local macOS test runner must remain inside the checkout.");
  return { cwd: canonical, script: target };
}

/** A separate, once-only host authority, never a fallback from ordinary bash. */
export function createMacOSTestTool(runHost: MacOSTestRunner): ToolDefinition<typeof parameters> {
  let busy = false;
  return {
    name: "macos_sandbox_test",
    label: "macOS sandbox integration tests",
    description: "Local macOS development only. Ask the human to run this repository's fixed OS integration tests from the host, so the tests can create their own sandboxes. Requires fresh, once-only UI approval; never disables sandbox enforcement for bash/write/edit. No arguments, CI, or headless execution.",
    parameters,
    async execute(id, params, signal, onUpdate, context) {
      const guard = () => {
        if (!isLocalMacOS()) throw new Error("macos_sandbox_test requires local macOS, outside CI.");
        if (signal?.aborted) throw new Error("macOS test execution cancelled; host execution was not started.");
      };
      guard();
      if (Object.keys(params).length) throw new Error("macos_sandbox_test accepts no command, path, or test arguments.");
      if (!context.hasUI) throw new Error("macOS host tests require an interactive human approval; host execution was not started.");
      if (busy) throw new Error("A macOS host test request is already pending or running.");
      busy = true;
      try {
        const target = await checkout(context.cwd);
        const command = `'${process.execPath.replaceAll("'", "'\\''")}' ${script}`;
        guard();
        const choice = await context.ui.select("Run local macOS integration tests outside the agent sandbox?"
          + "\n\nExact command:\n" + command + "\n\nCanonical working directory:\n" + target.cwd
          + "\n\nThis builds and executes checkout code with your host user's permissions, including filesystem, credentials, and network access. The tests create their own sandboxes; the build and test harness are NOT sandboxed."
          + "\n\nOnce only. No grant is saved. Bash/write/edit enforcement is unchanged. This is not the full npm test suite.",
          ["Deny", approve], { signal, timeout: 300000 });
        guard();
        if (choice !== approve) throw new Error("macOS host tests were not approved; host execution was not started.");
        const current = await checkout(context.cwd);
        if (current.cwd !== target.cwd || current.script !== target.script) throw new Error("The checkout changed during approval; host execution was not started.");
        guard();
        return await runHost(id, target.cwd, command, signal, onUpdate);
      } finally {
        busy = false;
      }
    }
  };
}
