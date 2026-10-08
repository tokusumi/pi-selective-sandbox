import assert from "node:assert/strict";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime, type SandboxSettings } from "../runtime-adapter.js";
import { DEFAULT_ALLOWED_DOMAINS } from "../network-policy.js";

test("a native child uses its session cwd and network policy, not the host process cwd", async t => {
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "pi-child-cwd-")));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  let settings: SandboxSettings | undefined;
  t.mock.method(AnthropicSandboxRuntime, "initialize", async (value: SandboxSettings) => {
    settings = value;
    return { logMonitorEnabled: true, wrap: async (command: string) => command,
      getViolationsForCommand: () => [], forgetCommand: () => undefined } as unknown as AnthropicSandboxRuntime;
  });
  const tools = new Map<string, ToolDefinition>();
  await selectiveSandboxExtension({
    on: () => undefined, registerCommand: () => undefined,
    registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); }
  } as never);
  const output = await tools.get("bash")!.execute("child-cwd", { command: "pwd" }, new AbortController().signal, () => {},
    { cwd, hasUI: false, sessionManager: { getSessionId: () => "child" } } as never);
  assert.equal(settings?.cwd, cwd);
  assert.ok(settings?.writePolicy.allow.includes(cwd));
  assert.deepEqual(settings?.allowedDomains, DEFAULT_ALLOWED_DOMAINS);
  assert.match(JSON.stringify(output.content), new RegExp(cwd));
});
