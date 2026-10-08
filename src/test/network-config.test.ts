import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { DEFAULT_ALLOWED_DOMAINS, canonicalNetworkEndpoint, networkResourceFromLine } from "../network-policy.js";

test("extension forwards network config to the runtime and invalid config closes both policies", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-network-config-"));
  const agentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = base;
  t.after(async () => {
    if (agentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = agentDir;
    await rm(base, { recursive: true, force: true });
  });
  const folder = join(base, "pi-selective-sandbox");
  await mkdir(folder);
  // SAFETY: the extension only uses these public methods; this fixture deliberately skips OS initialization.
  const initialize = t.mock.method(AnthropicSandboxRuntime, "initialize", async (_settings: Parameters<typeof AnthropicSandboxRuntime.initialize>[0]) => ({
    logMonitorEnabled: true, wrap: async (command: string) => command, forgetCommand: () => {}, getViolationsForCommand: () => []
  } as unknown as AnthropicSandboxRuntime));
  const diagnostic = t.mock.method(console, "warn", () => {});
  for (const [config, valid] of [[{ network: { extraAllowedDomains: ["Packages.Example.com:443"] } }, true], [{ network: { extraAllowedDomains: ["*"] } }, false]] as const) {
    await writeFile(join(folder, "config.json"), JSON.stringify(config));
    const tools = new Map<string, ToolDefinition>();
    await selectiveSandboxExtension({ on: () => {}, registerCommand: () => {}, registerTool: (tool: ToolDefinition) => tools.set(tool.name, tool) } as never);
    await tools.get("bash")!.execute("config", { command: "true" }, new AbortController().signal, () => {}, { hasUI: false } as never);
    const settings = initialize.mock.calls.at(-1)!.arguments[0];
    assert.deepEqual(settings.allowedDomains, valid ? [...DEFAULT_ALLOWED_DOMAINS, "packages.example.com:443"] : []);
    if (!valid) {
      assert.deepEqual(settings.writePolicy.allow, []);
      assert.match(String(diagnostic.mock.calls.at(-1)!.arguments[0]), /Invalid pi-selective-sandbox config/);
    }
  }
  await writeFile(join(folder, "config.json"), JSON.stringify({ network: {
    disabledDefaultProfiles: ["git", "node", "rust", "python"], extraAllowedDomains: ["Registry.NPMJS.org:443", "registry.npmjs.org:443"]
  } }));
  const tools = new Map<string, ToolDefinition>();
  await selectiveSandboxExtension({ on: () => {}, registerCommand: () => {}, registerTool: (tool: ToolDefinition) => tools.set(tool.name, tool) } as never);
  await tools.get("bash")!.execute("config-disabled", { command: "true" }, new AbortController().signal, () => {}, { hasUI: false } as never);
  assert.deepEqual(initialize.mock.calls.at(-1)!.arguments[0].allowedDomains, ["registry.npmjs.org:443"]);
});

test("endpoint identity canonicalizes host and IPv6 but never guesses or widens", () => {
  assert.equal(canonicalNetworkEndpoint("EXAMPLE.com:443"), "example.com:443");
  assert.equal(canonicalNetworkEndpoint("[2001:0db8::1]:443"), "[2001:db8::1]:443");
  assert.equal(networkResourceFromLine("deny network-outbound ::1:8080 (host is not on the allow list)"), "[::1]:8080");
  for (const resource of ["example.com", "example.com:0443", "*.example.com:443", "unknown", "https://example.com", "[::1]:65536", "example.com:443\0"]) {
    assert.equal(canonicalNetworkEndpoint(resource), undefined);
  }
  for (const reason of ["malformed host", "resolved to a loopback address", "host is on the deny list"]) {
    assert.equal(networkResourceFromLine(`deny network-outbound example.com:443 (${reason})`), undefined);
  }
});
