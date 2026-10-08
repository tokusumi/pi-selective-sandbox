import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension from "../pi-extension.js";
import { createSubagentSupport, type RequiredChildApi } from "../subagent-support.js";
import { AnthropicSandboxRuntime, type SandboxSettings } from "../runtime-adapter.js";
import type { Capability } from "../types.js";
import { SUBAGENT_BINDING_EVENT } from "../subagent-approval.js";

async function fixture(t: test.TestContext) {
  const base = await realpath(await mkdtemp(join(tmpdir(), "pi-child-support-")));
  const original = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = join(base, "agent");
  await mkdir(join(base, "parent")); await mkdir(join(base, "child"));
  await mkdir(join(base, "agent", "pi-selective-sandbox"), { recursive: true });
  t.after(async () => { if (original === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = original; await rm(base, { recursive: true, force: true }); });
  return base;
}
function api() {
  const events = new EventEmitter();
  const tools = new Map<string, ToolDefinition>();
  const handlers = new Map<string, (event: unknown, context: unknown) => unknown>();
  const bus = { emit: (name: string, value: unknown) => { events.emit(name, value); }, on: (name: string, handler: (value: unknown) => void) => { events.on(name, handler); return () => { events.off(name, handler); }; } };
  return { events: bus, tools, handlers,
    on: (name: string, handler: (event: unknown, context: unknown) => unknown) => {
      const previous = handlers.get(name);
      handlers.set(name, previous ? async (event, context) => { await previous(event, context); return handler(event, context); } : handler);
    },
    registerCommand: () => {}, registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); },
    getAllTools: () => [...tools.values()] };
}

test("required child extensions carry parent-specific routing and filesystem/network configuration", async t => {
  const base = await fixture(t);
  const parent = api();
  t.after(async () => { await parent.handlers.get("session_shutdown")?.({}, {}); });
  const registered: Parameters<RequiredChildApi["registerRequiredChildExtensions"]>[0][] = [];
  let disposed = false;
  const loadApi = async () => ({ registerRequiredChildExtensions: (value: typeof registered[number]) => {
    registered.push(value); return { dispose: () => { disposed = true; } };
  } });
  await writeFile(join(base, "agent", "pi-selective-sandbox", "config.json"), JSON.stringify({
    filesystem: { extraWritableRoots: ["relative-extra"], disabledDefaultProfiles: ["cargo-cache"] },
    network: { extraAllowedDomains: ["configured.example:8443"], disabledDefaultProfiles: ["git", "node", "rust", "python"] }
  }));
  await selectiveSandboxExtension(parent as never, { loadSubagentApi: loadApi });
  const titles: string[] = [];
  await parent.handlers.get("session_start")!({}, { cwd: join(base, "parent"), hasUI: true, mode: "tui",
    sessionManager: { getSessionId: () => "parent-session" }, ui: { select: async (title: string, choices: string[]) => { titles.push(title); return choices[0]; } } });
  assert.equal(registered.length, 1);
  assert.equal(registered[0].sessionId, "parent-session");
  assert.deepEqual(registered[0].extensions.map(value => value.id), ["pi-selective-sandbox", "pi-selective-sandbox-parent"]);
  assert.match(await readFile(registered[0].extensions[1].path, "utf8"), /parent-session/);
  assert.match(await readFile(registered[0].extensions[1].path, "utf8"), /configured.example:8443/);
  let settings: SandboxSettings | undefined;
  const attempts: Capability[][] = [];
  t.mock.method(AnthropicSandboxRuntime, "initialize", async (value: SandboxSettings) => {
    settings = value;
    return { logMonitorEnabled: true, supportsNetworkWidening: true,
      wrap: async (_command: string, context: { extraCapabilities?: Capability[] }) => {
        attempts.push([...(context.extraCapabilities ?? [])]);
        return attempts.length === 1 ? "exit 1" : "printf child-approved";
      },
      getViolationsForCommand: () => [{ kind: "network", resource: "blocked.example:9443" }],
      forgetCommand: async () => {}, dispose: async () => {}
    } as unknown as AnthropicSandboxRuntime;
  });
  const child = api();
  await selectiveSandboxExtension(child as never, { loadSubagentApi: loadApi });
  const companion = await import(pathToFileURL(registered[0].extensions[1].path).href);
  companion.default(child);
  const context = { cwd: join(base, "child"), hasUI: false, mode: "print", sessionManager: { getSessionId: () => "child-session" } };
  await child.handlers.get("session_start")!({}, context);
  assert.equal(registered.length, 1, "a headless child cannot replace its inherited parent endpoint");
  const signal = new AbortController().signal;
  const result = await child.tools.get("bash")!.execute("same-tool-id", { command: "probe" }, signal, () => {}, context as never);
  assert.match(JSON.stringify(result.content), /child-approved/);
  assert.equal(settings?.cwd, join(base, "child"));
  assert.deepEqual(settings?.allowedDomains, ["configured.example:8443"]);
  assert.ok(settings?.writePolicy.allow.includes(join(base, "parent", "relative-extra")));
  assert.ok(settings?.writePolicy.allow.includes(join(base, "child")));
  assert.ok(!settings?.writePolicy.allow.includes(join(base, "parent")));
  assert.ok(settings?.writePolicy.deny.includes(join(base, "agent", "pi-selective-sandbox", "approvals")));
  assert.deepEqual(attempts, [[], [{ kind: "network", resource: "blocked.example:9443" }]]);
  assert.equal(titles.length, 2);
  assert.ok(titles.every(title => title.includes("child-session") && title.includes("blocked.example:9443")));
  await assert.rejects(child.tools.get("write")!.execute("tamper", { path: registered[0].extensions[1].path, content: "tampered" }, signal, () => {}, context as never), /configured deny root/);
  await child.tools.get("write")!.execute("relative-write", { path: "child.txt", content: "inside child" }, signal, () => {}, context as never);
  assert.equal(await readFile(join(base, "child", "child.txt"), "utf8"), "inside child");
  await child.handlers.get("session_shutdown")!({}, context);
  assert.equal(disposed, false);
  // Load ordering must not drop inheritance or silently widen network defaults.
  // A later user config edit also must not alter the parent's registered snapshot.
  await writeFile(join(base, "agent", "pi-selective-sandbox", "config.json"), "{}");
  const earlyCompanionChild = api();
  companion.default(earlyCompanionChild);
  await selectiveSandboxExtension(earlyCompanionChild as never, { loadSubagentApi: loadApi });
  await earlyCompanionChild.handlers.get("session_start")!({}, context);
  await earlyCompanionChild.tools.get("bash")!.execute("early-binding", { command: "probe" }, signal, () => {}, context as never);
  assert.deepEqual(settings?.allowedDomains, ["configured.example:8443"], "companion-first loading must inherit the parent's restrictive network snapshot");
  assert.ok(settings?.writePolicy.allow.includes(join(base, "parent", "relative-extra")));
  await earlyCompanionChild.handlers.get("session_shutdown")!({}, context);
  await parent.handlers.get("session_shutdown")!({}, {});
  assert.equal(disposed, true);
});

test("a failed registration blocks subagent admission instead of falling back to unsandboxed children", async t => {
  const base = await fixture(t);
  const parent = api();
  const warning = t.mock.method(console, "warn", () => {});
  await selectiveSandboxExtension(parent as never, { loadSubagentApi: async () => ({ registerRequiredChildExtensions: () => { throw new Error("another host owns this registry"); } }) });
  await parent.handlers.get("session_start")!({}, { cwd: join(base, "parent"), hasUI: true, sessionManager: { getSessionId: () => "P" }, ui: { select: async () => undefined } });
  assert.equal(warning.mock.callCount(), 1);
  assert.deepEqual(parent.handlers.get("tool_call")!({ toolName: "subagent" }, {}), { block: true, reason: "Subagent sandbox integration is unavailable; no child was launched." });
  assert.equal(parent.handlers.get("tool_call")!({ toolName: "bash" }, {}), undefined);
  assert.equal(parent.handlers.get("tool_call")!({ toolName: "subagent", input: { action: "status" } }, {}), undefined);
  assert.equal(parent.handlers.get("tool_call")!({ toolName: "subagent", input: { action: "stop" } }, {}), undefined);
  assert.ok(parent.handlers.get("tool_call")!({ toolName: "subagent", input: { action: "resume" } }, {}));
  await parent.handlers.get("session_shutdown")!({}, {});
});

test("different parent sessions receive isolated endpoint files and registrations", async t => {
  const base = await fixture(t);
  const root = join(base, "approvals");
  const paths: string[] = [];
  const loadApi = async () => ({ registerRequiredChildExtensions: (value: Parameters<RequiredChildApi["registerRequiredChildExtensions"]>[0]) => {
    paths.push(value.extensions[1].path); return { dispose: () => {} };
  } });
  const supports = ["A", "B"].map(() => createSubagentSupport(api() as never, { entryPath: fileURLToPath(import.meta.url), loadApi }));
  t.after(async () => { for (const support of supports) await support.close(); });
  for (let index = 0; index < supports.length; index++) await supports[index].start({ cwd: base, hasUI: true, sessionManager: { getSessionId: () => ["A", "B"][index] }, ui: { select: async () => undefined } }, { valid: false }, root);
  assert.notEqual(paths[0], paths[1]);
  assert.match(await readFile(paths[0], "utf8"), /parentSessionId.*A/);
  assert.match(await readFile(paths[1], "utf8"), /parentSessionId.*B/);
});

test("an invalid child binding blocks execution instead of falling back to unrelated global defaults", async t => {
  const base = await fixture(t);
  const child = api();
  await selectiveSandboxExtension(child as never, { loadSubagentApi: async () => undefined });
  assert.throws(() => child.events.emit(SUBAGENT_BINDING_EVENT, { version: 1, binding: null }), /Invalid/);
  const context = { cwd: join(base, "child"), hasUI: false, sessionManager: { getSessionId: () => "child" } };
  await assert.rejects(Promise.resolve().then(() => child.handlers.get("session_start")!({}, context)), /binding failed/);
  const signal = new AbortController().signal;
  for (const [tool, params] of [["bash", { command: "printf must-not-run" }], ["write", { path: "must-not-write", content: "no" }], ["edit", { path: "must-not-edit", oldText: "before", newText: "after" }]] as const) {
    await assert.rejects(child.tools.get(tool)!.execute("invalid-binding", params, signal, () => {}, context as never), /binding failed/);
  }
  await child.handlers.get("session_shutdown")!({}, context);
});

for (const failure of ["missing-parent-id", "malformed-receipt"] as const) {
  test(`${failure} fails closed and preserves safe subagent status/control access`, async t => {
    const base = await fixture(t);
    const parent = api();
    const warning = t.mock.method(console, "warn", () => {});
    await selectiveSandboxExtension(parent as never, { loadSubagentApi: async () => ({
      registerRequiredChildExtensions: () => undefined as unknown as ReturnType<RequiredChildApi["registerRequiredChildExtensions"]>
    }) });
    await parent.handlers.get("session_start")!({}, { cwd: join(base, "parent"), hasUI: true,
      sessionManager: { getSessionId: () => failure === "missing-parent-id" ? undefined : "P" }, ui: { select: async () => undefined } });
    assert.equal(warning.mock.callCount(), 1);
    assert.ok(parent.handlers.get("tool_call")!({ toolName: "subagent" }, {}));
    assert.equal(parent.handlers.get("tool_call")!({ toolName: "subagent", input: { action: "status" } }, {}), undefined);
    await parent.handlers.get("session_shutdown")!({}, {});
  });
}
