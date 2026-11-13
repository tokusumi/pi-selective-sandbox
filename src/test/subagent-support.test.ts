import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import type { RegisteredCommand, ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension from "../pi-extension.js";
import { createSubagentSupport, type RequiredChildApi } from "../subagent-support.js";
import { AnthropicSandboxRuntime, type NetworkRestrictions, type SandboxSettings } from "../runtime-adapter.js";
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
  const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
  const handlers = new Map<string, (event: unknown, context: unknown) => unknown>();
  const bus = { emit: (name: string, value: unknown) => { events.emit(name, value); }, on: (name: string, handler: (value: unknown) => void) => { events.on(name, handler); return () => { events.off(name, handler); }; } };
  return { events: bus, tools, handlers, commands,
    on: (name: string, handler: (event: unknown, context: unknown) => unknown) => {
      const previous = handlers.get(name);
      handlers.set(name, previous ? async (event, context) => { await previous(event, context); return handler(event, context); } : handler);
    },
    registerCommand: (name: string, command: Omit<RegisteredCommand, "name" | "sourceInfo">) => { commands.set(name, command); }, registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); },
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
    network: { extraAllowedDomains: ["configured.example:8443"], disabledDefaultProfiles: ["git", "node", "rust", "python"], allowLocalBinding: false }
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
  const result = await child.tools.get("bash")!.execute("same-tool-id", { command: "probe", retryOnSandboxDenial: true }, signal, () => {}, context as never);
  assert.match(JSON.stringify(result.content), /child-approved/);
  assert.equal(settings?.cwd, join(base, "child"));
  assert.deepEqual(settings?.allowedDomains, ["configured.example:8443"]);
  assert.equal(settings?.allowLocalBinding, false, "the child must inherit the parent's strict local-listener opt-out");
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
  assert.equal(settings?.allowLocalBinding, false, "later global defaults must not reopen child loopback access");
  assert.ok(settings?.writePolicy.allow.includes(join(base, "parent", "relative-extra")));
  await earlyCompanionChild.handlers.get("session_shutdown")!({}, context);
  await parent.handlers.get("session_shutdown")!({}, {});
  assert.equal(disposed, true);
});

test("global, network and socket switches propagate to new and retained native children", async t => {
  const base = await fixture(t);
  const registered: Parameters<RequiredChildApi["registerRequiredChildExtensions"]>[0][] = [];
  const loadApi = async () => ({ registerRequiredChildExtensions: (value: typeof registered[number]) => {
    registered.push(value); return { dispose: () => {} };
  } });
  const attempts: NetworkRestrictions[] = [];
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({
    logMonitorEnabled: true, supportsNetworkWidening: true,
    wrap: async (_command: string, _context: unknown, restrictions: NetworkRestrictions) => {
      attempts.push({ ...restrictions }); return "printf sandbox-boundary-active";
    },
    getViolationsForCommand: () => [], dispose: async () => {}
  }) as unknown as AnthropicSandboxRuntime);
  const parent = api(), child = api();
  const parentContext = { cwd: join(base, "parent"), hasUI: true,
    sessionManager: { getSessionId: () => "parent-switches" },
    ui: { notify: () => {}, select: async () => undefined }
  };
  const childContext = { cwd: join(base, "child"), hasUI: false,
    sessionManager: { getSessionId: () => "child-switches" }, ui: { notify: () => {} }
  };
  t.after(async () => {
    await child.handlers.get("session_shutdown")?.({}, childContext);
    await parent.handlers.get("session_shutdown")?.({}, parentContext);
  });
  const toggle = async (session: ReturnType<typeof api>, mode: "on" | "off", context: unknown) => {
    for (const args of [`network ${mode}`, `socket ${mode}`, mode]) {
      await session.commands.get("selective-sandbox")!.handler(args, context as never);
    }
  };
  await selectiveSandboxExtension(parent as never, { loadSubagentApi: loadApi });
  await parent.handlers.get("session_start")!({}, parentContext);
  await toggle(parent, "off", parentContext);
  const run = (session: ReturnType<typeof api>, context: unknown) => session.tools.get("bash")!.execute(
    "switch-propagation", { command: "printf enforcement-disabled" }, undefined, undefined, context as never);
  assert.match(JSON.stringify((await run(parent, parentContext)).content), /enforcement-disabled/);
  assert.equal(attempts.length, 0);

  await selectiveSandboxExtension(child as never, { loadSubagentApi: loadApi });
  const companion = await import(pathToFileURL(registered[0].extensions[1].path).href);
  companion.default(child);
  await child.handlers.get("session_start")!({}, childContext);
  assert.match(JSON.stringify((await run(child, childContext)).content), /enforcement-disabled/);
  assert.deepEqual(attempts, [], "a newly bound child inherits global off without initializing a sandbox attempt");
  const outside = join(base, "outside.txt");
  await child.tools.get("write")!.execute("child-off-write", { path: outside, content: "before" }, undefined, undefined, childContext as never);
  await child.tools.get("edit")!.execute("child-off-edit", { path: outside, edits: [{ oldText: "before", newText: "after" }] }, undefined, undefined, childContext as never);
  assert.equal(await readFile(outside, "utf8"), "after", "global off reaches both native mutation surfaces");

  await toggle(parent, "on", parentContext);
  assert.match(JSON.stringify((await run(child, childContext)).content), /sandbox-boundary-active/);
  assert.deepEqual(attempts.at(-1), { network: true, socket: true });
  for (const tool of ["write", "edit"]) await assert.rejects(child.tools.get(tool)!.execute("child-on-deny", {
    path: registered[0].extensions[1].path, content: "must-not-write", edits: [{ oldText: "before", newText: "after" }]
  }, undefined, undefined, childContext as never), /configured deny root/);

  for (const [args, expected] of [
    ["network off", { network: false, socket: true }],
    ["socket off", { network: false, socket: false }],
    ["network on", { network: true, socket: false }],
    ["socket on", { network: true, socket: true }]
  ] as const) {
    await parent.commands.get("selective-sandbox")!.handler(args, parentContext as never);
    await run(child, childContext);
    assert.deepEqual(attempts.at(-1), expected, `retained child follows ${args}`);
  }
  const switchPath = join(dirname(registered[0].extensions[1].path), "switches.json");
  const savedPath = switchPath + ".saved";
  await rename(switchPath, savedPath);
  await mkdir(switchPath);
  await assert.rejects(parent.commands.get("selective-sandbox")!.handler("network off", parentContext as never));
  await rm(switchPath, { recursive: true });
  await rename(savedPath, switchPath);
  await parent.commands.get("selective-sandbox")!.handler("socket off", parentContext as never);
  await run(child, childContext);
  assert.deepEqual(attempts.at(-1), { network: true, socket: false }, "failed publication did not commit local network off");
  await parent.commands.get("selective-sandbox")!.handler("socket on", parentContext as never);
  await Promise.all(["network off", "socket off"].map(args => parent.commands.get("selective-sandbox")!.handler(args, parentContext as never)));
  await run(child, childContext);
  assert.deepEqual(attempts.at(-1), { network: false, socket: false }, "serialized commands preserve both changes");
  await parent.commands.get("selective-sandbox")!.handler("off", parentContext as never);
  await parent.commands.get("selective-sandbox")!.handler("on", parentContext as never);
  await run(child, childContext);
  assert.deepEqual(attempts.at(-1), { network: false, socket: false }, "global on preserves inherited component switches");
  await toggle(parent, "on", parentContext);
  await parent.commands.get("selective-sandbox")!.handler("network off", parentContext as never);
  // A bound descendant uses the same owning parent's companion, including companion-first loading.
  const grandchild = api();
  companion.default(grandchild);
  await selectiveSandboxExtension(grandchild as never, { loadSubagentApi: loadApi });
  await grandchild.handlers.get("session_start")!({}, childContext);
  t.after(async () => { await grandchild.handlers.get("session_shutdown")?.({}, childContext); });
  await toggle(child, "off", childContext); // Bound child commands cannot alter parent/siblings.
  await run(child, childContext);
  assert.deepEqual(attempts.at(-1), { network: false, socket: true });
  await run(grandchild, childContext);
  assert.deepEqual(attempts.at(-1), { network: false, socket: true });
  await run(parent, parentContext);
  assert.deepEqual(attempts.at(-1), { network: false, socket: true });
  await toggle(parent, "off", parentContext);
  const count = attempts.length;
  assert.match(JSON.stringify((await run(grandchild, childContext)).content), /enforcement-disabled/);
  assert.equal(attempts.length, count);
  const savedOff = await readFile(switchPath, "utf8");
  await writeFile(switchPath, "{broken");
  await assert.rejects(run(child, childContext), /switch state.*blocked/);
  for (const tool of ["write", "edit"]) await assert.rejects(child.tools.get(tool)!.execute("corrupt-off", {
    path: outside, content: "must-not-write", edits: [{ oldText: "after", newText: "must-not-write" }]
  }, undefined, undefined, childContext as never), /switch state.*blocked/);
  await writeFile(switchPath, savedOff);
  await parent.handlers.get("session_shutdown")!({}, parentContext);
  await assert.rejects(run(child, childContext), /switch state.*blocked/);
  await assert.rejects(child.tools.get("write")!.execute("closed-parent", { path: outside, content: "must-not-write" }, undefined, undefined, childContext as never), /switch state.*blocked/);
  assert.equal(await readFile(outside, "utf8"), "after");
});

test("parent switch changes do not rewrite a child's in-flight attempt or approved retry", async t => {
  const base = await fixture(t);
  let companionPath = "";
  const loadApi = async () => ({ registerRequiredChildExtensions: (value: Parameters<RequiredChildApi["registerRequiredChildExtensions"]>[0]) => {
    companionPath = value.extensions[1].path; return { dispose: () => {} };
  } });
  let started!: () => void, release!: () => void;
  const firstStarted = new Promise<void>(resolve => { started = resolve; });
  const wait = new Promise<void>(resolve => { release = resolve; });
  const attempts: NetworkRestrictions[] = [];
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => ({
    logMonitorEnabled: true, supportsNetworkWidening: true,
    wrap: async (_command: string, _context: unknown, switches: NetworkRestrictions) => {
      attempts.push({ ...switches });
      if (attempts.length === 1) { started(); await wait; return "exit 1"; }
      return "printf approved-retry";
    },
    getViolationsForCommand: () => [{ kind: "network", resource: "fixture.example:443" }], dispose: async () => {}
  }) as unknown as AnthropicSandboxRuntime);
  const parent = api(), child = api();
  const parentContext = { cwd: join(base, "parent"), hasUI: true, sessionManager: { getSessionId: () => "snapshot-parent" }, ui: {
    notify: () => {}, select: async (_title: string, choices: string[]) => choices.includes("Once") ? "Once" : choices.includes("Allow and retry") ? "Allow and retry" : undefined
  } };
  const childContext = { cwd: join(base, "child"), hasUI: false, sessionManager: { getSessionId: () => "snapshot-child" } };
  t.after(async () => { release(); await child.handlers.get("session_shutdown")?.({}, childContext); await parent.handlers.get("session_shutdown")?.({}, parentContext); });
  await selectiveSandboxExtension(parent as never, { loadSubagentApi: loadApi });
  await parent.handlers.get("session_start")!({}, parentContext);
  await selectiveSandboxExtension(child as never, { loadSubagentApi: loadApi });
  (await import(pathToFileURL(companionPath).href)).default(child);
  await child.handlers.get("session_start")!({}, childContext);
  const run = (id: string) => child.tools.get("bash")!.execute(id, { command: "printf next-operation", retryOnSandboxDenial: true }, undefined, undefined, childContext as never);
  const inFlight = run("snapshot-first");
  await firstStarted;
  for (const args of ["off", "network off", "socket off"]) await parent.commands.get("selective-sandbox")!.handler(args, parentContext as never);
  release();
  assert.match(JSON.stringify((await inFlight).content), /approved-retry/);
  assert.deepEqual(attempts, [{ network: true, socket: true }, { network: true, socket: true }]);
  assert.match(JSON.stringify((await run("snapshot-next")).content), /next-operation/);
  assert.equal(attempts.length, 2, "only the next operation switches to global off");
});

test("a child's SDK monitor fallback never publishes off to its parent", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(console, "warn", () => {});
  const base = await fixture(t);
  let companionPath = "";
  const loadApi = async () => ({ registerRequiredChildExtensions: (value: Parameters<RequiredChildApi["registerRequiredChildExtensions"]>[0]) => {
    companionPath = value.extensions[1].path; return { dispose: () => {} };
  } });
  t.mock.method(AnthropicSandboxRuntime, "initialize", async (settings: SandboxSettings) => ({
    logMonitorEnabled: settings.cwd !== join(base, "child"), supportsNetworkWidening: true,
    wrap: async () => "printf parent-still-sandboxed", getViolationsForCommand: () => [], dispose: async () => {}
  }) as unknown as AnthropicSandboxRuntime);
  const parent = api(), child = api();
  const parentContext = { cwd: join(base, "parent"), hasUI: true, sessionManager: { getSessionId: () => "monitor-parent" }, ui: { notify: () => {}, select: async () => undefined } };
  const childContext = { cwd: join(base, "child"), hasUI: false, sessionManager: { getSessionId: () => "monitor-child" } };
  t.after(async () => { await child.handlers.get("session_shutdown")?.({}, childContext); await parent.handlers.get("session_shutdown")?.({}, parentContext); });
  await selectiveSandboxExtension(parent as never, { loadSubagentApi: loadApi });
  await parent.handlers.get("session_start")!({}, parentContext);
  await selectiveSandboxExtension(child as never, { loadSubagentApi: loadApi });
  (await import(pathToFileURL(companionPath).href)).default(child);
  await child.handlers.get("session_start")!({}, childContext);
  const run = (session: ReturnType<typeof api>, context: unknown) => session.tools.get("bash")!.execute("monitor", { command: "printf local-fallback" }, undefined, undefined, context as never);
  assert.match(JSON.stringify((await run(child, childContext)).content), /local-fallback/);
  await parent.commands.get("selective-sandbox")!.handler("network off", parentContext as never);
  assert.match(JSON.stringify((await run(parent, parentContext)).content), /parent-still-sandboxed/);
  assert.equal(JSON.parse(await readFile(join(dirname(companionPath), "switches.json"), "utf8")).enabled, true);
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
