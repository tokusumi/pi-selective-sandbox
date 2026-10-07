import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { RegisteredCommand, ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension, { emitExecutorOutput, emitSandboxStatus, minimalWriteRoots, redactToolResult } from "../pi-extension.js";
import { DEFAULT_WRITE_PROFILES } from "../config.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";

test("Pi entrypoint registers a replacement bash tool", async () => {
  const tools: { name: string }[] = [];
  const events: string[] = [];
  const commands: string[] = [];
  await selectiveSandboxExtension({
    on: (event: string) => { events.push(event); },
    registerCommand: (name: string) => { commands.push(name); },
    registerTool: (value: { name: string }) => { tools.push(value); }
  } as never);
  assert.deepEqual(tools.map(tool => tool.name), ["bash", "write", "edit"]);
  assert.deepEqual(events, ["session_shutdown"]);
  assert.deepEqual(commands, ["selective-sandbox"]);
});

test("package manifest exposes the compiled Pi extension", async () => {
  const manifest = await import("../../package.json", { with: { type: "json" } });
  assert.deepEqual(manifest.default.pi.extensions, ["./src/pi-extension.ts"]);
  assert.equal(manifest.default.private, true);
});

test("whole-result redaction protects a token split across streamed chunks", () => {
  const chunk1 = "ghp_";
  const chunk2 = "A".repeat(36);
  const result = redactToolResult({ content: [{ type: "text", text: chunk1 + chunk2 }] });
  const text = result.content[0].text ?? "";
  assert.doesNotMatch(text, /ghp_A/);
  assert.match(text, /\[REDACTED:GitHub Token\]/);
});

test("executor-generated fail-closed messages are emitted to Pi", () => {
  const chunks: string[] = [];
  emitExecutorOutput(
    { stdout: "", stderr: "Sandbox unavailable; host execution was not attempted." },
    chunk => chunks.push(chunk.toString())
  );
  assert.deepEqual(chunks, ["Sandbox unavailable; host execution was not attempted."]);
});

test("sandbox status markers stream as separate transcript lines", () => {
  const chunks = ["fatal: Read-only file system"];
  emitSandboxStatus("<sandbox: approval-required filesystem.write>", chunk => chunks.push(chunk.toString()));
  assert.equal(chunks.join(""), "fatal: Read-only file system\n<sandbox: approval-required filesystem.write>\n");
});

test("parent approval removes redundant nested mount points", () => {
  const write = (resource: string) => ({ kind: "filesystem.write" as const, resource });
  assert.deepEqual(minimalWriteRoots([
    write("/repo/.git/worktrees/child"), write("/repo"), write("/repo/.git"), write("/other")
  ]), [write("/repo"), write("/other")]);
});

test("write fails closed without an interactive approval UI", async t => {
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () =>
    ({ logMonitorEnabled: true } as unknown as AnthropicSandboxRuntime));
  const tools: unknown[] = [];
  await selectiveSandboxExtension({ on: () => undefined, registerCommand: () => undefined, registerTool: (tool: unknown) => { tools.push(tool); } } as never);
  const write = tools.find((tool: any) => tool.name === "write") as any;
  await assert.rejects(write.execute("no-ui", { path: "/var/pi-selective-denied/file.txt", content: "no" }, new AbortController().signal, () => {}));
});

test("an explicitly false macOS SDK monitor flag forces all tools off and blocks on", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-selective-monitor-off-"));
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  process.env.PI_CODING_AGENT_DIR = base;
  Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
  t.after(async () => {
    Object.defineProperty(process, "platform", platform);
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    await rm(base, { recursive: true, force: true });
  });
  await mkdir(join(base, "pi-selective-sandbox"));
  await writeFile(join(base, "pi-selective-sandbox", "config.json"), JSON.stringify({
    filesystem: { disabledDefaultProfiles: DEFAULT_WRITE_PROFILES }
  }));
  let failInitialization = false;
  t.mock.method(SandboxManager, "initialize", async () => {
    if (failInitialization) throw new Error("SDK startup unavailable for this test");
  });
  const actualInitialize = AnthropicSandboxRuntime.initialize.bind(AnthropicSandboxRuntime);
  const initialize = t.mock.method(AnthropicSandboxRuntime, "initialize", (settings: Parameters<typeof actualInitialize>[0]) => actualInitialize(settings, false));
  const stderr = t.mock.method(console, "warn", () => {});
  for (const scenario of [{ hasUI: true, failure: false }, { hasUI: false, failure: false }, { hasUI: true, failure: true }, { hasUI: false, failure: true }]) {
    const hasUI = scenario.hasUI;
    failInitialization = scenario.failure;
    const initializations = initialize.mock.callCount(), warnings = stderr.mock.callCount();
    const tools = new Map<string, ToolDefinition>();
    const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
    await selectiveSandboxExtension({
      on: () => undefined,
      registerCommand: (name: string, command: Omit<RegisteredCommand, "name" | "sourceInfo">) => { commands.set(name, command); },
      registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); }
    } as never);
    const notices: { message: string; level: string }[] = [];
    const context = { cwd: process.cwd(), hasUI, ui: { notify: (message: string, level: string) => { notices.push({ message, level }); } } } as never;
    const signal = new AbortController().signal;
    const execute = (name: string, params: unknown) => tools.get(name)!.execute(name, params, signal, () => {}, context);
    const target = join(base, "file.txt");
    // Native calls can arrive together before bash initializes anything.
    await Promise.all([
      execute("write", { path: target, content: "before" }),
      execute("write", { path: join(base, "parallel.txt"), content: "parallel" })
    ]);
    await execute("edit", { path: target, edits: [{ oldText: "before", newText: "after" }] });
    assert.equal(await readFile(target, "utf8"), "after");
    const output = await execute("bash", { command: "printf monitor-disabled" });
    assert.match(JSON.stringify(output.content), /monitor-disabled/);
    assert.equal(initialize.mock.callCount(), initializations + 1);
    assert.equal(notices.length, hasUI ? 1 : 0);
    assert.equal(stderr.mock.callCount(), warnings + (hasUI ? 0 : 1));
    const message = hasUI ? notices[0].message : String(stderr.mock.calls.at(-1)!.arguments[0]);
    if (hasUI) assert.equal(notices[0].level, "warning");
    else assert.match(message, /^WARNING:/);
    assert.match(message, /log monitoring.*disabled/i);
    assert.match(message, /Bash runs on the host/);
    assert.match(message, /native mutation approvals are bypassed/);
    await commands.get("selective-sandbox")!.handler("on", context);
    if (hasUI) assert.equal(notices.at(-1)!.level, "warning");
    else assert.equal(stderr.mock.callCount(), warnings + 2);
    await execute("write", { path: target, content: "still off" });
    assert.equal(await readFile(target, "utf8"), "still off");
  }
});

test("on/off toggles all tool boundaries, retains redaction, and resets on reload", async t => {
  const base = await mkdtemp(join(tmpdir(), "pi-selective-off-"));
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = base;
  t.after(async () => {
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    await rm(base, { recursive: true, force: true });
  });
  await mkdir(join(base, "pi-selective-sandbox"));
  await writeFile(join(base, "pi-selective-sandbox", "config.json"), JSON.stringify({
    filesystem: { disabledDefaultProfiles: DEFAULT_WRITE_PROFILES }
  }));
  const initialize = t.mock.method(AnthropicSandboxRuntime, "initialize", async () => {
    throw new Error("Sandbox unavailable for this test");
  });
  const tools = new Map<string, ToolDefinition>();
  const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
  const api = {
    on: () => undefined,
    registerCommand: (name: string, command: Omit<RegisteredCommand, "name" | "sourceInfo">) => { commands.set(name, command); },
    registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); }
  };
  const notices: string[] = [];
  const context = { cwd: process.cwd(), hasUI: false, ui: { notify: (message: string) => { notices.push(message); } } } as never;
  const signal = new AbortController().signal;
  const target = join(base, "file.txt");
  const execute = (name: string, params: unknown, onUpdate: Parameters<ToolDefinition["execute"]>[3] = () => {}) => tools.get(name)!.execute(name, params, signal, onUpdate, context);
  await selectiveSandboxExtension(api as never);
  const command = commands.get("selective-sandbox")!;
  for (const args of ["", "invalid", "off extra"]) {
    await command.handler(args, context);
    assert.equal(notices.at(-1), "Usage: /selective-sandbox on|off");
    await assert.rejects(execute("write", { path: target, content: "before" }), /Permission denied/);
  }
  await assert.rejects(readFile(target));
  await assert.rejects(execute("bash", { command: "printf sandbox-off" }), /host execution was not attempted/);
  assert.equal(initialize.mock.callCount(), 1);

  await command.handler(" off ", context);
  assert.match(notices.at(-1)!, /disabled for bash, write, and edit/);
  await command.handler("off", context);
  await execute("write", { path: target, content: "before" });
  await execute("edit", { path: target, edits: [{ oldText: "before", newText: "after" }] });
  assert.equal(await readFile(target, "utf8"), "after");
  const updates: unknown[] = [];
  const output = await execute("bash", { command: `printf 'ghp_%s' '${"A".repeat(36)}'` }, update => { updates.push(update); });
  assert.match(JSON.stringify(output.content), /REDACTED:GitHub Token/);
  assert.doesNotMatch(JSON.stringify([output, ...updates]), /ghp_A/);
  await assert.rejects(execute("bash", { command: "exit 7" }), /code 7/);
  assert.equal(initialize.mock.callCount(), 1);

  await command.handler("on", context);
  assert.match(notices.at(-1)!, /enabled for bash, write, and edit/);
  await assert.rejects(execute("write", { path: target, content: "no" }), /Permission denied/);
  await assert.rejects(execute("edit", { path: target, edits: [{ oldText: "after", newText: "no" }] }), /Permission denied/);
  await assert.rejects(execute("bash", { command: "printf sandbox-on" }), /host execution was not attempted/);
  assert.equal(await readFile(target, "utf8"), "after");
  await command.handler("off", context);
  await selectiveSandboxExtension(api as never);
  await assert.rejects(execute("write", { path: target, content: "no" }), /Permission denied/);
  await assert.rejects(execute("edit", { path: target, edits: [{ oldText: "after", newText: "no" }] }), /Permission denied/);
  assert.equal(await readFile(target, "utf8"), "after");
});
