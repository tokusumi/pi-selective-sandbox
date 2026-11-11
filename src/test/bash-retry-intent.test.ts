import assert from "node:assert/strict";
import test from "node:test";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import selectiveSandboxExtension from "../pi-extension.js";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import type { CommandResult, SandboxRuntime } from "../types.js";
import { commandOutcomeFixtures } from "./command-outcome-fixtures.js";

async function fixture(t: test.TestContext) {
  const root = await mkdtemp(join(tmpdir(), "pi-bash-retry-intent-"));
  const environment = Object.fromEntries(["PI_CODING_AGENT_DIR", "PI_SELECTIVE_SANDBOX_SESSION_AUDIT", "PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS"].map(key => [key, process.env[key]]));
  const handlers = new Map<string, (...args: any[]) => any>();
  process.env.PI_CODING_AGENT_DIR = root;
  delete process.env.PI_SELECTIVE_SANDBOX_SESSION_AUDIT;
  delete process.env.PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS;
  t.after(async () => {
    await handlers.get("session_shutdown")?.();
    for (const [key, value] of Object.entries(environment)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  });
  let current: CommandResult = commandOutcomeFixtures[0].result;
  const spawned: string[] = [], wrapped: string[] = [], titles: string[] = [], forgotten: string[] = [];
  const answers: string[] = [], sessionEvents: unknown[] = [];
  const runtime: SandboxRuntime & { logMonitorEnabled: boolean; dispose(): Promise<void> } = {
    logMonitorEnabled: true, dispose: async () => {},
    wrap: async command => { wrapped.push(command); return "fixture wrapped command"; },
    getViolationsForCommand: () => [{ kind: "network", resource: "unknown", message: "private denial fixture" }],
    forgetCommand: commandId => { forgotten.push(commandId); }
  };
  t.mock.method(AnthropicSandboxRuntime, "initialize", async () => runtime as AnthropicSandboxRuntime);
  // Exercise the registered bash tool and executor with fixture streams/exits,
  // never spawning the command under test (gh, sandbox-exec or host replay).
  // Extension setup retains its ordinary read-only Git metadata discovery.
  const spawn = t.mock.method(childProcess, "spawn", (...args: unknown[]) => {
    const argv = args[1] as string[];
    spawned.push(argv.at(-1)!);
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), signalCode: null });
    queueMicrotask(() => {
      child.stdout.end(current.stdout);
      child.stderr.end(current.stderr);
      child.emit("exit", current.exitCode, null);
      child.emit("close", current.exitCode, null);
    });
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => { spawn.mock.restore(); syncBuiltinESMExports(); });
  const tools = new Map<string, ToolDefinition>();
  await selectiveSandboxExtension({
    on: (event: string, handler: (...args: any[]) => any) => { handlers.set(event, handler); }, registerCommand: () => {},
    appendEntry: (_type: string, data: unknown) => { sessionEvents.push(data); },
    registerTool: (tool: ToolDefinition) => { tools.set(tool.name, tool); }
  } as never, { loadSubagentApi: async () => undefined });
  const context = { cwd: process.cwd(), hasUI: true, sessionManager: { getSessionId: () => "fixture-session" },
    ui: { select: async (title: string, choices: string[]) => {
      titles.push(title);
      const answer = answers.shift();
      assert.ok(answer === undefined || choices.includes(answer));
      return answer;
    } } };
  await handlers.get("session_start")!({}, context);
  return {
    tool: tools.get("bash")!, spawned, wrapped, titles, answers, forgotten, sessionEvents,
    run: (result: CommandResult, retryOnSandboxDenial?: unknown) => {
      current = result;
      return tools.get("bash")!.execute("fixture-call", { command: "opaque application", ...(retryOnSandboxDenial === undefined ? {} : { retryOnSandboxDenial }) },
        new AbortController().signal, () => {}, context as never);
    }
  };
}

test("registered bash exposes a default-off boolean intent and preserves streamed command status", async t => {
  const f = await fixture(t);
  const schema = f.tool.parameters as { properties: Record<string, { type: string }>; required: string[] };
  assert.equal(schema.properties.retryOnSandboxDenial.type, "boolean");
  assert.ok(!schema.required.includes("retryOnSandboxDenial"));
  assert.match(f.tool.description, /Nonzero exits are returned unchanged/);
  assert.ok(f.tool.promptGuidelines?.some(rule => rule.includes("retryOnSandboxDenial")));
  for (const sample of commandOutcomeFixtures) for (const intent of [undefined, false]) {
    const before = f.spawned.length;
    const output = await f.run(sample.result, intent);
    const text = output.content.map(part => part.type === "text" ? part.text : "").join("");
    const structured = output.structuredContent as { exit_code: number; output: string };
    assert.equal(output.isError === true, sample.result.exitCode !== 0);
    assert.equal(structured.exit_code, sample.result.exitCode);
    assert.ok(structured.output.includes(sample.result.stdout));
    assert.ok(structured.output.includes(sample.result.stderr));
    assert.ok(text.includes(sample.result.stdout));
    assert.ok(text.includes(sample.result.stderr));
    assert.deepEqual((output.details as any).selectiveSandbox, {
      disposition: "sandbox", denialObserved: sample.result.exitCode !== 0, retryNotRequested: sample.result.exitCode !== 0
    });
    if (sample.result.exitCode !== 0) assert.match(text, /denial-observed retry-not-requested/);
    assert.doesNotMatch(JSON.stringify(output), /private denial fixture/);
    assert.equal(f.spawned.length, before + 1);
    assert.equal(f.spawned.at(-1), "fixture wrapped command");
    assert.equal(f.titles.length, 0);
  }
  assert.equal(f.forgotten.length, f.spawned.length);
  assert.ok(f.sessionEvents.some((event: any) => event.event === "retry" && event.reason === "not-requested" && event.outcome === "skipped"));
  assert.ok(!f.sessionEvents.some((event: any) => event.event === "provider.start"));
  assert.doesNotMatch(JSON.stringify(f.sessionEvents), /private denial fixture/);
});

test("bash opt-in reaches unchanged explicit host confirmation, and later default calls do not inherit it", async t => {
  const f = await fixture(t);
  // Malformed direct execute() inputs also cannot enable retry; normal Pi
  // schema validation happens before this method in production.
  await f.run(commandOutcomeFixtures[0].result, "true");
  assert.equal(f.titles.length, 0);
  f.answers.push("Run outside sandbox…", "Once", "Deny");
  const denied = await f.run(commandOutcomeFixtures[0].result, true);
  assert.equal((denied.structuredContent as any).exit_code, 8);
  assert.equal(f.spawned.length, 2, "denying exact-command confirmation cannot replay");
  assert.equal((denied.details as any).selectiveSandbox.disposition, "denied");
  f.answers.push("Run outside sandbox…", "Once", "Run on host");
  const requested = await f.run(commandOutcomeFixtures[0].result, true);
  assert.equal((requested.structuredContent as any).exit_code, 8);
  assert.equal(requested.isError, true);
  assert.equal((requested.details as any).selectiveSandbox.disposition, "host");
  assert.equal(f.spawned.length, 4);
  assert.equal(f.spawned.at(-1), "opaque application", "only the explicitly confirmed exact command is passed to the mocked host backend");
  assert.match(f.titles.at(-1)!, /Sandbox protections will not apply/);
  assert.match(f.titles.at(-1)!, /opaque application/);
  const prompts = f.titles.length;
  const last = await f.run(commandOutcomeFixtures[0].result);
  assert.equal((last.details as any).selectiveSandbox.retryNotRequested, true);
  assert.equal(f.titles.length, prompts);
  assert.equal(f.spawned.length, 5);
});
