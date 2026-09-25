import assert from "node:assert/strict";
import test from "node:test";
import selectiveSandboxExtension, { emitExecutorOutput, redactToolResult } from "../pi-extension.js";

test("Pi entrypoint registers a replacement bash tool", async () => {
  const tools: { name: string }[] = [];
  const events: string[] = [];
  await selectiveSandboxExtension({
    on: (event: string) => { events.push(event); },
    registerTool: (value: { name: string }) => { tools.push(value); }
  } as never);
  assert.deepEqual(tools.map(tool => tool.name), ["bash", "write", "edit"]);
  assert.deepEqual(events, ["session_shutdown"]);
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

test("write fails closed without an interactive approval UI", async () => {
  const tools: unknown[] = [];
  await selectiveSandboxExtension({ on: () => undefined, registerTool: (tool: unknown) => { tools.push(tool); } } as never);
  const write = tools.find((tool: any) => tool.name === "write") as any;
  await assert.rejects(write.execute("no-ui", { path: "/var/pi-selective-denied/file.txt", content: "no" }, new AbortController().signal, () => {}));
});
