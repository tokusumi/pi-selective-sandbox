import assert from "node:assert/strict";
import test from "node:test";
import selectiveSandboxExtension from "../pi-extension.js";

test("Pi entrypoint registers a replacement bash tool", async () => {
  let tool: { name: string } | undefined;
  const events: string[] = [];
  await selectiveSandboxExtension({
    on: (event: string) => { events.push(event); },
    registerTool: (value: { name: string }) => { tool = value; }
  } as never);
  assert.equal(tool?.name, "bash");
  assert.deepEqual(events, ["session_shutdown"]);
});

test("package manifest exposes the compiled Pi extension", async () => {
  const manifest = await import("../../package.json", { with: { type: "json" } });
  assert.deepEqual(manifest.default.pi.extensions, ["./dist/pi-extension.js"]);
  assert.equal("private" in manifest.default, false);
});
