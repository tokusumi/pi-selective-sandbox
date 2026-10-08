import assert from "node:assert/strict";
import test from "node:test";
import { SandboxManager, SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";

test("disposing one foreground child preserves sibling SDK state and violation attribution", async t => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "linux" });
  t.after(() => Object.defineProperty(process, "platform", platform));
  t.mock.method(SandboxManager, "initialize", async () => {});
  const reset = t.mock.method(SandboxManager, "reset", async () => {});
  const store = new SandboxViolationStore();
  t.mock.method(SandboxManager, "getSandboxViolationStore", () => store);
  const ids: string[] = [];
  t.mock.method(SandboxManager, "wrapWithSandbox", async (command: string, _shell: unknown, _config: unknown, _signal: unknown, context: { commandId: string }) => {
    ids.push(context.commandId);
    store.addViolation({ line: `deny file-write-create /${context.commandId.split(":")[0]}/blocked`, encodedCommand: Buffer.from(context.commandId).toString("base64"), timestamp: new Date() });
    return command;
  });
  const parent = await AnthropicSandboxRuntime.initialize({ cwd: "/parent", writePolicy: { allow: ["/parent"], deny: [] }, commandNamespace: "parent" });
  const child = await AnthropicSandboxRuntime.initialize({ cwd: "/child", writePolicy: { allow: ["/child"], deny: [] }, commandNamespace: "child" });
  t.after(async () => { await child.dispose(); await parent.dispose(); });
  await parent.wrap("probe", { commandId: "same-id", commandText: "probe" });
  await child.wrap("probe", { commandId: "same-id", commandText: "probe" });
  assert.deepEqual(ids, ["parent:same-id", "child:same-id"]);
  assert.equal((await parent.getViolationsForCommand("same-id"))[0].resource, "/parent/blocked");
  assert.equal((await child.getViolationsForCommand("same-id"))[0].resource, "/child/blocked");
  await child.dispose();
  assert.equal(reset.mock.callCount(), 0);
  await parent.wrap("still available", { commandId: "next", commandText: "still available" });
  await assert.rejects(child.wrap("no", { commandId: "late", commandText: "no" }), /disposed/);
  await parent.dispose();
  assert.equal(reset.mock.callCount(), 1);
});
