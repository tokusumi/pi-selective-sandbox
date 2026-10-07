import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";
import { SandboxViolationStore } from "@anthropic-ai/sandbox-runtime";
import { startMacOSSandboxLogMonitor } from "@anthropic-ai/sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";

function monitorFixture(t: TestContext) {
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true
  });
  const spawn = t.mock.method(childProcess, "spawn", () => child);
  syncBuiltinESMExports();
  const store = new SandboxViolationStore();
  const stop = startMacOSSandboxLogMonitor(event => store.addViolation(event), undefined, id => id);
  const args = spawn.mock.calls[0].arguments[1] as string[];
  const suffix = args[args.indexOf("--predicate") + 1].match(/ENDSWITH "([^"]+)"/)![1];
  const tag = (id: string) => `CMD64_${Buffer.from(id).toString("base64")}_END_${suffix}`;
  const event = (id: string, resource: string) => ({
    processID: 0, processImagePath: "/kernel",
    senderImagePath: "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox",
    eventMessage: `Sandbox: git(123) deny(1) file-write-create ${resource}\n${tag(id)}`
  });
  t.after(() => { stop(); spawn.mock.restore(); syncBuiltinESMExports(); });
  return { child, store, spawn, args, event, tag, stop };
}

test("SDK streams complete structured kernel events using the system log binary", t => {
  const { spawn, args } = monitorFixture(t);
  assert.equal(spawn.mock.calls[0].arguments[0], "/usr/bin/log");
  assert.equal(args[0], "stream");
  assert.equal(args[args.indexOf("--style") + 1], "ndjson");
});

test("split and batched SDK records cannot cross-attribute command resources", t => {
  const { child, store, event } = monitorFixture(t);
  const a = JSON.stringify(event("A", "/command-A/file")) + "\n";
  const b = JSON.stringify(event("B", "/command-B/file")) + "\n";
  const cut = a.indexOf("CMD64_");
  child.stdout.emit("data", Buffer.from(a.slice(0, cut)));
  assert.deepEqual(store.getViolations(), []);
  child.stdout.emit("data", Buffer.from(a.slice(cut) + b));
  assert.equal(store.getViolationsForCommand("A").length, 1);
  assert.equal(store.getViolationsForCommand("B").length, 1);
  assert.match(store.getViolationsForCommand("A")[0].line, /\/command-A\/file$/);
  assert.match(store.getViolationsForCommand("B")[0].line, /\/command-B\/file$/);
});

test("SDK preserves UTF-8 paths across arbitrary byte boundaries", t => {
  const { child, store, event } = monitorFixture(t);
  const bytes = Buffer.from(JSON.stringify(event("utf8", "/repo/日本語/file")) + "\n");
  const cut = bytes.indexOf(Buffer.from("日")) + 1;
  child.stdout.emit("data", bytes.subarray(0, cut));
  child.stdout.emit("data", bytes.subarray(cut));
  assert.match(store.getViolationsForCommand("utf8")[0].line, /\/repo\/日本語\/file$/);
});

test("SDK rejects spoofed senders, malformed records, and non-exact tags", t => {
  const { child, store, event } = monitorFixture(t);
  const valid = event("A", "/repo/file");
  const records = [
    { ...valid, processID: 123, processImagePath: "/usr/bin/logger" },
    { ...valid, senderImagePath: "/untrusted/Sandbox" },
    { ...valid, eventMessage: valid.eventMessage.replace("deny(1)", "allow(1)") },
    { ...valid, eventMessage: valid.eventMessage + "-other" },
    { ...valid, eventMessage: valid.eventMessage + "\n" },
    { ...valid, eventMessage: valid.eventMessage.replace("CMD64_QQ==", "CMD64_Q===") }
  ];
  child.stdout.emit("data", Buffer.from("Filtering the log data\n{malformed}\n" + records.map(r => JSON.stringify(r)).join("\n") + "\n"));
  assert.deepEqual(store.getViolations(), []);
  child.stdout.emit("data", Buffer.from(JSON.stringify(valid) + "\n"));
  assert.equal(store.getViolationsForCommand("A").length, 1);
});

test("SDK bounds incomplete records and recovers at the next record boundary", t => {
  const { child, store, event } = monitorFixture(t);
  child.stdout.emit("data", Buffer.from("x".repeat(1024 * 1024 + 1)));
  child.stdout.emit("data", Buffer.from("remaining oversized record\n" + JSON.stringify(event("A", "/repo/file")) + "\n"));
  assert.equal(store.getViolationsForCommand("A").length, 1);
});

test("stopping SDK monitoring stops event delivery", t => {
  const { child, store, event, stop } = monitorFixture(t);
  stop();
  child.stdout.emit("data", Buffer.from(JSON.stringify(event("A", "/repo/file")) + "\n"));
  assert.deepEqual(store.getViolations(), []);
});

test("SDK keeps raw resources separate from safe presentation text", () => {
  const store = new SandboxViolationStore();
  const raw = "git(123) deny(1) file-write-create /repo<a>/file";
  store.addViolation({ line: raw, encodedCommand: Buffer.from("path").toString("base64"), timestamp: new Date() });
  const event = store.getViolationsForCommand("path")[0];
  assert.equal(event.rawLine, raw);
  assert.equal(event.line, raw.replace(/[<>]/g, ""));
});
