import assert from "node:assert/strict";
import test from "node:test";
import { buildSandboxRuntimeConfig, parseLinuxSandboxMode, sandboxInitializationError } from "../runtime-adapter.js";

test("Linux sandbox mode defaults to Ubuntu-compatible", () => {
  assert.equal(parseLinuxSandboxMode(undefined), "ubuntu-compatible");
});

test("strict mode retains Unix-socket isolation", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", linuxSandboxMode: "strict" });
  assert.equal(config.network.allowAllUnixSockets, undefined);
});

test("Ubuntu-compatible mode explicitly disables Unix-socket isolation only", () => {
  const strict = buildSandboxRuntimeConfig({ cwd: "/project", allowRead: ["/read"], allowWrite: ["/write"], linuxSandboxMode: "strict" });
  const compatible = buildSandboxRuntimeConfig({ cwd: "/project", allowRead: ["/read"], allowWrite: ["/write"], linuxSandboxMode: "ubuntu-compatible" });
  assert.equal(compatible.network.allowAllUnixSockets, true);
  assert.deepEqual(compatible.filesystem, strict.filesystem);
  assert.deepEqual(compatible.network.allowedDomains, strict.network.allowedDomains);
  assert.deepEqual(compatible.network.deniedDomains, strict.network.deniedDomains);
});

test("unknown modes fail closed instead of weakening isolation", () => {
  assert.throws(() => parseLinuxSandboxMode("compatible"), /Invalid Linux sandbox mode/);
});

test("known strict nested-userns failure has actionable diagnostics", () => {
  const message = sandboxInitializationError(new Error("apply-seccomp: creating nested user namespace: Operation not permitted"), "strict");
  assert.match(message, /Strict Linux sandbox is unavailable/);
  assert.match(message, /Ubuntu-compatible/);
  assert.match(message, /Host execution was not attempted/);
});
