import assert from "node:assert/strict";
import test from "node:test";
import { buildSandboxRuntimeConfig, isUbuntu24Release, sandboxInitializationError } from "../runtime-adapter.js";

test("Ubuntu 24.x release detection is narrow", () => {
  assert.equal(isUbuntu24Release('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'), true);
  assert.equal(isUbuntu24Release('ID=ubuntu\nVERSION_ID="24.10"\n'), true);
  assert.equal(isUbuntu24Release('ID=ubuntu\nVERSION_ID="22.04"\n'), false);
  assert.equal(isUbuntu24Release('ID=debian\nVERSION_ID="24"\n'), false);
});

test("normal platforms retain Unix-socket isolation", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/project"], deny: [] } });
  assert.equal(config.network.allowAllUnixSockets, undefined);
});

test("Ubuntu 24.x exception disables only Unix-socket isolation", () => {
  const settings = { cwd: "/project", allowRead: ["/read"], writePolicy: { allow: ["/write"], deny: ["/write/secret"] } };
  const normal = buildSandboxRuntimeConfig(settings);
  const ubuntu24 = buildSandboxRuntimeConfig(settings, true);
  assert.equal(ubuntu24.network.allowAllUnixSockets, true);
  assert.deepEqual(ubuntu24.filesystem, normal.filesystem);
  assert.deepEqual(ubuntu24.network.allowedDomains, normal.network.allowedDomains);
  assert.deepEqual(ubuntu24.network.deniedDomains, normal.network.deniedDomains);
});

test("resolved write policy preserves deny roots", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/write"], deny: ["/write/secret"] } });
  assert.deepEqual(config.filesystem.allowWrite, ["/write"]);
  assert.deepEqual(config.filesystem.denyWrite, ["/write/secret"]);
});

test("nested-userns failure has actionable fail-closed diagnostics", () => {
  const message = sandboxInitializationError(new Error("apply-seccomp: creating nested user namespace: Operation not permitted"));
  assert.match(message, /nested user namespace/);
  assert.match(message, /Host execution was not attempted/);
});

test("unavailable strace is reported without offering host execution", () => {
  const message = sandboxInitializationError(new Error("Ubuntu 24 filesystem observation requires working strace."));
  assert.match(message, /strace could not trace commands/);
  assert.match(message, /Host execution was not attempted/);
});
