import assert from "node:assert/strict";
import test from "node:test";
import { buildSandboxRuntimeConfig, isUbuntuRelease, sandboxInitializationError } from "../runtime-adapter.js";

test("Ubuntu release detection accepts all versions and excludes other distributions", () => {
  assert.equal(isUbuntuRelease('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\nVERSION_ID="24.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\nVERSION_ID="26.04"\n'), true);
  assert.equal(isUbuntuRelease('ID=ubuntu\n'), true);
  assert.equal(isUbuntuRelease('ID=debian\nVERSION_ID="24"\n'), false);
  assert.equal(isUbuntuRelease('ID=linuxmint\nID_LIKE="ubuntu debian"\n'), false);
});

test("normal platforms retain Unix-socket isolation", () => {
  const config = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/project"], deny: [] } });
  assert.equal(config.network.allowAllUnixSockets, undefined);
});

test("Ubuntu execution path disables only Unix-socket isolation", () => {
  const settings = { cwd: "/project", allowRead: ["/read"], writePolicy: { allow: ["/write"], deny: ["/write/secret"] } };
  const normal = buildSandboxRuntimeConfig(settings);
  const ubuntu = buildSandboxRuntimeConfig(settings, true);
  assert.equal(ubuntu.network.allowAllUnixSockets, true);
  assert.deepEqual(ubuntu.filesystem, normal.filesystem);
  assert.deepEqual(ubuntu.network.allowedDomains, normal.network.allowedDomains);
  assert.deepEqual(ubuntu.network.deniedDomains, normal.network.deniedDomains);
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
  const message = sandboxInitializationError(new Error("Ubuntu filesystem observation requires working strace."));
  assert.match(message, /strace could not trace commands/);
  assert.match(message, /Host execution was not attempted/);
});
