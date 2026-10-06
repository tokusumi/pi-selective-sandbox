import assert from "node:assert/strict";
import test from "node:test";
import { isMacOSCapabilityViolation, macOSCommandObservation, macOSViolationLines } from "../macos-observer.js";

const tag = "CMD64_Z2l0LWFkZA==_END__session_SBX";
const line = "git(123) deny(1) file-write-create /repo with spaces/.git/index.lock";
const event = (message = `Sandbox: ${line}\n${tag}`) => ({
  processID: 0, processImagePath: "/kernel",
  senderImagePath: "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox", eventMessage: message
});

test("Seatbelt snapshot requires the exact command tag and kernel sender", () => {
  const output = [
    event(), event(), { count: 2, finished: 1 },
    event(`Sandbox: ${line}\n${tag}-other`),
    { ...event(), processID: 123, processImagePath: "/usr/bin/logger" },
    { ...event(), senderImagePath: "/untrusted/Sandbox" }
  ].map(record => JSON.stringify(record)).join("\n");
  assert.deepEqual(macOSViolationLines(output, tag), [line]);
});

test("sysctl and Mach noise do not become approval capabilities", () => {
  const sysctl = "git(123) deny(1) sysctl-read kern.iossupportversion";
  const mach = "git(123) deny(1) mach-lookup com.apple.diagnosticd";
  assert.equal(isMacOSCapabilityViolation(sysctl), false);
  assert.equal(isMacOSCapabilityViolation(mach), false);
  assert.equal(isMacOSCapabilityViolation(line), true);
  const output = [event(`Sandbox: ${sysctl}\n${tag}`), event(`Sandbox: ${mach}\n${tag}`)].map(record => JSON.stringify(record)).join("\n");
  assert.deepEqual(macOSViolationLines(output, tag), []);
});

test("invalid observation output is an explicit failure, not an empty success", () => {
  assert.throws(() => macOSViolationLines("{invalid", tag), /violation log is malformed/);
});

test("missing or ambiguous attribution fails closed; repeated profile tags are valid", () => {
  assert.deepEqual(macOSCommandObservation(`${tag} ${tag}`, "git-add", 123), { tag, since: 123 });
  assert.throws(() => macOSCommandObservation("no tag", "git-add", 123), /attribution is unavailable/);
  assert.throws(() => macOSCommandObservation(tag, "other-call", 123), /attribution is unavailable/);
  const other = tag.replace("_session_SBX", "_other_SBX");
  assert.throws(() => macOSCommandObservation(`${tag} ${other}`, "git-add", 123), /attribution is unavailable/);
  const longId = "x".repeat(100) + "tail";
  const truncatedTag = `CMD64_${Buffer.from(longId.slice(0, 100)).toString("base64")}_END__session_SBX`;
  assert.throws(() => macOSCommandObservation(truncatedTag, longId, 123), /attribution is unavailable/);
});
