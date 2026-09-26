import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { StraceViolationObserver } from "../strace-observer.js";
import { runTracedSandbox } from "../strace-runner.js";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "pi-strace-test-"));
  const writable = join(root, "writable");
  const blocked = join(root, "blocked");
  await Promise.all([mkdir(writable), mkdir(blocked)]);
  return { root, writable, blocked, observer: new StraceViolationObserver(writable, { allow: [writable], deny: [] }) };
}

function workload(observer: StraceViolationObserver, lines: string[]) {
  observer.ingest([
    '100 execve("/usr/bin/bwrap", ["bwrap", "--ro-bind"], 0x0) = 0',
    '100 clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = 101',
    '101 execve("/usr/bin/bash", ["bash", "-c", "user command"], 0x0) = 0',
    '101 clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = 102',
    ...lines
  ].join("\n") + "\n");
}

test("bwrap setup EROFS is ignored; Git lock and child EROFS are attributed", async () => {
  const { writable, blocked, observer } = await fixture();
  observer.ingest('100 openat(AT_FDCWD</>, "/newroot/proc/sys", O_WRONLY) = -1 EROFS (Read-only file system)\n');
  workload(observer, [
    '100 openat(AT_FDCWD</>, "/newroot/late-setup", O_WRONLY) = -1 EROFS (Read-only file system)',
    `102 openat(AT_FDCWD<${blocked}>, "${blocked}/repo/.git/index.lock", O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0666) = -1 EROFS (Read-only file system)`,
    `102 openat(AT_FDCWD<${blocked}>, "missing", O_RDONLY) = -1 EROFS (Read-only file system)`,
    `102 openat(AT_FDCWD<${blocked}>, "permission", O_WRONLY) = -1 EACCES (Permission denied)`,
    `102 openat(AT_FDCWD<${writable}>, "allowed", O_WRONLY|O_CREAT, 0666) = -1 EROFS (Read-only file system)`
  ]);
  const violations = await observer.getViolations();
  assert.deepEqual(violations.map(v => v.resource), [join(blocked, "repo/.git")]);
  assert.match(violations[0].message ?? "", /index\.lock/);
});

test("relative dirfd, openat2 flags, and two-path mutations use the shared write policy", async () => {
  const { writable, blocked, observer } = await fixture();
  await Promise.all(["open", "open2", "rename", "link"].map(name => mkdir(join(blocked, name))));
  workload(observer, [
    `102 openat(AT_FDCWD<${join(blocked, "open")}>, "relative", O_WRONLY|O_CREAT, 0666) = -1 EROFS (Read-only file system)`,
    `102 openat2(4<${join(blocked, "open2")}>, "new", {flags=O_RDWR|O_CREAT, mode=0644, resolve=0}, 24) = -1 EROFS (Read-only file system)`,
    `102 renameat(AT_FDCWD<${writable}>, "old", AT_FDCWD<${join(blocked, "rename")}>, "new-name") = -1 EROFS (Read-only file system)`,
    `102 linkat(AT_FDCWD<${join(blocked, "link")}>, "source", AT_FDCWD<${writable}>, "dest", 0) = -1 EROFS (Read-only file system)`,
    '102 mkdirat(AT_FDCWD, "unresolved", 0777) = -1 EROFS (Read-only file system)'
  ]);
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [
    join(blocked, "open"), join(blocked, "open2"), join(blocked, "rename"), join(blocked, "link")
  ]);
});

test("ordinary failures and trace lines without a confirmed workload yield no violations", async () => {
  const { blocked, observer } = await fixture();
  observer.ingest(`100 openat(AT_FDCWD<${blocked}>, "x", O_WRONLY) = -1 EROFS (Read-only file system)\n`);
  workload(observer, [
    `102 openat(AT_FDCWD<${blocked}>, "x", O_RDONLY) = -1 EROFS (Read-only file system)`,
    `102 openat(AT_FDCWD<${blocked}>, "x", O_WRONLY) = -1 ENOENT (No such file or directory)`,
    `102 unlinkat(AT_FDCWD<${blocked}>, "x", 0) = -1 EPERM (Operation not permitted)`,
    `102 openat(AT_FDCWD<${blocked}>, "x", O_WRONLY <unfinished ...>`
  ]);
  assert.deepEqual(await observer.getViolations(), []);
});

test("unprefixed initial tracee is followed through bwrap and shell exec", async () => {
  const { blocked, observer } = await fixture();
  observer.ingest([
    'execve("/usr/bin/bash", ["bash", "-c", "exec bwrap"], 0x0) = 0',
    'execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0',
    `openat(AT_FDCWD</>, "/newroot/setup", O_WRONLY) = -1 EROFS (Read-only file system)`,
    'clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = 201',
    '[pid 201] execve("/usr/bin/bash", ["bash", "-c", "touch"], 0x0) = 0',
    `[pid 201] openat(AT_FDCWD<${blocked}>, "probe", O_WRONLY|O_CREAT, 0666) = -1 EROFS (Read-only file system)`
  ].join("\n") + "\n");
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [blocked]);
});

test("legacy relative paths follow workload cwd changes", async () => {
  const { blocked, observer } = await fixture();
  await mkdir(join(blocked, "rename"));
  workload(observer, [
    `101 chdir("${blocked}") = 0`,
    '101 clone(flags=SIGCHLD) = 103',
    '103 mkdir("directory", 0777) = -1 EROFS (Read-only file system)',
    '103 rename("old", "rename/new") = -1 EROFS (Read-only file system)',
    '103 fchdir(4</unresolvable>) = -1 EBADF (Bad file descriptor)'
  ]);
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [
    blocked, join(blocked, "rename")
  ]);
});

test("octal-escaped UTF-8 paths resolve to the intended resource", async () => {
  const { blocked, observer } = await fixture();
  workload(observer, [
    `102 mkdirat(AT_FDCWD<${blocked}>, "caf\\303\\251", 0777) = -1 EROFS (Read-only file system)`
  ]);
  const violations = await observer.getViolations();
  assert.deepEqual(violations.map(v => v.resource), [blocked]);
  assert.match(violations[0].message ?? "", /café/);
});

test("existing files stay exact and deny carve-outs stay blocked from widening", async () => {
  const { writable, blocked } = await fixture();
  await writeFile(join(blocked, "existing"), "x");
  const observer = new StraceViolationObserver(writable, { allow: [writable], deny: [] });
  workload(observer, [
    `102 openat(AT_FDCWD<${blocked}>, "existing", O_RDWR|O_CREAT, 0666) = -1 EROFS (Read-only file system)`
  ]);
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [join(blocked, "existing")]);

  const secret = join(blocked, "secret");
  await mkdir(secret);
  const carved = new StraceViolationObserver(writable, { allow: [blocked, writable], deny: [secret] });
  workload(carved, [
    `102 unlinkat(AT_FDCWD<${secret}>, "file", 0) = -1 EROFS (Read-only file system)`
  ]);
  assert.deepEqual((await carved.getViolations()).map(v => v.resource), [join(secret, "file")]);
});

test("directory-entry paths do not follow the final symlink", async () => {
  const { writable, blocked } = await fixture();
  const link = join(blocked, "link");
  await symlink(join(writable, "target"), link);
  const observer = new StraceViolationObserver(writable, { allow: [writable], deny: [] });
  workload(observer, [
    `102 unlinkat(AT_FDCWD<${blocked}>, "link", 0) = -1 EROFS (Read-only file system)`
  ]);
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [blocked]);
});

test("interleaved unfinished and resumed syscalls retain their path and errno", async () => {
  const { blocked, observer } = await fixture();
  observer.ingest([
    '100 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0',
    '100 clone(flags=SIGCHLD) = 101',
    '[pid 101] execve("/usr/bin/bash", ["bash"], 0x0 <unfinished ...>',
    '[pid 102] openat(AT_FDCWD</>, "/newroot/proc", O_WRONLY) = -1 EROFS (Read-only file system)',
    '[pid 101] <... execve resumed>) = 0',
    `[pid 101] unlinkat(AT_FDCWD<${blocked}>, "victim", 0 <unfinished ...>`,
    '[pid 102] openat(AT_FDCWD</>, "/newroot/sys", O_WRONLY) = -1 EROFS (Read-only file system)',
    '[pid 101] <... unlinkat resumed>) = -1 EROFS (Read-only file system)'
  ].join("\n") + "\n");
  assert.deepEqual((await observer.getViolations()).map(v => v.resource), [blocked]);
});

test("trace channel stays separate from command output", async () => {
  const { root } = await fixture();
  const bin = join(root, "bin");
  await mkdir(bin);
  await writeFile(join(bin, "strace"), '#!/bin/sh\nprintf "trace event\\n" >&2\nprintf "user output\\n"\nprintf "forged trace\\n"\n', { mode: 0o755 });
  let output = "", trace = "";
  const result = await runTracedSandbox("true", root, {
    onData: chunk => { output += chunk.toString(); },
    env: process.env
  }, chunk => { trace += chunk.toString(); }, join(bin, "strace"));
  assert.equal(result.exitCode, 0);
  assert.equal(output, "user output\nforged trace\n");
  assert.equal(trace, "trace event\n");
});
