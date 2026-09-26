import { dirname, isAbsolute, resolve } from "node:path";
import { lstat } from "node:fs/promises";
import { MutationBoundary } from "./filesystem-boundary.js";
import type { WritePolicy } from "./filesystem-policy.js";
import type { SandboxViolation } from "./types.js";

// Mirrors observe_calls[] and the open flag check in sandbox-runtime's
// vendor/seccomp-src/apply-seccomp.c (sandbox-runtime 0.0.76).
const commonCalls = [
  "openat", "openat2", "unlinkat", "mkdirat", "mknodat", "symlinkat",
  "linkat", "renameat", "renameat2", "fchmodat", "fchmodat2", "fchownat", "utimensat"
] as const;
const x64Calls = [
  "open", "creat", "unlink", "rmdir", "rename", "link", "symlink",
  "mkdir", "mknod", "truncate", "chmod", "chown", "lchown", "utime", "utimes"
] as const;
const observedCalls: readonly string[] = [...commonCalls, ...(process.arch === "x64" ? x64Calls : [])];
export const STRACE_BINARY = "/usr/bin/strace";

export const STRACE_ARGS = [
  "-f", "--seccomp-bpf", "--decode-pids=pidns", "-qq", "-yy", "-s", "4096",
  // Successful exec/fork calls identify the workload after bwrap setup. -Z
  // would hide those calls, so failure filtering happens in this parser.
  "-e", `trace=execve,execveat,clone,clone3,fork,vfork,chdir,fchdir,${observedCalls.join(",")}`
] as const;

type GrantScope = "path" | "nofollow-path" | "parent" | "parent-if-missing";
type Attempt = { syscall: string; path: string; errno: "EROFS"; grantScope: GrantScope };
const writeFlags = /(?:^|\W)(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)(?:$|\W)/;
const processCalls = new Set(["clone", "clone3", "fork", "vfork"]);
const directoryEntryCalls = new Set([
  "unlinkat", "mkdirat", "mknodat", "symlinkat", "linkat", "renameat", "renameat2",
  "unlink", "rmdir", "rename", "link", "symlink", "mkdir", "mknod"
]);
const nofollowMetadataCalls = new Set(["fchmodat", "fchmodat2", "fchownat", "utimensat"]);

function argsOf(input: string): string[] {
  const args: string[] = [];
  let start = 0, depth = 0, quoted = false, escaped = false;
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (quoted) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) { args.push(input.slice(start, i).trim()); start = i + 1; }
  }
  args.push(input.slice(start).trim());
  return args;
}

function quotedPath(arg: string): string | undefined {
  if (!arg.startsWith('"')) return undefined;
  const end = arg.match(/^"((?:\\.|[^"\\])*)"/);
  if (!end || arg.slice(end[0].length).startsWith("...")) return undefined;
  const bytes: number[] = [];
  const encoded = end[1];
  for (let i = 0; i < encoded.length; i++) {
    const c = encoded[i];
    if (c !== "\\") {
      const char = String.fromCodePoint(encoded.codePointAt(i)!);
      bytes.push(...Buffer.from(char));
      i += char.length - 1;
      continue;
    }
    const rest = encoded.slice(i + 1);
    const octal = rest.match(/^[0-7]{3}/);
    const hex = rest.match(/^x[0-9a-fA-F]{2}/);
    if (octal) { bytes.push(parseInt(octal[0], 8)); i += 3; }
    else if (hex) { bytes.push(parseInt(hex[0].slice(1), 16)); i += 3; }
    else {
      const escaped = rest[0];
      if (!escaped) return undefined;
      const decoded = ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v" } as Record<string, string>)[escaped] ?? escaped;
      bytes.push(...Buffer.from(decoded));
      i++;
    }
  }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes)); }
  catch { return undefined; }
}

function dirfdPath(arg: string): string | undefined {
  const match = arg.match(/^[^<]*<([^<>]+)>$/);
  return match?.[1]?.startsWith("/") ? match[1] : undefined;
}

function target(pathArg: string | undefined, dirfd?: string, cwd?: string): string | undefined {
  const path = pathArg === undefined ? undefined : quotedPath(pathArg);
  if (!path) return undefined;
  if (isAbsolute(path)) return resolve(path);
  const base = dirfd === undefined || dirfd === "AT_FDCWD" ? cwd : dirfdPath(dirfd);
  return base ? resolve(base, path) : undefined;
}

function writeTargets(syscall: string, args: string[], cwd?: string): { path: string; grantScope: GrantScope }[] {
  const paths: (string | undefined)[] = [];
  if (syscall === "openat" || syscall === "openat2") {
    if (!writeFlags.test(args[2] ?? "")) return [];
    paths.push(target(args[1], args[0], cwd));
  } else if (syscall === "open") {
    if (!writeFlags.test(args[1] ?? "")) return [];
    paths.push(target(args[0], undefined, cwd));
  } else if (syscall === "renameat" || syscall === "renameat2" || syscall === "linkat") {
    paths.push(target(args[1], args[0], cwd), target(args[3], args[2], cwd));
  } else if (syscall === "rename" || syscall === "link") {
    paths.push(target(args[0], undefined, cwd), target(args[1], undefined, cwd));
  } else if (syscall === "symlinkat") {
    paths.push(target(args[2], args[1], cwd));
  } else if (syscall === "symlink") {
    paths.push(target(args[1], undefined, cwd));
  } else if (syscall.endsWith("at") || syscall === "fchmodat2") {
    paths.push(target(args[1], args[0], cwd));
  } else {
    paths.push(target(args[0], undefined, cwd));
  }
  const grantScope: GrantScope = directoryEntryCalls.has(syscall) ? "parent"
    : syscall === "lchown" || (nofollowMetadataCalls.has(syscall) && args.some(arg => /(?:^|\W)AT_SYMLINK_NOFOLLOW(?:$|\W)/.test(arg))) ? "nofollow-path"
    : syscall === "creat" || ((syscall === "open" || syscall === "openat" || syscall === "openat2") && /(?:^|\W)O_CREAT(?:$|\W)/.test(args[syscall === "open" ? 1 : 2] ?? ""))
      ? "parent-if-missing" : "path";
  return paths.filter((path): path is string => path !== undefined).map(path => ({ path, grantScope }));
}

/** Parses the parent-owned strace pipe, excluding bwrap's setup phase. */
export class StraceViolationObserver {
  private pending = "";
  private bwrapStarted = false;
  private readonly workloadPids = new Set<number>();
  private readonly cwdByPid = new Map<number, string>();
  private readonly unfinished = new Map<number, { syscall: string; head: string }>();
  private readonly attempts: Attempt[] = [];
  private readonly seenAttempts = new Set<string>();

  constructor(private readonly cwd: string, private readonly policy: WritePolicy) {}

  ingest(chunk: Buffer | string): void {
    const input = this.pending + chunk.toString();
    let start = 0, newline: number;
    while ((newline = input.indexOf("\n", start)) >= 0) {
      this.line(input.slice(start, newline));
      start = newline + 1;
    }
    this.pending = input.slice(start);
    if (this.pending.length > 32768) this.pending = "";
  }

  private line(raw: string): void {
    const prefixed = raw.match(/^\s*(?:\[pid\s+(\d+)\]|(\d+))\s+(.+)$/);
    // Without -o, strace omits a PID on the initial tracee. PID 0 represents
    // that one process until descendants receive explicit prefixes.
    const pid = prefixed ? Number(prefixed[1] ?? prefixed[2]) : 0;
    let body = prefixed ? prefixed[3] : raw;
    const start = body.match(/^([a-z0-9_]+)\(.*<unfinished \.\.\.>$/);
    if (start) {
      if (this.unfinished.size >= 1024) this.unfinished.clear();
      this.unfinished.set(pid, { syscall: start[1], head: body.slice(0, body.indexOf("<unfinished ...>")) });
      return;
    }
    const resumed = body.match(/^<\.\.\. ([a-z0-9_]+) resumed>(.*)$/);
    if (resumed) {
      const previous = this.unfinished.get(pid);
      this.unfinished.delete(pid);
      if (!previous || previous.syscall !== resumed[1]) return;
      body = previous.head + resumed[2];
    }
    const call = body.match(/^([a-z0-9_]+)\((.*)\)\s+=\s+(.+)$/);
    if (!call) return;
    const [, syscall, input, result] = call;
    if (processCalls.has(syscall)) {
      const child = result.match(/^(\d+)\b/);
      if (child) {
        if (this.workloadPids.has(pid)) {
          // Inside bwrap's PID namespace, clone returns an inner PID while
          // strace prefixes later syscalls with its own outer-namespace PID.
          const tracedPid = Number(result.match(/\/\* (\d+) in strace's PID NS \*\//)?.[1] ?? child[1]);
          this.workloadPids.add(tracedPid);
          const cwd = this.cwdByPid.get(pid);
          if (cwd) this.cwdByPid.set(tracedPid, cwd);
        }
      }
      return;
    }
    if (syscall === "execve" || syscall === "execveat") {
      if (!result.startsWith("0")) return;
      const args = argsOf(input);
      const executable = quotedPath(args[syscall === "execve" ? 0 : 1] ?? "");
      if (!executable) return;
      if (/(?:^|\/)bwrap$/.test(executable)) this.bwrapStarted = true;
      else if (this.bwrapStarted && /(?:^|\/)bash$/.test(executable)) {
        this.workloadPids.add(pid);
        if (!this.cwdByPid.has(pid)) this.cwdByPid.set(pid, this.cwd);
      }
      return;
    }
    const isWorkloadProcess = this.workloadPids.has(pid);
    if (isWorkloadProcess && result.startsWith("0") && syscall === "chdir") {
      const next = target(argsOf(input)[0], undefined, this.cwdByPid.get(pid));
      if (next) this.cwdByPid.set(pid, next);
      return;
    }
    if (isWorkloadProcess && result.startsWith("0") && syscall === "fchdir") {
      const next = dirfdPath(argsOf(input)[0] ?? "");
      if (next) this.cwdByPid.set(pid, next);
      return;
    }
    if (!isWorkloadProcess || !observedCalls.includes(syscall)) return;
    if (!/^-1 EROFS\b/.test(result)) return;
    for (const { path, grantScope } of writeTargets(syscall, argsOf(input), this.cwdByPid.get(pid))) {
      if (path === "/newroot" || path.startsWith("/newroot/")) continue;
      if (this.attempts.length >= 256) break;
      const key = JSON.stringify([path, grantScope]);
      if (this.seenAttempts.has(key)) continue;
      this.seenAttempts.add(key);
      this.attempts.push({ syscall, path, errno: "EROFS", grantScope });
    }
  }

  async getViolations(): Promise<readonly SandboxViolation[]> {
    let boundary: MutationBoundary;
    try { boundary = await MutationBoundary.create(this.cwd, this.policy); }
    catch { return []; }
    const violations: SandboxViolation[] = [];
    const seen = new Set<string>();
    for (const attempt of this.attempts) {
      try {
        const target = attempt.grantScope === "parent" || attempt.grantScope === "nofollow-path"
          ? await boundary.resolveEntry(attempt.path) : await boundary.resolve(attempt.path);
        if (target.allowed) continue;
        let resource = target.canonical;
        if (!target.denied && attempt.grantScope !== "path") {
          let needsParent = attempt.grantScope === "parent";
          if (attempt.grantScope === "parent-if-missing") {
            try { await lstat(target.canonical); } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") continue;
              needsParent = true;
            }
          }
          if (attempt.grantScope === "nofollow-path") {
            try { needsParent = (await lstat(target.canonical)).isSymbolicLink(); }
            catch { continue; }
          }
          if (needsParent) resource = dirname(target.canonical);
        }
        if (seen.has(resource)) continue;
        seen.add(resource);
        violations.push({ kind: "filesystem.write", resource, message: `${attempt.syscall} ${attempt.path} ${attempt.errno}` });
      } catch { /* Unresolvable paths do not create approval candidates. */ }
    }
    return violations;
  }
}
