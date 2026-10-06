import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { WritePolicy } from "./filesystem-policy.js";
import { StraceViolationObserver, STRACE_ARGS, STRACE_BINARY } from "./strace-observer.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";

export type SandboxSettings = { cwd: string; writePolicy: WritePolicy; allowRead?: readonly string[]; allowedDomains?: readonly string[] };

export function isUbuntuRelease(osRelease: string): boolean {
  const values = new Map(osRelease.split("\n").map(line => {
    const separator = line.indexOf("=");
    if (separator < 0) return [line, ""];
    return [line.slice(0, separator), line.slice(separator + 1).replace(/^["']|["']$/g, "")];
  }));
  return values.get("ID")?.toLowerCase() === "ubuntu";
}

export async function isUbuntu(osReleasePath = "/etc/os-release"): Promise<boolean> {
  if (process.platform !== "linux") return false;
  try { return isUbuntuRelease(await readFile(osReleasePath, "utf8")); } catch { return false; }
}

export function buildSandboxRuntimeConfig(settings: SandboxSettings, allowAllUnixSockets = false): SandboxRuntimeConfig {
  const policy = settings.writePolicy;
  return {
    filesystem: {
      // Runtime reads are broad by default; credential visibility is handled at the model boundary.
      allowRead: [...(settings.allowRead ?? [])], denyRead: [],
      allowWrite: [...policy.allow], denyWrite: [...policy.deny]
    },
    network: {
      // GitHub CLI remains usable with its normal credential helpers.
      allowedDomains: [...(settings.allowedDomains ?? ["api.github.com", "github.com", "*.github.com"])], deniedDomains: [],
      ...(allowAllUnixSockets ? { allowAllUnixSockets: true } : {})
    }
  };
}

export function sandboxInitializationError(error: unknown): string {
  const detail = error instanceof Error ? `${error.message}\n${error.cause instanceof Error ? error.cause.message : ""}` : String(error);
  if (/strace|ptrace|PTRACE/i.test(detail)) {
    return "Linux sandbox observation is unavailable because strace could not trace commands. Host execution was not attempted.";
  }
  if (/apply-seccomp|seccomp|nested.{0,20}(user namespace|userns)|user namespace.{0,20}(denied|not permitted|operation not permitted)/is.test(detail)) {
    return "Linux sandbox is unavailable because the host blocks the nested user namespace required for Unix-socket isolation. Host execution was not attempted.";
  }
  if (/apparmor|unprivileged_userns|user namespace|userns/i.test(detail)) {
    return "Linux sandbox is unavailable because Bubblewrap is blocked by the host AppArmor/user-namespace policy. Host execution was not attempted.";
  }
  if (/\bbwrap\b|bubblewrap/i.test(detail)) {
    return "Linux sandbox is unavailable because Bubblewrap could not be started. Host execution was not attempted.";
  }
  return "Sandbox unavailable; host execution was not attempted.";
}

function resourceFromLine(line: string): string {
  const quoted = line.match(/['"]((?:\/|~\/)[^'"\s]+)['"]/);
  const path = quoted ?? line.match(/((?:\/|~\/)[^\s,;]+)/);
  return path?.[1] ?? "unknown";
}

function violationFromLine(line: string): SandboxViolation {
  if (/network|connect|outbound/i.test(line)) return { kind: "network", resource: resourceFromLine(line), message: line };
  if (/read|file-read/i.test(line)) return { kind: "filesystem.read", resource: resourceFromLine(line), message: line };
  return { kind: "filesystem.write", resource: resourceFromLine(line), message: line };
}

/** Concrete adapter for @anthropic-ai/sandbox-runtime's per-command telemetry. */
export class AnthropicSandboxRuntime implements SandboxRuntime {
  private readonly strace = new Map<string, StraceViolationObserver>();
  private constructor(private readonly settings: SandboxSettings, private readonly useStrace: boolean) {}

  static async initialize(settings: SandboxSettings): Promise<AnthropicSandboxRuntime> {
    const ubuntu = await isUbuntu();
    if (ubuntu) {
      try { await promisify(execFile)(STRACE_BINARY, [...STRACE_ARGS, "/usr/bin/true"], { timeout: 5000 }); }
      catch (cause) { throw new Error("Ubuntu filesystem observation requires working strace.", { cause }); }
    }
    await SandboxManager.initialize(buildSandboxRuntimeConfig(settings, ubuntu));
    return new AnthropicSandboxRuntime(settings, ubuntu);
  }

  async wrap(command: string, context: { commandId: string; commandText: string; cwd?: string; extraCapabilities?: readonly import("./types.js").Capability[] }): Promise<string> {
    const extraWrites = context.extraCapabilities?.filter(capability => capability.kind === "filesystem.write").map(capability => capability.resource) ?? [];
    const policy = this.settings.writePolicy;
    const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, { filesystem: { allowWrite: [...policy.allow, ...extraWrites], allowRead: [...(this.settings.allowRead ?? [])], denyRead: [], denyWrite: [...policy.deny] } }, undefined, context);
    if (this.useStrace) this.strace.set(context.commandId, new StraceViolationObserver(context.cwd ?? this.settings.cwd, { allow: [...policy.allow, ...extraWrites], deny: policy.deny }));
    return wrapped;
  }

  traceSinkForCommand(commandId: string): ((chunk: Buffer) => void) | undefined {
    const observer = this.strace.get(commandId);
    return observer ? chunk => observer.ingest(chunk) : undefined;
  }

  forgetCommand(commandId: string): void { this.strace.delete(commandId); }

  async getViolationsForCommand(commandId: string): Promise<readonly SandboxViolation[]> {
    const observer = this.strace.get(commandId);
    this.strace.delete(commandId);
    const upstream = SandboxManager.getSandboxViolationStore().getViolationsForCommand(commandId)
      .map(event => violationFromLine(event.line));
    return observer ? [...upstream, ...await observer.getViolations()] : upstream;
  }

  static async reset(): Promise<void> { await SandboxManager.reset(); }
}
