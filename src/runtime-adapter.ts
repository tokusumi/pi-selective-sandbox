import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { WritePolicy } from "./filesystem-policy.js";
import { StraceViolationObserver, STRACE_ARGS, STRACE_BINARY } from "./strace-observer.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";
import { macOSCommandObservation, readMacOSViolationLines, type MacOSCommandObservation } from "./macos-observer.js";

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
  const filesystem = line.match(/\bdeny(?:\(\d+\))?\s+file-(?:read|write)(?:-[\w-]+)?\s+(.+)$/)?.[1];
  if (filesystem) {
    const unquoted = filesystem.replace(/^(['"])(.*)\1$/, "$2");
    if (unquoted.startsWith("/") || unquoted.startsWith("~/")) return unquoted;
  }
  const quoted = line.match(/['"]((?:\/|~\/)[^'"\s]+)['"]/);
  const path = quoted ?? line.match(/((?:\/|~\/)[^\s,;]+)/);
  return path?.[1] ?? "unknown";
}

function isProxyNetworkViolation(line: string): boolean {
  // Proxy producers use this unprefixed format; Seatbelt lines include a PID.
  return /^deny (?:network-outbound|http-request)\s/.test(line);
}

export function violationFromLine(line: string): SandboxViolation {
  // Seatbelt emits `<process>(pid) deny(1) <operation> <resource>`;
  // Linux observers and proxies emit `deny <operation> <resource>`.
  // Process names and paths may themselves contain "read" or "network".
  const operation = line.match(/\bdeny(?:\(\d+\))?\s+([\w-]+)/i)?.[1] ?? "";
  if (/^(?:network(?:-|$)|http-request$|connect$|outbound$)/i.test(operation)) return { kind: "network", resource: resourceFromLine(line), message: line };
  if (/^file-read(?:-|$)/i.test(operation)) return { kind: "filesystem.read", resource: resourceFromLine(line), message: line };
  return { kind: "filesystem.write", resource: resourceFromLine(line), message: line };
}

/** Concrete adapter for @anthropic-ai/sandbox-runtime's per-command telemetry. */
export class AnthropicSandboxRuntime implements SandboxRuntime {
  private readonly strace = new Map<string, StraceViolationObserver>();
  private readonly macOS = new Map<string, MacOSCommandObservation & { attributionId: string }>();
  private constructor(private readonly settings: SandboxSettings, private readonly useStrace: boolean) {}

  static async initialize(settings: SandboxSettings): Promise<AnthropicSandboxRuntime> {
    const ubuntu = await isUbuntu();
    if (ubuntu) {
      try { await promisify(execFile)(STRACE_BINARY, [...STRACE_ARGS, "/usr/bin/true"], { timeout: 5000 }); }
      catch (cause) { throw new Error("Ubuntu filesystem observation requires working strace.", { cause }); }
    }
    // The stream has no sender provenance and can contaminate proxy telemetry.
    // macOS uses kernel snapshots; proxy denials are recorded independently.
    // Linux's startup-policy observer cannot account for per-command grants.
    await SandboxManager.initialize(buildSandboxRuntimeConfig(settings, ubuntu), undefined, false);
    return new AnthropicSandboxRuntime(settings, ubuntu);
  }

  async wrap(command: string, context: { commandId: string; commandText: string; cwd?: string; extraCapabilities?: readonly import("./types.js").Capability[] }): Promise<string> {
    const extraWrites = context.extraCapabilities?.filter(capability => capability.kind === "filesystem.write").map(capability => capability.resource) ?? [];
    const policy = this.settings.writePolicy;
    const since = Date.now();
    // SDK tags truncate keys at 100 characters. A fresh short key also prevents
    // stale log events when callers reuse a tool-call ID across attempts.
    const attributionId = process.platform === "darwin" ? randomUUID() : context.commandId;
    const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, { filesystem: { allowWrite: [...policy.allow, ...extraWrites], allowRead: [...(this.settings.allowRead ?? [])], denyRead: [], denyWrite: [...policy.deny] } }, undefined, { ...context, commandId: attributionId });
    if (this.useStrace) this.strace.set(context.commandId, new StraceViolationObserver(context.cwd ?? this.settings.cwd, { allow: [...policy.allow, ...extraWrites], deny: policy.deny }));
    if (process.platform === "darwin") this.macOS.set(context.commandId, { ...macOSCommandObservation(wrapped, attributionId, since), attributionId });
    return wrapped;
  }

  traceSinkForCommand(commandId: string): ((chunk: Buffer) => void) | undefined {
    const observer = this.strace.get(commandId);
    return observer ? chunk => observer.ingest(chunk) : undefined;
  }

  forgetCommand(commandId: string): void { this.strace.delete(commandId); this.macOS.delete(commandId); }

  async getViolationsForCommand(commandId: string): Promise<readonly SandboxViolation[]> {
    const observer = this.strace.get(commandId);
    this.strace.delete(commandId);
    const store = SandboxManager.getSandboxViolationStore();
    if (process.platform === "darwin") {
      const observation = this.macOS.get(commandId);
      if (!observation) throw new Error("macOS sandbox command attribution is unavailable.");
      // Always validate the snapshot: stream chunks can misattribute another
      // command's denial and the upstream store strips '<'/'>' from paths.
      const kernel = (await readMacOSViolationLines(observation)).map(violationFromLine);
      // Proxy events originate in-process and do not have kernel counterparts.
      const proxy = store.getViolationsForCommand(observation.attributionId).filter(event => isProxyNetworkViolation(event.line)).map(event =>
        ({ ...violationFromLine(event.line), kind: "network" as const }));
      return [...kernel, ...proxy];
    }
    const upstream = store.getViolationsForCommand(commandId).map(event => violationFromLine(event.line));
    return observer ? [...upstream, ...await observer.getViolations()] : upstream;
  }

  static async reset(): Promise<void> { await SandboxManager.reset(); }
}
