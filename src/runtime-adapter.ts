import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { defaultWritableRoots } from "./filesystem-boundary.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";

export const LINUX_SANDBOX_MODES = ["strict", "ubuntu-compatible"] as const;
export type LinuxSandboxMode = typeof LINUX_SANDBOX_MODES[number];
export type SandboxSettings = { cwd: string; linuxSandboxMode?: LinuxSandboxMode; allowWrite?: readonly string[]; allowRead?: readonly string[]; allowedDomains?: readonly string[] };

export function parseLinuxSandboxMode(value: unknown): LinuxSandboxMode {
  if (value === undefined || value === "ubuntu-compatible") return "ubuntu-compatible";
  if (value === "strict") return "strict";
  throw new Error(`Invalid Linux sandbox mode: ${String(value)}. Expected strict or ubuntu-compatible.`);
}

export function buildSandboxRuntimeConfig(settings: SandboxSettings): SandboxRuntimeConfig {
  const mode = parseLinuxSandboxMode(settings.linuxSandboxMode);
  return {
    filesystem: {
      // Runtime reads are broad by default; credential visibility is handled at the model boundary.
      allowRead: [...(settings.allowRead ?? [])], denyRead: [],
      allowWrite: [...(settings.allowWrite ?? defaultWritableRoots(settings.cwd))], denyWrite: []
    },
    network: {
      // GitHub CLI remains usable with its normal credential helpers.
      allowedDomains: [...(settings.allowedDomains ?? ["api.github.com", "github.com", "*.github.com"])], deniedDomains: [],
      ...(mode === "ubuntu-compatible" ? { allowAllUnixSockets: true } : {})
    }
  };
}

export function sandboxInitializationError(error: unknown, mode: LinuxSandboxMode): string {
  const detail = error instanceof Error ? `${error.message}\n${error.cause instanceof Error ? error.cause.message : ""}` : String(error);
  if (mode === "strict" && /apply-seccomp|seccomp|nested.{0,20}(user namespace|userns)|user namespace.{0,20}(denied|not permitted|operation not permitted)/is.test(detail)) {
    return "Strict Linux sandbox is unavailable because the host blocks the nested user namespace required for Unix-socket isolation. Use the documented Ubuntu-compatible mode if accepting loss of Unix-socket isolation. Host execution was not attempted.";
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
  private constructor(private readonly settings: SandboxSettings) {}

  static async initialize(settings: SandboxSettings): Promise<AnthropicSandboxRuntime> {
    const normalized = { ...settings, linuxSandboxMode: parseLinuxSandboxMode(settings.linuxSandboxMode) };
    await SandboxManager.initialize(buildSandboxRuntimeConfig(normalized));
    return new AnthropicSandboxRuntime(normalized);
  }

  async wrap(command: string, context: { commandId: string; commandText: string; extraCapabilities?: readonly import("./types.js").Capability[] }): Promise<string> {
    const extraWrites = context.extraCapabilities?.filter(capability => capability.kind === "filesystem.write").map(capability => capability.resource) ?? [];
    return SandboxManager.wrapWithSandbox(command, undefined, { filesystem: { allowWrite: [...(this.settings.allowWrite ?? defaultWritableRoots(this.settings.cwd)), ...extraWrites], allowRead: [...(this.settings.allowRead ?? [])], denyRead: [], denyWrite: [] } }, undefined, context);
  }

  getViolationsForCommand(commandId: string): readonly SandboxViolation[] {
    return SandboxManager.getSandboxViolationStore().getViolationsForCommand(commandId)
      .map(event => violationFromLine(event.line));
  }

  static async reset(): Promise<void> { await SandboxManager.reset(); }
}
