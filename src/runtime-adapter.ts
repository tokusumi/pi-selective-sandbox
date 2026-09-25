import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { readFile } from "node:fs/promises";
import { defaultWritableRoots } from "./filesystem-boundary.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";

export type SandboxSettings = { cwd: string; allowWrite?: readonly string[]; allowRead?: readonly string[]; allowedDomains?: readonly string[] };

export function isUbuntu24Release(osRelease: string): boolean {
  const values = new Map(osRelease.split("\n").map(line => {
    const separator = line.indexOf("=");
    if (separator < 0) return [line, ""];
    return [line.slice(0, separator), line.slice(separator + 1).replace(/^["']|["']$/g, "")];
  }));
  return values.get("ID")?.toLowerCase() === "ubuntu" && /^24(?:\.|$)/.test(values.get("VERSION_ID") ?? "");
}

export async function isUbuntu24(osReleasePath = "/etc/os-release"): Promise<boolean> {
  if (process.platform !== "linux") return false;
  try { return isUbuntu24Release(await readFile(osReleasePath, "utf8")); } catch { return false; }
}

export function buildSandboxRuntimeConfig(settings: SandboxSettings, allowAllUnixSockets = false): SandboxRuntimeConfig {
  return {
    filesystem: {
      // Runtime reads are broad by default; credential visibility is handled at the model boundary.
      allowRead: [...(settings.allowRead ?? [])], denyRead: [],
      allowWrite: [...(settings.allowWrite ?? defaultWritableRoots(settings.cwd))], denyWrite: []
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
  private constructor(private readonly settings: SandboxSettings) {}

  static async initialize(settings: SandboxSettings): Promise<AnthropicSandboxRuntime> {
    await SandboxManager.initialize(buildSandboxRuntimeConfig(settings, await isUbuntu24()));
    return new AnthropicSandboxRuntime(settings);
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
