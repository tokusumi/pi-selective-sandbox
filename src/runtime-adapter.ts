import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { defaultWritableRoots } from "./filesystem-boundary.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";

export type SandboxSettings = { cwd: string; allowWrite?: readonly string[]; allowRead?: readonly string[]; allowedDomains?: readonly string[] };

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
    const config: SandboxRuntimeConfig = {
      filesystem: {
        // Runtime reads are broad by default; credential visibility is handled at the model boundary.
        allowRead: [...(settings.allowRead ?? [])], denyRead: [],
        allowWrite: [...(settings.allowWrite ?? defaultWritableRoots(settings.cwd))], denyWrite: []
      },
      network: {
        // GitHub CLI remains usable with its normal credential helpers.
        allowedDomains: [...(settings.allowedDomains ?? ["api.github.com", "github.com", "*.github.com"])], deniedDomains: []
      }
    };
    await SandboxManager.initialize(config);
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
