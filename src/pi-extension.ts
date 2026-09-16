import { dirname } from "node:path";
import { createBashTool, createLocalBashOperations, type BashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { redact_text } from "@spences10/pi-redact";
import { create_skills_manager } from "@spences10/pi-skills";
import { AnthropicSandboxRuntime } from "./runtime-adapter.js";
import { SelectiveSandboxExecutor } from "./executor.js";
import { CapabilityPolicy } from "./policy.js";
import type { ApprovalProvider, CommandResult, CommandRunner, SkillAuthority } from "./types.js";

type ApprovalUI = { hasUI?: boolean; ui?: { select(message: string, choices: string[]): Promise<string | undefined> } };

async function runCommand(local: BashOperations, command: string, cwd: string, options: Parameters<BashOperations["exec"]>[2]): Promise<CommandResult> {
  const completed = await local.exec(command, cwd, {
    ...options,
    onData: chunk => options.onData(Buffer.from(redact_text(chunk.toString()).redacted))
  });
  return { exitCode: completed.exitCode ?? 1, stdout: "", stderr: "" };
}

export function redactToolResult<T extends { content: readonly { type: string; text?: string }[] }>(result: T): T {
  return { ...result, content: result.content.map(item =>
    item.type === "text" && typeof item.text === "string" ? { ...item, text: redact_text(item.text).redacted } : item
  ) } as T;
}

function skills(cwd: string): SkillAuthority {
  const manager = create_skills_manager({ cwd });
  return {
    async getActiveSkills() {
      const enabled = new Set(manager.get_enabled_skill_paths());
      return manager.discover().filter(skill => skill.enabled && enabled.has(skill.skillPath)).map(skill => ({
        id: skill.key,
        root: dirname(skill.skillPath),
        helperRoots: ["scripts"],
        active: true,
        trusted: true
      }));
    }
  };
}

function approvals(context: ApprovalUI): ApprovalProvider {
  return {
    async request(request) {
      if (!context.hasUI || !context.ui) return "deny";
      const requested = request.capabilities.map(capability => `${capability.kind}: ${capability.resource}`).join("\n");
      const choice = await context.ui.select(
        `Sandbox blocked this operation:\n\n${request.command}\n\nRequested capability:\n${requested}\n\nThis command already ran once; replay may repeat permitted side effects.`,
        ["Allow once", "Deny"]
      );
      return choice === "Allow once" ? "allow-once" : "deny";
    }
  };
}

/** Pi package entrypoint. Replaces bash with sandbox-first execution. */
export default async function selectiveSandboxExtension(pi: ExtensionAPI): Promise<void> {
  const cwd = process.cwd();
  let runtime: AnthropicSandboxRuntime | undefined;
  let initialization: Promise<void> | undefined;
  const ensureRuntime = async () => {
    initialization ??= AnthropicSandboxRuntime.initialize({ cwd }).then(value => { runtime = value; });
    try { await initialization; } catch { runtime = undefined; }
  };
  pi.on("session_shutdown", async () => { await AnthropicSandboxRuntime.reset().catch(() => undefined); });
  const localBash = createBashTool(cwd);
  pi.registerTool({
    ...localBash,
    async execute(id, params, signal, onUpdate, context) {
      await ensureRuntime();
      const localOperations = createLocalBashOperations();
      const sandboxedBash = createBashTool(cwd, {
        operations: {
          async exec(command, commandCwd, options) {
            const runner: CommandRunner = {
              run: wrapped => runCommand(localOperations, wrapped, commandCwd, options),
              runElevated: raw => runCommand(localOperations, raw, commandCwd, options)
            };
            const executor = new SelectiveSandboxExecutor({
              runtime,
              runner,
              policy: new CapabilityPolicy([], "ask"),
              approvals: approvals(context as unknown as ApprovalUI),
              skills: skills(commandCwd),
              trustedHelpersAutoApprove: true,
              redactor: { redact: text => redact_text(text).redacted }
            });
            const output = await executor.execute(command, id);
            return { exitCode: output.exitCode };
          }
        }
      });
      const output = await sandboxedBash.execute(id, params, signal, onUpdate);
      return redactToolResult(output);
    }
  });
}
