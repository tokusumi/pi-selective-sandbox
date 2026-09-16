import { spawn } from "node:child_process";
import { dirname } from "node:path";
import { createBashTool, type BashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { redact_text } from "@spences10/pi-redact";
import { create_skills_manager } from "@spences10/pi-skills";
import { AnthropicSandboxRuntime } from "./runtime-adapter.js";
import { SelectiveSandboxExecutor } from "./executor.js";
import { CapabilityPolicy } from "./policy.js";
import type { ApprovalProvider, CommandResult, CommandRunner, SkillAuthority } from "./types.js";

type ApprovalUI = { hasUI?: boolean; ui?: { select(message: string, choices: string[]): Promise<string | undefined> } };

function runCommand(command: string, cwd: string, options: Parameters<BashOperations["exec"]>[2]): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", ["-c", command], { cwd, env: options.env ?? process.env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const emit = (chunk: Buffer, isError: boolean) => {
      const text = redact_text(chunk.toString()).redacted;
      if (isError) stderr += text;
      else stdout += text;
      options.onData(Buffer.from(text));
    };
    child.stdout?.on("data", chunk => emit(chunk, false));
    child.stderr?.on("data", chunk => emit(chunk, true));
    child.on("error", reject);
    const kill = () => child.kill("SIGKILL");
    options.signal?.addEventListener("abort", kill, { once: true });
    child.on("close", code => {
      options.signal?.removeEventListener("abort", kill);
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
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
      const sandboxedBash = createBashTool(cwd, {
        operations: {
          async exec(command, commandCwd, options) {
            const runner: CommandRunner = {
              run: wrapped => runCommand(wrapped, commandCwd, options),
              runElevated: raw => runCommand(raw, commandCwd, options)
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
      return sandboxedBash.execute(id, params, signal, onUpdate);
    }
  });
}
