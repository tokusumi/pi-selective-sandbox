import { dirname } from "node:path";
import { createBashTool, createLocalBashOperations, type BashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { redact_text } from "@spences10/pi-redact";
import { create_skills_manager } from "@spences10/pi-skills";
import { AnthropicSandboxRuntime } from "./runtime-adapter.js";
import { defaultWritableRoots } from "./filesystem-boundary.js";
import { createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "./mutation-tools.js";
import { SelectiveSandboxExecutor } from "./executor.js";
import { CapabilityPolicy } from "./policy.js";
import { SessionGrantStore } from "./session-grants.js";
import type { ApprovalProvider, CommandResult, CommandRunner, SkillAuthority } from "./types.js";

type ApprovalUI = {
  hasUI?: boolean;
  ui?: { select(message: string, choices: string[]): Promise<string | undefined> };
  sessionManager?: { getSessionId(): string };
};

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

/** One approval surface for both replay approvals and preflight mutation grants. */
export function createApprovalProvider(context: ApprovalUI, grants: SessionGrantStore): ApprovalProvider {
  return {
    async request(request) {
      const sessionId = request.sessionGrantEligible ? context.sessionManager?.getSessionId() : undefined;
      if (sessionId && grants.covers(sessionId, request.capabilities)) return "allow-session";
      if (!context.hasUI || !context.ui) return "deny";
      const requested = request.capabilities.map(capability => `${capability.kind}: ${capability.resource}`).join("\n");
      const sessionChoice = request.sessionGrantEligible && sessionId;
      const choice = await context.ui.select(
        `${request.replayWarning ? "Sandbox blocked this operation" : "Permission required before this file mutation"}:\n\n${request.command}\n\nRequested capability:\n${requested}${request.replayWarning ? "\n\nThis command already ran once; replay may repeat permitted side effects." : "\n\nNo mutation has occurred yet."}${sessionChoice ? "\n\nAllow for session remembers exactly the capability/resource above for the current Pi session." : ""}`,
        sessionChoice ? ["Allow once", "Allow for session", "Deny"] : ["Allow once", "Deny"]
      );
      if (choice === "Allow for session" && sessionId) {
        grants.grant(sessionId, request.capabilities);
        return "allow-session";
      }
      return choice === "Allow once" ? "allow-once" : "deny";
    }
  };
}

/** Pi package entrypoint. Replaces bash plus boundary-aware file mutation tools. */
export default async function selectiveSandboxExtension(pi: ExtensionAPI): Promise<void> {
  const cwd = process.cwd();
  const grants = new SessionGrantStore();
  const writableRoots = defaultWritableRoots(cwd);
  let runtime: AnthropicSandboxRuntime | undefined;
  let initialization: Promise<void> | undefined;
  const ensureRuntime = async () => {
    initialization ??= AnthropicSandboxRuntime.initialize({ cwd, allowWrite: writableRoots }).then(value => { runtime = value; });
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
              approvals: createApprovalProvider(context as unknown as ApprovalUI, grants),
              skills: skills(commandCwd),
              trustedHelpersAutoApprove: true,
              redactor: { redact: text => redact_text(text).redacted }
            });
            const output = await executor.execute(command, id);
            emitExecutorOutput(output, options.onData);
            return { exitCode: output.exitCode };
          }
        }
      });
      const output = await sandboxedBash.execute(id, params, signal, onUpdate);
      return redactToolResult(output);
    }
  });
  const approvalProvider = (context: unknown) => createApprovalProvider(context as ApprovalUI, grants);
  pi.registerTool(await createBoundaryAwareWriteTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
  pi.registerTool(await createBoundaryAwareEditTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
}

export function emitExecutorOutput(output: Pick<CommandResult, "stdout" | "stderr">, onData: (chunk: Buffer) => void): void {
  if (output.stdout) onData(Buffer.from(output.stdout));
  if (output.stderr) onData(Buffer.from(output.stderr));
}
