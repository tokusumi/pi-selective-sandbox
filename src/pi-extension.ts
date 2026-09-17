import { dirname, join } from "node:path";
import { createBashTool, createLocalBashOperations, getAgentDir, type BashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { redact_text } from "@spences10/pi-redact";
import { create_skills_manager } from "@spences10/pi-skills";
import { AnthropicSandboxRuntime } from "./runtime-adapter.js";
import { defaultWritableRoots, MutationBoundary } from "./filesystem-boundary.js";
import { createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "./mutation-tools.js";
import { SelectiveSandboxExecutor } from "./executor.js";
import { CapabilityPolicy } from "./policy.js";
import { ProjectGrantStore } from "./project-grants.js";
import { resolveProjectIdentity } from "./project-identity.js";
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

/** One approval surface for replay approvals and preflight mutation grants. */
export function createApprovalProvider(
  context: ApprovalUI, grants: SessionGrantStore, project?: { projectId: string; grants: ProjectGrantStore }
): ApprovalProvider {
  return {
    async request(request) {
      const projectEligible = request.projectGrantEligible === true && project !== undefined;
      if (projectEligible && await project.grants.covers(project.projectId, request.capabilities)) return "sandbox-allow-project";
      const sessionId = request.sessionGrantEligible ? context.sessionManager?.getSessionId() : undefined;
      if (sessionId && grants.covers(sessionId, request.capabilities)) return "sandbox-allow-session";
      if (!context.hasUI || !context.ui) return "deny";

      const requested = request.capabilities.map(capability => capability.kind + ": " + capability.resource).join("\n");
      const choices = request.kind === "escalation" ? ["Allow resource in sandbox once", "Run command on host once"] : ["Allow once"];
      if (sessionId) choices.push("Allow for session");
      if (projectEligible) choices.push("Allow for project");
      choices.push("Deny");
      const scopeMessage = projectEligible
        ? "\n\nAllow for project remembers exactly:\n" + requested + "\n\nfor local project:\n" + project.projectId + "\nincluding future Pi sessions."
        : sessionId ? "\n\nAllow for session remembers exactly the capability/resource above for the current Pi session." : "";
      const message = (request.replayWarning ? "Sandbox blocked this operation" : "Permission required before this file mutation")
        + ":\n\n" + request.command + "\n\nRequested capability:\n" + requested
        + (request.replayWarning ? "\n\nThis command already ran once; replay may repeat permitted side effects." : "\n\nNo mutation has occurred yet.") + scopeMessage;
      const choice = await context.ui.select(message, choices);
      if (choice === "Allow for project" && projectEligible) {
        try { await project.grants.grant(project.projectId, request.capabilities); return "sandbox-allow-project"; }
        catch { return "deny"; }
      }
      if (choice === "Allow for session" && sessionId) { grants.grant(sessionId, request.capabilities); return "sandbox-allow-session"; }
      if (request.kind === "escalation") return choice === "Run command on host once" ? "host-allow-once" : choice === "Allow resource in sandbox once" ? "sandbox-allow-once" : "deny";
      return choice === "Allow once" ? "sandbox-allow-once" : "deny";
    }
  };
}

/** Pi package entrypoint. Replaces bash plus boundary-aware file mutation tools. */
export default async function selectiveSandboxExtension(pi: ExtensionAPI): Promise<void> {
  const cwd = process.cwd();
  const grants = new SessionGrantStore();
  const projectId = await resolveProjectIdentity(cwd);
  const projectGrants = projectId ? new ProjectGrantStore(join(getAgentDir(), "pi-selective-sandbox", "project-grants.json")) : undefined;
  if (projectGrants) await projectGrants.load();
  const project = projectId && projectGrants ? { projectId, grants: projectGrants } : undefined;
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
              runSandbox: wrapped => runCommand(localOperations, wrapped, commandCwd, options),
              runHost: raw => runCommand(localOperations, raw, commandCwd, options)
            };
            const executor = new SelectiveSandboxExecutor({
              runtime,
              runner,
              policy: new CapabilityPolicy([], "ask"),
              approvals: createApprovalProvider(context as unknown as ApprovalUI, grants, project),
              skills: skills(commandCwd),
              trustedHelpersAutoApprove: true,
              canonicalizeCapabilities: async capabilities => { const boundary = await MutationBoundary.create(commandCwd); return Promise.all(capabilities.map(async capability => ({ ...capability, resource: (await boundary.resolve(capability.resource)).canonical }))); },
              commandIdentity: shellCommand => ({ shellCommand, cwd: commandCwd, executionMode: "shell" }),
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
  const approvalProvider = (context: unknown) => createApprovalProvider(context as ApprovalUI, grants, project);
  pi.registerTool(await createBoundaryAwareWriteTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
  pi.registerTool(await createBoundaryAwareEditTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
}

export function emitExecutorOutput(output: Pick<CommandResult, "stdout" | "stderr">, onData: (chunk: Buffer) => void): void {
  if (output.stdout) onData(Buffer.from(output.stdout));
  if (output.stderr) onData(Buffer.from(output.stderr));
}
