import { realpath } from "node:fs/promises";
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
import { ProjectHostCommandGrantStore } from "./project-host-command-grants.js";
import { resolveProjectIdentity } from "./project-identity.js";
import { SessionGrantStore } from "./session-grants.js";
import { SessionHostCommandGrantStore } from "./session-host-command-grants.js";
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
  context: ApprovalUI,
  grants: SessionGrantStore,
  project?: { projectId: string; grants: ProjectGrantStore; hostGrants?: ProjectHostCommandGrantStore },
  hostGrants = new SessionHostCommandGrantStore()
): ApprovalProvider {
  return {
    async request(request) {
      const projectEligible = request.projectGrantEligible === true && project !== undefined;
      const sessionId = request.sessionGrantEligible ? context.sessionManager?.getSessionId() : undefined;

      // Host grants contain only an exact canonical command identity. They do not
      // participate in sandbox capability matching or sandbox policy widening.
      const hostCommand = request.kind === "escalation" ? request.commandIdentity : undefined;
      const hostProjectStore = hostCommand ? project?.hostGrants : undefined;
      if (hostCommand && project && hostProjectStore && await hostProjectStore.covers(project.projectId, hostCommand)) return "host-allow-project";
      if (sessionId && hostCommand && hostGrants.covers(sessionId, hostCommand)) return "host-allow-session";
      if (projectEligible && await project.grants.covers(project.projectId, request.capabilities)) return "sandbox-allow-project";
      if (sessionId && grants.covers(sessionId, request.capabilities)) return "sandbox-allow-session";
      if (!context.hasUI || !context.ui) return "deny";

      const requested = request.capabilities.map(capability => capability.kind + ": " + capability.resource).join("\n");
      const reusableHost = hostCommand !== undefined;
      const hostProjectEligible = hostProjectStore !== undefined;
      const choices = request.kind === "escalation"
        ? [
            "Allow resource in sandbox once",
            ...(sessionId ? ["Allow resource in sandbox for session"] : []),
            ...(projectEligible ? ["Allow resource in sandbox for project"] : []),
            "Run command on host once",
            ...(reusableHost && sessionId ? ["Run command on host for session"] : []),
            ...(reusableHost && hostProjectEligible ? ["Run command on host for project"] : []),
          ]
        : ["Allow once"];
      if (request.kind !== "escalation" && sessionId) choices.push("Allow for session");
      if (request.kind !== "escalation" && projectEligible) choices.push("Allow for project");
      choices.push("Deny");

      const sandboxScope = projectEligible
        ? "\n\nSandbox project approval remembers exactly:\n" + requested + "\n\nfor local project:\n" + project.projectId + "\nincluding future Pi sessions."
        : sessionId ? "\n\nSandbox session approval remembers exactly the capability/resource above for the current Pi session." : "";
      const hostScope = reusableHost
        ? "\n\nHost approval target (not a resource permission):\nexact command: " + hostCommand!.shellCommand
          + "\ncanonical cwd: " + hostCommand!.cwd + "\nexecution mode: " + hostCommand!.executionMode
        : request.kind === "escalation" ? "\n\nThe working directory could not be canonicalized, so reusable host approval is unavailable." : "";
      const message = request.kind === "escalation"
        ? "Sandbox blocked this operation:\n\n" + request.command + "\n\nSandbox observation (informational for host replay):\n" + requested
          + "\n\nApproving a resource never approves leaving the sandbox. Approving host execution never grants a resource capability."
          + "\n\nThis command already ran once; replay may repeat permitted side effects." + sandboxScope + hostScope
        : "Permission required before this file mutation:\n\n" + request.command + "\n\nRequested capability:\n" + requested
          + "\n\nNo mutation has occurred yet." + sandboxScope;
      const choice = await context.ui.select(message, choices);
      if ((choice === "Allow for project" || choice === "Allow resource in sandbox for project") && projectEligible) {
        try { await project.grants.grant(project.projectId, request.capabilities); return "sandbox-allow-project"; } catch { return "deny"; }
      }
      if ((choice === "Allow for session" || choice === "Allow resource in sandbox for session") && sessionId) {
        grants.grant(sessionId, request.capabilities); return "sandbox-allow-session";
      }
      if (request.kind === "escalation" && request.commandIdentity) {
        if (choice === "Run command on host for project" && hostProjectEligible) {
          try { await project!.hostGrants!.grant(project!.projectId, request.commandIdentity); return "host-allow-project"; } catch { return "deny"; }
        }
        if (choice === "Run command on host for session" && sessionId) {
          hostGrants.grant(sessionId, request.commandIdentity); return "host-allow-session";
        }
      }
      if (request.kind === "escalation") return choice === "Run command on host once" ? "host-allow-once" : choice === "Allow resource in sandbox once" ? "sandbox-allow-once" : "deny";
      return choice === "Allow once" ? "sandbox-allow-once" : "deny";
    }
  };
}

/** Pi package entrypoint. Replaces bash plus boundary-aware file mutation tools. */
export default async function selectiveSandboxExtension(pi: ExtensionAPI): Promise<void> {
  const cwd = process.cwd();
  const grants = new SessionGrantStore();
  const hostGrants = new SessionHostCommandGrantStore();
  const projectId = await resolveProjectIdentity(cwd);
  const projectGrants = projectId ? new ProjectGrantStore(join(getAgentDir(), "pi-selective-sandbox", "project-grants.json")) : undefined;
  const projectHostGrants = projectId ? new ProjectHostCommandGrantStore(join(getAgentDir(), "pi-selective-sandbox", "host-command-grants.json")) : undefined;
  if (projectGrants) await projectGrants.load();
  if (projectHostGrants) await projectHostGrants.load();
  const project = projectId && projectGrants && projectHostGrants ? { projectId, grants: projectGrants, hostGrants: projectHostGrants } : undefined;
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
              approvals: createApprovalProvider(context as unknown as ApprovalUI, grants, project, hostGrants),
              skills: skills(commandCwd),
              trustedHelpersAutoApprove: true,
              getSandboxCapabilities: async () => { const sessionId = (context as unknown as ApprovalUI).sessionManager?.getSessionId(); const sessionCapabilities = sessionId ? grants.capabilities(sessionId) : []; const projectCapabilities = project ? await project.grants.capabilities(project.projectId) : []; return [...sessionCapabilities, ...projectCapabilities]; },
              canonicalizeCapabilities: async capabilities => { const boundary = await MutationBoundary.create(commandCwd); return Promise.all(capabilities.map(async capability => ({ ...capability, resource: (await boundary.resolve(capability.resource)).canonical }))); },
              commandIdentity: async shellCommand => { try { return { shellCommand, cwd: await realpath(commandCwd), executionMode: "shell" }; } catch { return undefined; } },
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
  const approvalProvider = (context: unknown) => createApprovalProvider(context as ApprovalUI, grants, project, hostGrants);
  pi.registerTool(await createBoundaryAwareWriteTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
  pi.registerTool(await createBoundaryAwareEditTool({ cwd, writableRoots, approvals: approvalProvider }) as never);
}

export function emitExecutorOutput(output: Pick<CommandResult, "stdout" | "stderr">, onData: (chunk: Buffer) => void): void {
  if (output.stdout) onData(Buffer.from(output.stdout));
  if (output.stderr) onData(Buffer.from(output.stderr));
}
