import { realpath } from "node:fs/promises";
import { isBroadGitParent, requestEscalationApproval, type ApprovalProject } from "./escalation-approval.js";
import type { EscalationUI } from "./widening-dialog.js";
import { dirname, join } from "node:path";
import { createBashTool, createLocalBashOperations, getAgentDir, type BashOperations, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { redact_text } from "@spences10/pi-redact";
import { create_skills_manager } from "@spences10/pi-skills";
import { AnthropicSandboxRuntime, SandboxInitializationFailure, sandboxInitializationError } from "./runtime-adapter.js";
import { MutationBoundary } from "./filesystem-boundary.js";
import { DEFAULT_WRITE_PROFILES, loadConfig } from "./config.js";
import { resolveWritePolicy } from "./filesystem-policy.js";
import { gitApprovalPaths, pathContains, resolveGitWritePaths, worktreeRemovalParent, type GitWritePaths } from "./git-write-paths.js";
import { createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "./mutation-tools.js";
import { SelectiveSandboxExecutor } from "./executor.js";
import { runTracedSandbox } from "./strace-runner.js";
import { CapabilityPolicy } from "./policy.js";
import { ProjectGrantStore } from "./project-grants.js";
import { ProjectHostCommandGrantStore } from "./project-host-command-grants.js";
import { resolveProjectIdentity } from "./project-identity.js";
import { SessionGrantStore } from "./session-grants.js";
import { SessionHostCommandGrantStore } from "./session-host-command-grants.js";
import type { ApprovalProvider, Capability, CommandResult, CommandRunner, SkillAuthority } from "./types.js";

type ApprovalUI = EscalationUI;

async function runCommand(local: BashOperations, command: string, cwd: string, options: Parameters<BashOperations["exec"]>[2]): Promise<CommandResult> {
  const completed = await local.exec(command, cwd, {
    ...options,
    onData: chunk => options.onData(Buffer.from(redact_text(chunk.toString()).redacted))
  });
  return { exitCode: completed.exitCode ?? 1, stdout: "", stderr: "" };
}

export function minimalWriteRoots(capabilities: readonly Capability[]): Capability[] {
  const unique = [...new Map(capabilities.map(capability => [`${capability.kind}\0${capability.resource}`, capability])).values()];
  return unique.filter(capability => capability.kind !== "filesystem.write" || !unique.some(other =>
    other.kind === "filesystem.write" && other.resource !== capability.resource && pathContains(other.resource, capability.resource)));
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

/** Shared stored-grant lookup; bash widening has its own scope/duration UI. */
export function createApprovalProvider(
  context: ApprovalUI,
  grants: SessionGrantStore,
  project?: ApprovalProject,
  hostGrants = new SessionHostCommandGrantStore(),
  gitWritePaths?: GitWritePaths
): ApprovalProvider {
  return {
    async request(request) {
      if (request.kind === "escalation") return requestEscalationApproval(context, request, grants, project, hostGrants, gitWritePaths);
      // Native tools retain exact, preflight resource approvals (no host execution).
      const broadParent = isBroadGitParent(request.capabilities, gitWritePaths);
      const projectEligible = request.projectGrantEligible === true && project !== undefined && !broadParent;
      const sessionId = request.sessionGrantEligible && !broadParent ? context.sessionManager?.getSessionId() : undefined;
      if (request.capabilities.length > 0 && projectEligible && await project.grants.covers(project.projectId, request.capabilities)) return "sandbox-allow-project";
      if (request.capabilities.length > 0 && sessionId && grants.covers(sessionId, request.capabilities)) return "sandbox-allow-session";
      if (!context.hasUI || !context.ui) return "deny";
      const requested = request.capabilities.map(capability => capability.kind + ": " + capability.resource).join("\n");
      const choices = ["Allow once", ...(sessionId ? ["Allow for session"] : []), ...(projectEligible ? ["Allow for project"] : []), "Deny"];
      const scope = projectEligible
        ? "\n\nSandbox project approval remembers exactly:\n" + requested + "\n\nfor local project:\n" + project.projectId + "\nincluding future Pi sessions."
        : sessionId ? "\n\nSandbox session approval remembers exactly the capability/resource above for the current Pi session." : "";
      const choice = await context.ui.select("Permission required before this file mutation:\n\n" + request.command
        + "\n\nRequested capability:\n" + requested + "\n\nNo mutation has occurred yet." + scope, choices);
      if (choice === "Allow for project" && projectEligible) {
        try { await project.grants.grant(project.projectId, request.capabilities); return "sandbox-allow-project"; } catch { return "deny"; }
      }
      if (choice === "Allow for session" && sessionId) { grants.grant(sessionId, request.capabilities); return "sandbox-allow-session"; }
      return choice === "Allow once" ? "sandbox-allow-once" : "deny";
    }
  };
}

/** Pi package entrypoint. Replaces bash plus boundary-aware file mutation tools. */
export default async function selectiveSandboxExtension(pi: ExtensionAPI): Promise<void> {
  const cwd = process.cwd();
  let enabled = true;
  let monitorDisabled = false;
  const monitorDisabledMessage = "Selective sandbox is disabled for bash, write, and edit because macOS SDK log monitoring is disabled (enableLogMonitor=false). Bash runs on the host; native mutation approvals are bypassed. Enable SDK log monitoring and reload to restore enforcement.";
  const warnMonitorDisabled = (context?: unknown) => {
    const ctx = context as { hasUI?: boolean; ui?: { notify(message: string, level: "warning"): void } } | undefined;
    if (ctx?.hasUI && ctx.ui) ctx.ui.notify(monitorDisabledMessage, "warning");
    else console.warn("WARNING: " + monitorDisabledMessage);
  };
  pi.registerCommand("selective-sandbox", {
    description: "Enable or disable sandbox enforcement: /selective-sandbox on|off",
    async handler(args, context) {
      const mode = args.trim();
      if (mode !== "on" && mode !== "off") {
        context.ui.notify("Usage: /selective-sandbox on|off", "info");
        return;
      }
      if (mode === "on" && monitorDisabled) {
        warnMonitorDisabled(context);
        return;
      }
      enabled = mode === "on";
      if (enabled && !await isEnabled(context)) return;
      context.ui.notify(enabled
        ? "Selective sandbox enabled for bash, write, and edit."
        : "Selective sandbox disabled for bash, write, and edit. Use /selective-sandbox on to enable it again.", enabled ? "info" : "warning");
    }
  });
  const grants = new SessionGrantStore();
  const hostGrants = new SessionHostCommandGrantStore();
  const projectId = await resolveProjectIdentity(cwd);
  const projectGrants = projectId ? new ProjectGrantStore(join(getAgentDir(), "pi-selective-sandbox", "project-grants.json")) : undefined;
  const projectHostGrants = projectId ? new ProjectHostCommandGrantStore(join(getAgentDir(), "pi-selective-sandbox", "host-command-grants.json")) : undefined;
  if (projectGrants) await projectGrants.load();
  if (projectHostGrants) await projectHostGrants.load();
  const project = projectId && projectGrants && projectHostGrants ? { projectId, grants: projectGrants, hostGrants: projectHostGrants } : undefined;
  const loadedConfig = await loadConfig(join(getAgentDir(), "pi-selective-sandbox", "config.json"));
  const writePolicy = loadedConfig.valid
    ? await resolveWritePolicy({ cwd, config: loadedConfig.config, env: process.env })
    : await resolveWritePolicy({
        cwd,
        config: { filesystem: { extraWritableRoots: [], disabledDefaultProfiles: [...DEFAULT_WRITE_PROFILES] } },
        env: process.env
      });
  const gitWritePaths = await resolveGitWritePaths(cwd, writePolicy);
  let runtime: AnthropicSandboxRuntime | undefined;
  let sandboxUnavailableMessage: string | undefined;
  let initialization: Promise<void> | undefined;
  const ensureRuntime = async () => {
    initialization ??= AnthropicSandboxRuntime.initialize({ cwd, writePolicy }).then(value => {
      runtime = value;
      monitorDisabled = process.platform === "darwin" && value.logMonitorEnabled === false;
    });
    try { await initialization; } catch (error) {
      runtime = undefined;
      sandboxUnavailableMessage = sandboxInitializationError(error);
      if (process.platform === "darwin" && error instanceof SandboxInitializationFailure) monitorDisabled = error.logMonitorEnabled === false;
    }
  };
  const isEnabled = async (context?: unknown) => {
    if (!enabled) return false;
    if (process.platform === "darwin") await ensureRuntime();
    if (monitorDisabled && enabled) {
      enabled = false;
      warnMonitorDisabled(context);
    }
    return enabled;
  };
  pi.on("session_shutdown", async () => { await AnthropicSandboxRuntime.reset().catch(() => undefined); });
  const localOperations = createLocalBashOperations();
  const localBash = createBashTool(cwd, {
    operations: { exec: (command, commandCwd, options) => runCommand(localOperations, command, commandCwd, options) }
  });
  pi.registerTool({
    ...localBash,
    async execute(id, params, signal, onUpdate, context) {
      if (!await isEnabled(context)) return redactToolResult(await localBash.execute(id, params, signal, onUpdate));
      await ensureRuntime();
      const sandboxedBash = createBashTool(cwd, {
        operations: {
          async exec(command, commandCwd, options) {
            const runner: CommandRunner = {
              runSandbox: (wrapped, onTrace) => onTrace
                ? runTracedSandbox(wrapped, commandCwd, { ...options, onData: chunk => options.onData(Buffer.from(redact_text(chunk.toString()).redacted)) }, onTrace)
                : runCommand(localOperations, wrapped, commandCwd, options),
              runHost: raw => runCommand(localOperations, raw, commandCwd, options)
            };
            const executor = new SelectiveSandboxExecutor({
              runtime,
              cwd: commandCwd,
              sandboxUnavailableMessage: sandboxUnavailableMessage ?? sandboxInitializationError,
              runner,
              policy: new CapabilityPolicy([], "ask"),
              approvals: createApprovalProvider({ ...context, signal: options.signal }, grants, project, hostGrants, gitWritePaths),
              skills: skills(commandCwd),
              trustedHelpersAutoApprove: true,
              getSandboxCapabilities: async () => { const sessionId = context.sessionManager.getSessionId(); const sessionCapabilities = sessionId ? grants.capabilities(sessionId) : []; const projectCapabilities = project ? await project.grants.capabilities(project.projectId) : []; return [...sessionCapabilities, ...projectCapabilities]; },
              canonicalizeCapabilities: async capabilities => {
                const boundary = await MutationBoundary.create(commandCwd, writePolicy);
                const targets = await Promise.all(capabilities.map(capability => boundary.resolve(capability.resource)));
                if (targets.some(target => target.denied)) return undefined;
                let canonical = capabilities.map((capability, index) => ({ ...capability, resource: targets[index].canonical }));
                const removal = await worktreeRemovalParent(command, commandCwd);
                if (removal && targets.some(target => pathContains(removal.target, target.canonical))) {
                  const removedTarget = await boundary.resolve(removal.target);
                  if (removedTarget.denied) return undefined;
                  if (!removedTarget.allowed) {
                    const parent = await boundary.resolve(removal.parent);
                    if (parent.denied) return undefined;
                    canonical = canonical.filter(capability => !pathContains(removal.target, capability.resource));
                    canonical.push({ kind: "filesystem.write", resource: parent.canonical });
                  }
                }
                // A linked worktree keeps its metadata across worktree and
                // common Git directories. Bundle related roots into one
                // explicit approval so Git staging and branch creation can
                // complete on the approved retry.
                const gitPathsToApprove = [...new Set(targets.flatMap(target => gitApprovalPaths(target.canonical, gitWritePaths)))];
                if (gitPathsToApprove.length > 0) {
                  const metadataTargets = await Promise.all(gitPathsToApprove.map(path => boundary.resolve(path)));
                  if (metadataTargets.some(target => target.denied)) return undefined;
                  // A nested grant becomes a bind mount and can prevent Git
                  // from removing a worktree directory. Keep only the roots.
                  const other = canonical.filter(capability => gitApprovalPaths(capability.resource, gitWritePaths).length === 0);
                  other.push(...gitPathsToApprove.map(resource => ({ kind: "filesystem.write" as const, resource })));
                  return minimalWriteRoots(other);
                }
                return minimalWriteRoots(canonical);
              },
              commandIdentity: async shellCommand => { try { return { shellCommand, cwd: await realpath(commandCwd), executionMode: "shell" }; } catch { return undefined; } },
              onStatus: marker => emitSandboxStatus(marker, options.onData),
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
  const approvalProvider = (context: unknown) => createApprovalProvider(context as ApprovalUI, grants, project, hostGrants, gitWritePaths);
  const mutationOptions = { cwd, writePolicy, approvals: approvalProvider, isEnabled };
  pi.registerTool(await createBoundaryAwareWriteTool(mutationOptions) as never);
  pi.registerTool(await createBoundaryAwareEditTool(mutationOptions) as never);
}

export function emitExecutorOutput(output: Pick<CommandResult, "stdout" | "stderr">, onData: (chunk: Buffer) => void): void {
  if (output.stdout) onData(Buffer.from(output.stdout));
  if (output.stderr) onData(Buffer.from(output.stderr));
}

export function emitSandboxStatus(marker: string, onData: (chunk: Buffer) => void): void {
  onData(Buffer.from(`\n${marker}\n`));
}
