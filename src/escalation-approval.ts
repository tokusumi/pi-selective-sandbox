import { pathContains, type GitWritePaths } from "./git-write-paths.js";
import { collapseWriteScopes, validateWideningSelection } from "./resource-selection.js";
import { displayText, durationLabels, showWideningDialog, type ApprovalDuration, type EscalationUI, type WideningDialogOptions } from "./widening-dialog.js";
import type { ProjectGrantStore } from "./project-grants.js";
import type { ProjectHostCommandGrantStore } from "./project-host-command-grants.js";
import type { SessionGrantStore } from "./session-grants.js";
import type { SessionHostCommandGrantStore } from "./session-host-command-grants.js";
import type { ApprovalResponse, Capability, EscalationApprovalRequest, SandboxApprovalDecision } from "./types.js";

export type ApprovalProject = { projectId: string; grants: ProjectGrantStore; hostGrants?: ProjectHostCommandGrantStore };

export function isBroadGitParent(capabilities: readonly Capability[], gitWritePaths?: GitWritePaths): boolean {
  return gitWritePaths !== undefined && capabilities.some(capability => capability.kind === "filesystem.write"
    && capability.resource !== gitWritePaths.commonDir && pathContains(capability.resource, gitWritePaths.commonDir));
}

export async function requestEscalationApproval(context: EscalationUI, request: EscalationApprovalRequest, grants: SessionGrantStore, project: ApprovalProject | undefined, hostGrants: SessionHostCommandGrantStore, gitWritePaths?: GitWritePaths): Promise<ApprovalResponse> {
  if (context.signal?.aborted) return "deny";
  const sessionId = request.sessionGrantEligible ? context.sessionManager?.getSessionId() : undefined;
  const hostCommand = request.commandIdentity;
  if (hostCommand && project?.hostGrants && await project.hostGrants.covers(project.projectId, hostCommand)) return "host-allow-project";
  if (hostCommand && sessionId && hostGrants.covers(sessionId, hostCommand)) return "host-allow-session";
  const durations = (capabilities: readonly Capability[]): ApprovalDuration[] => {
    const available: ApprovalDuration[] = ["once"];
    if (isBroadGitParent(capabilities, gitWritePaths)) return available;
    if (sessionId) available.push("session");
    if (request.projectGrantEligible && project) available.push("project");
    return available;
  };
  const eligible = durations(request.capabilities);
  if (request.capabilities.length > 0) {
    if (eligible.includes("project") && project && await project.grants.covers(project.projectId, request.capabilities)) return "sandbox-allow-project";
    if (eligible.includes("session") && sessionId && grants.covers(sessionId, request.capabilities)) return "sandbox-allow-session";
  }
  if (!context.hasUI || !context.ui) return "deny";
  const options: WideningDialogOptions = {
    request, durations, projectId: project?.projectId,
    warnings(capabilities) {
      const warnings: string[] = [];
      if (capabilities.some(capability => (gitWritePaths !== undefined
        && (pathContains(capability.resource, gitWritePaths.commonDir) || pathContains(capability.resource, gitWritePaths.worktreeDir)))
        || /(?:^|\/)\.git(?:\/|$)/.test(capability.resource))) {
        warnings.push("A shared Git directory grant also permits changes to other worktrees' Git metadata, refs, configuration, and hooks.");
      }
      if (isBroadGitParent(capabilities, gitWritePaths)) warnings.push("This parent-directory grant also permits writes to unrelated sibling paths. Only Once is available for a parent of shared Git metadata.");
      return warnings;
    }
  };
  const choice = request.capabilities.length > 0
    ? await showWideningDialog(context, options)
    : { action: await context.ui.select("Sandbox blocked this operation.\nNo supported write scope is available, or a configured deny root prevents widening.\n\nCommand\n" + displayText(request.command), ["Run outside sandbox…", "Deny"], { signal: context.signal }) === "Run outside sandbox…" ? "host" as const : "deny" as const };
  if (context.signal?.aborted) return "deny";
  if (choice.action === "host") return requestHostApproval(context, request, sessionId, project, hostGrants);
  if (choice.action !== "allow") return "deny";
  if (!durations(choice.capabilities).includes(choice.duration) || !await validateWideningSelection(request.capabilities, choice.capabilities) || context.signal?.aborted) return "deny";
  const capabilities = collapseWriteScopes(choice.capabilities);
  const decision: SandboxApprovalDecision = `sandbox-allow-${choice.duration}`;
  if (choice.duration === "project" && project) {
    try { await project.grants.grant(project.projectId, capabilities); } catch { return "deny"; }
  }
  if (choice.duration === "session" && sessionId) grants.grant(sessionId, capabilities);
  return { decision, capabilities };
}

/** Host approval is a separate duration + exact-command confirmation, never a resource permission. */
async function requestHostApproval(context: EscalationUI, request: EscalationApprovalRequest, sessionId: string | undefined, project: ApprovalProject | undefined, hosts: SessionHostCommandGrantStore): Promise<ApprovalResponse> {
  if (!context.ui || context.signal?.aborted) return "deny";
  const command = request.commandIdentity;
  const available: ApprovalDuration[] = ["once"];
  if (command && sessionId) available.push("session");
  if (command && project?.hostGrants) available.push("project");
  const chosen = await context.ui.select("Run outside sandbox — duration", available.map(value => durationLabels[value]), { signal: context.signal });
  const duration = available.find(value => durationLabels[value] === chosen);
  if (!duration) return "deny";
  const message = [
    "Run exact command outside sandbox", "WARNING: Sandbox protections will not apply to this execution.",
    "", "Command", displayText(request.command),
    ...(command ? [`Working directory: ${displayText(command.cwd)}`, `Execution mode: ${displayText(command.executionMode)}`]
      : ["Working directory could not be canonicalized. Only Once is available."]),
    `Duration: ${durationLabels[duration]}`,
    ...(duration === "project" && project ? [`Project: ${displayText(project.projectId)}`] : []),
    "", "The entire command will run again and may repeat earlier side effects.",
    "This approval is for the exact command, working directory and execution mode — not a resource permission."
  ].join("\n");
  if (await context.ui.select(message, ["Run on host", "Deny"], { signal: context.signal }) !== "Run on host" || context.signal?.aborted) return "deny";
  if (duration === "project" && command && project?.hostGrants) {
    try { await project.hostGrants.grant(project.projectId, command); } catch { return "deny"; }
  }
  if (duration === "session" && sessionId && command) hosts.grant(sessionId, command);
  return `host-allow-${duration}`;
}
