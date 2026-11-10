import { approvalSelect, auditEvent, lookupResult, lookupStart, sessionPersistence } from "./approval-diagnostics.js";
import { pathContains, type GitWritePaths } from "./git-write-paths.js";
import { collapseWriteScopes, validateWideningSelection } from "./resource-selection.js";
import { displayText, durationLabels, showWideningDialog, type ApprovalDuration, type EscalationUI, type WideningDialogOptions } from "./widening-dialog.js";
import type { ProjectGrantStore } from "./project-grants.js";
import type { ProjectHostCommandGrantStore } from "./project-host-command-grants.js";
import type { SessionGrantStore } from "./session-grants.js";
import type { SessionHostCommandGrantStore } from "./session-host-command-grants.js";
import type { ApprovalResponse, Capability, EscalationApprovalRequest, SandboxApprovalDecision, WideningUnavailableReason } from "./types.js";

export type ApprovalProject = { projectId: string; grants: ProjectGrantStore; hostGrants?: ProjectHostCommandGrantStore };

const unavailableMessages = {
  "filesystem-write-scope-unavailable": "Filesystem write scope preparation rejected widening. A configured deny root may cover a target or its required Git/directory scope. No sandbox resource retry is offered for this attempt, including any network targets.",
  "network-runtime-unsupported": "This runtime does not support sandbox network widening.",
  "network-target-unavailable": "The network denial does not identify an approvable exact proxy host:port. Socket denials and DNS/private-address protection failures cannot be widened by inferring a destination from the command.",
  "filesystem-read-unsupported": "Sandbox filesystem-read widening is not supported.",
  "no-additional-scope": "No additional supported sandbox resource scope is available; another resource retry would not add authority."
} satisfies Record<WideningUnavailableReason, string>;

function hostOnlySummary(request: EscalationApprovalRequest): string {
  const targets = request.observedCapabilities ?? [];
  return [
    "Sandbox blocked this operation.", "", "Observed sandbox denials",
    ...targets.flatMap(target => [`  ${target.kind}: ${displayText(target.resource)}`, ...(target.message ? [`    ${displayText(target.message)}`] : [])]),
    ...(targets.length === 0 ? ["  No target details are available."] : []),
    "", "Why sandbox retry is unavailable",
    ...(request.wideningUnavailableReasons?.length ? request.wideningUnavailableReasons.map(reason => unavailableMessages[reason])
      : ["No supported sandbox resource scope is available for these denials."]),
    "", "These denials are correlated with this attempt; they do not establish the cause of every command error (including TLS certificate verification failures).",
    "", "Command", displayText(request.command),
    ...(request.commandIdentity ? [`Working directory: ${displayText(request.commandIdentity.cwd)}`] : []),
    "", "Run outside sandbox… requires separate exact-command confirmation. Sandbox protections will not apply.",
    "The entire command will run again and may repeat earlier side effects. Deny keeps the failed sandbox result without retry or host replay."
  ].join("\n");
}

export function isBroadGitParent(capabilities: readonly Capability[], gitWritePaths?: GitWritePaths): boolean {
  return gitWritePaths !== undefined && capabilities.some(capability => capability.kind === "filesystem.write"
    && capability.resource !== gitWritePaths.commonDir && pathContains(capability.resource, gitWritePaths.commonDir));
}

export async function requestEscalationApproval(context: EscalationUI, request: EscalationApprovalRequest, grants: SessionGrantStore, project: ApprovalProject | undefined, hostGrants: SessionHostCommandGrantStore, gitWritePaths?: GitWritePaths): Promise<ApprovalResponse> {
  if (context.signal?.aborted) return "deny";
  const sessionId = request.sessionGrantEligible ? context.sessionManager?.getSessionId() : undefined;
  const hostCommand = request.commandIdentity;
  const audit = context.approvalAudit;
  if (lookupResult(audit, "host", "project", hostCommand && project?.hostGrants ? await (lookupStart(audit, "host", "project"), project.hostGrants.covers(project.projectId, hostCommand)) : undefined)) return "host-allow-project";
  if (lookupResult(audit, "host", "session", hostCommand && sessionId ? (lookupStart(audit, "host", "session"), hostGrants.covers(sessionId, hostCommand)) : undefined)) return "host-allow-session";
  const durations = (capabilities: readonly Capability[]): ApprovalDuration[] => {
    const available: ApprovalDuration[] = ["once"];
    if (isBroadGitParent(capabilities, gitWritePaths)) return available;
    if (sessionId) available.push("session");
    if (request.projectGrantEligible && project) available.push("project");
    return available;
  };
  const eligible = durations(request.capabilities);
  if (lookupResult(audit, "resource", "project", request.capabilities.length > 0 && eligible.includes("project") && project ? await (lookupStart(audit, "resource", "project"), project.grants.covers(project.projectId, request.capabilities)) : undefined)) return "sandbox-allow-project";
  if (lookupResult(audit, "resource", "session", request.capabilities.length > 0 && eligible.includes("session") && sessionId ? (lookupStart(audit, "resource", "session"), grants.covers(sessionId, request.capabilities)) : undefined)) return "sandbox-allow-session";
  if (!context.hasUI || !context.ui) { auditEvent(audit, { event: "provider.skip", outcome: "unavailable", reason: "headless" }); return "deny"; }
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
    : { action: await approvalSelect(context, "action", hostOnlySummary(request), ["Run outside sandbox…", "Deny"], { signal: context.signal }) === "Run outside sandbox…" ? "host" as const : "deny" as const };
  if (context.signal?.aborted) return "deny";
  if (choice.action === "host") return requestHostApproval(context, request, sessionId, project, hostGrants);
  if (choice.action !== "allow") return "deny";
  if (!durations(choice.capabilities).includes(choice.duration) || !await validateWideningSelection(request.capabilities, choice.capabilities) || context.signal?.aborted) return "deny";
  const capabilities = collapseWriteScopes(choice.capabilities);
  const decision: SandboxApprovalDecision = `sandbox-allow-${choice.duration}`;
  auditEvent(audit, { event: "approval.selection", authority: "resource", duration: choice.duration, scopes: audit?.diagnostics.scopes(capabilities) });
  if (choice.duration === "project" && project) {
    try { await project.grants.grant(project.projectId, capabilities); auditEvent(audit, { event: "persist", authority: "resource", duration: "project", outcome: "success", scopes: audit?.diagnostics.scopes(capabilities) }); }
    catch { auditEvent(audit, { event: "persist", authority: "resource", duration: "project", outcome: "error" }); return "deny"; }
  }
  if (choice.duration === "session" && sessionId) sessionPersistence(audit, "resource", () => grants.grant(sessionId, capabilities));
  return { decision, capabilities };
}

/** Host approval is a separate duration + exact-command confirmation, never a resource permission. */
async function requestHostApproval(context: EscalationUI, request: EscalationApprovalRequest, sessionId: string | undefined, project: ApprovalProject | undefined, hosts: SessionHostCommandGrantStore): Promise<ApprovalResponse> {
  if (!context.ui || context.signal?.aborted) return "deny";
  const command = request.commandIdentity;
  const available: ApprovalDuration[] = ["once"];
  if (command && sessionId) available.push("session");
  if (command && project?.hostGrants) available.push("project");
  const chosen = await approvalSelect(context, "host-duration", "Run outside sandbox — duration", available.map(value => durationLabels[value]), { signal: context.signal });
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
  if (await approvalSelect(context, "host-confirm", message, ["Run on host", "Deny"], { signal: context.signal }) !== "Run on host" || context.signal?.aborted) return "deny";
  auditEvent(context.approvalAudit, { event: "approval.selection", authority: "host", duration });
  if (duration === "project" && command && project?.hostGrants) {
    try { await project.hostGrants.grant(project.projectId, command); auditEvent(context.approvalAudit, { event: "persist", authority: "host", duration: "project", outcome: "success" }); }
    catch { auditEvent(context.approvalAudit, { event: "persist", authority: "host", duration: "project", outcome: "error" }); return "deny"; }
  }
  if (duration === "session" && sessionId && command) sessionPersistence(context.approvalAudit, "host", () => hosts.grant(sessionId, command));
  return `host-allow-${duration}`;
}
