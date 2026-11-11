import { ApprovalDiagnostics, type ApprovalTrace } from "./approval-diagnostics.js";
import { createHash, randomUUID } from "node:crypto";
import { validateWideningSelection } from "./resource-selection.js";
import { pathContains } from "./git-write-paths.js";
import { realpath } from "node:fs/promises";
import { findTrustedHelper } from "./skills.js";
import { canonicalNetworkEndpoint } from "./network-policy.js";
import { networkDiagnostics } from "./network-diagnostics.js";
import type { ApprovalProvider, Capability, CommandResult, CommandRunner, CommandIdentity, EscalationPolicy, ExecutionResult, Redactor, SandboxObservationDiagnostic, SandboxRuntime, SkillAuthority, WideningUnavailableReason, SandboxExecutionOptions } from "./types.js";

export type SelectiveSandboxOptions = { diagnostics?: ApprovalDiagnostics; diagnosticActor?: "parent" | "child"; runtime?: SandboxRuntime; cwd?: string; sandboxUnavailableMessage?: string | ((error?: unknown) => string); runner: CommandRunner; policy: EscalationPolicy; approvals?: ApprovalProvider; skills?: SkillAuthority; redactor?: Redactor; onStatus?: (marker: string) => void; onDiagnostic?: (details: string) => void; trustedHelpersAutoApprove?: boolean; getSandboxCapabilities?: (trace?: ApprovalTrace) => Promise<readonly Capability[]>; canonicalizeCapabilities?: (c: readonly Capability[]) => Promise<readonly Capability[] | undefined>; commandIdentity?: (c: string) => Promise<CommandIdentity | undefined> };
const MAX_SANDBOX_APPROVALS = 16;
const digest = (v: string) => createHash("sha256").update(v).digest("hex");
const redact = (r: CommandResult, redactor?: Redactor): CommandResult => !redactor ? r : { ...r, stdout: redactor.redact(r.stdout), stderr: redactor.redact(r.stderr) };

export class SelectiveSandboxExecutor { constructor(private readonly options: SelectiveSandboxOptions) {}
  async execute(command: string, toolCallId: string, toolName = "bash", options: SandboxExecutionOptions = {}): Promise<ExecutionResult> {
    const retryRequested = options.retryOnSandboxDenial === true;
    const { runtime, runner, policy, approvals, skills } = this.options;
    const diagnostics = this.options.diagnostics;
    const operationId = diagnostics ? randomUUID() : undefined;
    const initialTrace: ApprovalTrace | undefined = diagnostics ? { originId: diagnostics.originId, operationId: operationId!, requestId: randomUUID(), attempt: 0,
      actor: this.options.diagnosticActor ?? "parent", tool: "bash", callId: diagnostics.token("call", toolCallId) } : undefined;
    let currentTrace = initialTrace;
    const complete = (output: ExecutionResult) => {
      if (currentTrace) diagnostics!.emit(currentTrace, { event: "operation.end", execution: output.disposition === "host" ? "host" : "sandbox",
        disposition: output.disposition, exitCode: output.exitCode, outcome: output.exitCode === 0 ? "success" : "error" });
      return output;
    };
    if (!runtime) return complete(this.unavailable());
    if (skills && this.options.trustedHelpersAutoApprove && await findTrustedHelper(command, skills)) return complete(this.finish(await runner.runHost(command), "host", []));
    const granted = [...(await this.options.getSandboxCapabilities?.(initialTrace) ?? [])]
      .filter(capability => capability.kind !== "network" || runtime.supportsNetworkWidening);
    let commandId = toolCallId;
    let lastTargets = new Set<string>();
    let approvalsUsed = 0;
    let priorViolations: readonly Capability[] = [];
    for (;;) {
      const trace: ApprovalTrace | undefined = approvalsUsed === 0 ? initialTrace : diagnostics ? { originId: diagnostics.originId, operationId: operationId!, requestId: randomUUID(), attempt: approvalsUsed,
        actor: this.options.diagnosticActor ?? "parent", tool: "bash", callId: initialTrace?.callId } : undefined;
      currentTrace = trace;
      let attempt: CommandResult;
      try { attempt = await this.runSandbox(command, commandId, granted); }
      catch (error) { await runtime.forgetCommand?.(commandId); return complete(this.unavailable(error)); }
      if (trace) diagnostics!.emit(trace, { event: "attempt.result", execution: "sandbox", exitCode: attempt.exitCode, outcome: attempt.exitCode === 0 ? "success" : "error" });
      if (approvalsUsed > 0) this.status(`retry exit=${attempt.exitCode}`);
      if (attempt.exitCode === 0) { await runtime.forgetCommand?.(commandId); return complete(this.finish(attempt, "sandbox", priorViolations)); }

      let observed;
      let observationDiagnostic: SandboxObservationDiagnostic | undefined;
      try {
        observed = await runtime.getViolationsForCommand(commandId);
        observationDiagnostic = runtime.getObservationDiagnostic?.(commandId);
      }
      finally { await runtime.forgetCommand?.(commandId); }
      if (observed.length === 0) {
        if (observationDiagnostic) {
          this.options.onDiagnostic?.(this.options.redactor?.redact(observationDiagnostic.details) ?? observationDiagnostic.details);
          if (observationDiagnostic.warning) {
            this.status("observation-unavailable");
            attempt = { ...attempt, stderr: `${attempt.stderr}${attempt.stderr.endsWith("\n") || !attempt.stderr ? "" : "\n"}${observationDiagnostic.warning}\n` };
          }
        }
        return complete(this.finish(attempt, "sandbox", priorViolations));
      }
      const targetIds = diagnostics?.scopes(observed) ?? [];
      const currentTargets = new Set(targetIds.map(target => target.id));
      const repeated = [...currentTargets].filter(id => lastTargets.has(id)).length;
      const relation = lastTargets.size === 0 ? "first" : repeated === currentTargets.size && currentTargets.size === lastTargets.size ? "same" : repeated === 0 ? "new" : "mixed";
      if (trace) diagnostics!.emit(trace, { event: "attempt.denial", observed: targetIds, relation,
        network: networkDiagnostics(observed, resource => diagnostics!.token("scope", `network\0${resource}`)) });
      lastTargets = currentTargets;
      // A nonzero exit and correlated denial do not establish that replay is
      // useful. Return the command result unless THIS invocation requested it.
      // Gate before scope preparation and provider lookup (including host grants).
      if (!retryRequested) {
        if (trace) diagnostics!.emit(trace, { event: "retry", reason: "not-requested", outcome: "skipped", relation });
        this.status("denial-observed retry-not-requested");
        return complete({ ...this.finish(attempt, "sandbox", observed), retryNotRequested: true });
      }
      const writeCandidates = observed.filter(violation => violation.kind === "filesystem.write");
      const prepared = writeCandidates.length ? await (this.options.canonicalizeCapabilities?.(writeCandidates) ?? writeCandidates) : [];
      const wideningBlocked = prepared === undefined;
      const networkCandidates: Capability[] = runtime.supportsNetworkWidening ? observed.flatMap(violation => {
        const resource = violation.kind === "network" ? canonicalNetworkEndpoint(violation.resource) : undefined;
        return resource ? [{ kind: "network" as const, resource }] : [];
      }) : [];
      const covered = (candidate: Capability) => granted.some(capability => capability.kind === candidate.kind
        && (capability.kind === "filesystem.write" ? pathContains(capability.resource, candidate.resource) : capability.resource === candidate.resource));
      const candidates = [...(prepared ?? []), ...networkCandidates];
      const caps = wideningBlocked ? [] : [...new Map(candidates.map(candidate => [`${candidate.kind}\0${candidate.resource}`, candidate])).values()]
        .filter(candidate => !covered(candidate));
      const uncovered = observed.filter(violation => !covered(violation));
      if (trace) for (const candidate of candidates) diagnostics!.emit(trace, { event: "coverage", authority: "resource", outcome: covered(candidate) ? "hit" : "miss", scopes: diagnostics!.scopes([candidate]) });
      // Covered telemetry cannot make another retry useful. Unsupported
      // network/read denials can still offer exact-command host replay.
      if (!wideningBlocked && caps.length === 0 && (uncovered.length === 0 || uncovered.every(violation => violation.kind === "filesystem.write"))) {
        if (trace) diagnostics!.emit(trace, { event: "retry", reason: "covered", outcome: "skipped", relation });
        return complete(this.finish(attempt, "sandbox", observed));
      }
      const violations = uncovered.length > 0 ? uncovered : observed;
      if (policy.decide(violations, { command, toolCallId }) === "deny" || !approvals) {
        if (trace) diagnostics!.emit(trace, { event: "retry", reason: "policy", outcome: "skipped", relation });
        return complete(this.finish(attempt, "denied", violations));
      }
      if (approvalsUsed >= MAX_SANDBOX_APPROVALS) {
        if (trace) diagnostics!.emit(trace, { event: "retry", reason: "limit", outcome: "skipped", relation });
        return complete(this.finish(attempt, "sandbox", violations));
      }
      const commandIdentity = await (this.options.commandIdentity ?? (async shellCommand => { try { return { shellCommand, cwd: await realpath(process.cwd()), executionMode: "shell" }; } catch { return undefined; } }))(command);
      const wideningUnavailableReasons: WideningUnavailableReason[] = [];
      if (caps.length === 0) {
        if (wideningBlocked) wideningUnavailableReasons.push("filesystem-write-scope-unavailable");
        else {
          if (violations.some(violation => violation.kind === "filesystem.read")) wideningUnavailableReasons.push("filesystem-read-unsupported");
          if (violations.some(violation => violation.kind === "network")) {
            if (!runtime.supportsNetworkWidening) wideningUnavailableReasons.push("network-runtime-unsupported");
            else if (violations.some(violation => violation.kind === "network" && !canonicalNetworkEndpoint(violation.resource))) wideningUnavailableReasons.push("network-target-unavailable");
          }
          if (wideningUnavailableReasons.length === 0) wideningUnavailableReasons.push("no-additional-scope");
        }
      }
      this.status(`approval-required ${violations[0].kind}`);
      // Keep all observed targets for diagnostics: even a stored write grant
      // cannot override a deny root that suppressed the resource candidates.
      const response = await approvals.request({ diagnosticContext: operationId ? { operationId, attempt: approvalsUsed, requestId: trace?.requestId } : undefined, kind: "escalation", toolCallId, toolName, inputDigest: digest(command), capabilities: caps, observedCapabilities: observed, wideningUnavailableReasons, command, replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true, commandIdentity });
      const decision = typeof response === "string" ? response : response.decision;
      if (decision === "host-allow-once" || decision === "host-allow-session" || decision === "host-allow-project") {
        if (trace) diagnostics!.emit(trace, { event: "retry", reason: "host", authority: "host", outcome: "allow", relation });
        this.status("approved host-replay");
        let replay: CommandResult;
        try { replay = await runner.runHost(command); }
        catch (error) {
          if (trace) {
            diagnostics!.emit(trace, { event: "attempt.result", execution: "host", outcome: "error" });
            diagnostics!.emit(trace, { event: "operation.end", execution: "host", disposition: "host", outcome: "error" });
          }
          throw error;
        }
        if (trace) diagnostics!.emit(trace, { event: "attempt.result", execution: "host", exitCode: replay.exitCode, outcome: replay.exitCode === 0 ? "success" : "error" });
        this.status(`replay exit=${replay.exitCode}`);
        return complete(this.finish(replay, "host", violations));
      }
      const selected = typeof response === "string" ? caps : response.capabilities;
      if (decision === "deny" || caps.length === 0 || (typeof response !== "string" && !await validateWideningSelection(caps, selected))) {
        if (trace) diagnostics!.emit(trace, { event: "retry", outcome: "deny", relation });
        this.status("approval-denied"); return complete(this.finish(attempt, "denied", violations));
      }
      if (trace) diagnostics!.emit(trace, { event: "retry", reason: "widen", authority: "resource", outcome: "allow", relation, scopes: diagnostics!.scopes(selected) });
      this.status("approved widen retry");
      granted.push(...selected);
      priorViolations = violations;
      approvalsUsed++;
      commandId = `${toolCallId}:widened:${approvalsUsed}`;
    }
  }
  private status(value: string): void { this.options.onStatus?.(`<sandbox: ${value}>`); }
  private async runSandbox(command: string, commandId: string, caps: readonly Capability[]): Promise<CommandResult> { const runtime = this.options.runtime!; const wrapped = await runtime.wrap(command, { commandId, commandText: command, cwd: this.options.cwd, extraCapabilities: caps }); return this.options.runner.runSandbox(wrapped, runtime.traceSinkForCommand?.(commandId)); }
  private unavailable(error?: unknown): ExecutionResult {
    const configured = this.options.sandboxUnavailableMessage;
    const message = typeof configured === "function" ? configured(error) : configured;
    return this.finish({ exitCode: 126, stdout: "", stderr: message ?? "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []);
  }
  private finish(result: CommandResult, disposition: ExecutionResult["disposition"], violations: ExecutionResult["violations"]): ExecutionResult { return { ...redact(result, this.options.redactor), disposition, violations }; }
}
