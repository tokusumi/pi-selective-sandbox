import { createHash } from "node:crypto";
import { validateWideningSelection } from "./resource-selection.js";
import { pathContains } from "./git-write-paths.js";
import { realpath } from "node:fs/promises";
import { findTrustedHelper } from "./skills.js";
import type { ApprovalProvider, Capability, CommandResult, CommandRunner, CommandIdentity, EscalationPolicy, ExecutionResult, Redactor, SandboxRuntime, SkillAuthority } from "./types.js";

export type SelectiveSandboxOptions = { runtime?: SandboxRuntime; cwd?: string; sandboxUnavailableMessage?: string | ((error?: unknown) => string); runner: CommandRunner; policy: EscalationPolicy; approvals?: ApprovalProvider; skills?: SkillAuthority; redactor?: Redactor; onStatus?: (marker: string) => void; trustedHelpersAutoApprove?: boolean; getSandboxCapabilities?: () => Promise<readonly Capability[]>; canonicalizeCapabilities?: (c: readonly Capability[]) => Promise<readonly Capability[] | undefined>; commandIdentity?: (c: string) => Promise<CommandIdentity | undefined> };
const MAX_SANDBOX_APPROVALS = 16;
const digest = (v: string) => createHash("sha256").update(v).digest("hex");
const redact = (r: CommandResult, redactor?: Redactor): CommandResult => !redactor ? r : { ...r, stdout: redactor.redact(r.stdout), stderr: redactor.redact(r.stderr) };

export class SelectiveSandboxExecutor { constructor(private readonly options: SelectiveSandboxOptions) {}
  async execute(command: string, toolCallId: string, toolName = "bash"): Promise<ExecutionResult> {
    const { runtime, runner, policy, approvals, skills } = this.options;
    if (!runtime) return this.unavailable();
    if (skills && this.options.trustedHelpersAutoApprove && await findTrustedHelper(command, skills)) return this.finish(await runner.runHost(command), "host", []);
    const granted = [...(await this.options.getSandboxCapabilities?.() ?? [])];
    let commandId = toolCallId;
    let approvalsUsed = 0;
    let priorViolations: readonly Capability[] = [];
    for (;;) {
      let attempt: CommandResult;
      try { attempt = await this.runSandbox(command, commandId, granted); }
      catch (error) { runtime.forgetCommand?.(commandId); return this.unavailable(error); }
      if (approvalsUsed > 0) this.status(`retry exit=${attempt.exitCode}`);
      if (attempt.exitCode === 0) { runtime.forgetCommand?.(commandId); return this.finish(attempt, "sandbox", priorViolations); }

      let observed;
      try { observed = await runtime.getViolationsForCommand(commandId); }
      finally { runtime.forgetCommand?.(commandId); }
      if (observed.length === 0) return this.finish(attempt, "sandbox", priorViolations);
      const writeCandidates = observed.filter(violation => violation.kind === "filesystem.write");
      const prepared = writeCandidates.length ? await (this.options.canonicalizeCapabilities?.(writeCandidates) ?? writeCandidates) : [];
      const wideningBlocked = prepared === undefined;
      const covered = (candidate: Capability) => granted.some(capability => capability.kind === candidate.kind
        && (capability.kind === "filesystem.write" ? pathContains(capability.resource, candidate.resource) : capability.resource === candidate.resource));
      const caps = wideningBlocked ? [] : prepared.filter(candidate => !covered(candidate));
      const uncovered = observed.filter(violation => !covered(violation));
      // A write already covered by the current authority cannot make another
      // retry useful. Other violation kinds can still offer host replay.
      if (!wideningBlocked && caps.length === 0 && uncovered.every(violation => violation.kind === "filesystem.write")) return this.finish(attempt, "sandbox", observed);
      const violations = uncovered.length > 0 ? uncovered : observed;
      if (policy.decide(violations, { command, toolCallId }) === "deny" || !approvals) return this.finish(attempt, "denied", violations);
      if (approvalsUsed >= MAX_SANDBOX_APPROVALS) return this.finish(attempt, "sandbox", violations);
      const commandIdentity = await (this.options.commandIdentity ?? (async shellCommand => { try { return { shellCommand, cwd: await realpath(process.cwd()), executionMode: "shell" }; } catch { return undefined; } }))(command);
      this.status(`approval-required ${violations[0].kind}`);
      const response = await approvals.request({ kind: "escalation", toolCallId, toolName, inputDigest: digest(command), capabilities: caps, observedCapabilities: violations, command, replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true, commandIdentity });
      const decision = typeof response === "string" ? response : response.decision;
      if (decision === "host-allow-once" || decision === "host-allow-session" || decision === "host-allow-project") {
        this.status("approved host-replay");
        const replay = await runner.runHost(command);
        this.status(`replay exit=${replay.exitCode}`);
        return this.finish(replay, "host", violations);
      }
      const selected = typeof response === "string" ? caps : response.capabilities;
      if (decision === "deny" || caps.length === 0 || (typeof response !== "string" && !await validateWideningSelection(caps, selected))) {
        this.status("approval-denied"); return this.finish(attempt, "denied", violations);
      }
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
