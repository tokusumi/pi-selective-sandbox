import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { findTrustedHelper } from "./skills.js";
import type { ApprovalProvider, Capability, CommandResult, CommandRunner, CommandIdentity, EscalationPolicy, ExecutionResult, Redactor, SandboxRuntime, SkillAuthority } from "./types.js";

export type SelectiveSandboxOptions = { runtime?: SandboxRuntime; sandboxUnavailableMessage?: string | ((error?: unknown) => string); runner: CommandRunner; policy: EscalationPolicy; approvals?: ApprovalProvider; skills?: SkillAuthority; redactor?: Redactor; trustedHelpersAutoApprove?: boolean; getSandboxCapabilities?: () => Promise<readonly Capability[]>; canonicalizeCapabilities?: (c: readonly Capability[]) => Promise<readonly Capability[] | undefined>; commandIdentity?: (c: string) => Promise<CommandIdentity | undefined> };
const digest = (v: string) => createHash("sha256").update(v).digest("hex");
const redact = (r: CommandResult, redactor?: Redactor): CommandResult => !redactor ? r : { ...r, stdout: redactor.redact(r.stdout), stderr: redactor.redact(r.stderr) };

export class SelectiveSandboxExecutor { constructor(private readonly options: SelectiveSandboxOptions) {}
  async execute(command: string, toolCallId: string, toolName = "bash"): Promise<ExecutionResult> {
    const { runtime, runner, policy, approvals, skills } = this.options;
    if (!runtime) return this.unavailable();
    if (skills && this.options.trustedHelpersAutoApprove && await findTrustedHelper(command, skills)) return this.finish(await runner.runHost(command), "host", []);
    const stored = await this.options.getSandboxCapabilities?.() ?? [];
    let first: CommandResult; try { first = await this.runSandbox(command, toolCallId, stored); } catch (error) { return this.unavailable(error); }
    if (first.exitCode === 0) return this.finish(first, "sandbox", []);
    const observed = runtime.getViolationsForCommand(toolCallId);
    const writeCandidates = observed.filter(violation => violation.kind === "filesystem.write");
    const prepared = writeCandidates.length ? await (this.options.canonicalizeCapabilities?.(writeCandidates) ?? writeCandidates) : [];
    const wideningBlocked = prepared === undefined;
    const uncovered = observed.filter(violation => !stored.some(capability => capability.kind === violation.kind && capability.resource === violation.resource));
    if (uncovered.length === 0 && !wideningBlocked) return this.finish(first, "sandbox", []);
    const violations = uncovered.length > 0 ? uncovered : observed;
    if (policy.decide(violations, { command, toolCallId }) === "deny" || !approvals) return this.finish(first, "denied", violations);
    const caps = wideningBlocked ? [] : prepared.filter(candidate => !stored.some(capability => capability.kind === candidate.kind && capability.resource === candidate.resource));
    const commandIdentity = await (this.options.commandIdentity ?? (async shellCommand => { try { return { shellCommand, cwd: await realpath(process.cwd()), executionMode: "shell" }; } catch { return undefined; } }))(command);
    const response = await approvals.request({ kind: "escalation", toolCallId, toolName, inputDigest: digest(command), capabilities: caps, command, replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true, commandIdentity });
    if (response === "host-allow-once" || response === "host-allow-session" || response === "host-allow-project") return this.finish(await runner.runHost(command), "host", violations);
    if (response === "deny" || caps.length === 0) return this.finish(first, "denied", violations);
    return this.finish(await this.runSandbox(command, toolCallId + ":widened", [...stored, ...caps]), "sandbox", violations);
  }
  private async runSandbox(command: string, commandId: string, caps: readonly Capability[]): Promise<CommandResult> { const runtime = this.options.runtime!; return this.options.runner.runSandbox(await runtime.wrap(command, { commandId, commandText: command, extraCapabilities: caps })); }
  private unavailable(error?: unknown): ExecutionResult {
    const configured = this.options.sandboxUnavailableMessage;
    const message = typeof configured === "function" ? configured(error) : configured;
    return this.finish({ exitCode: 126, stdout: "", stderr: message ?? "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []);
  }
  private finish(result: CommandResult, disposition: ExecutionResult["disposition"], violations: ExecutionResult["violations"]): ExecutionResult { return { ...redact(result, this.options.redactor), disposition, violations }; }
}
