import { createHash } from "node:crypto";
import { findTrustedHelper } from "./skills.js";
import type { ApprovalProvider, Capability, CommandResult, CommandRunner, CommandIdentity, EscalationPolicy, ExecutionResult, Redactor, SandboxRuntime, SkillAuthority } from "./types.js";

export type SelectiveSandboxOptions = { runtime?: SandboxRuntime; runner: CommandRunner; policy: EscalationPolicy; approvals?: ApprovalProvider; skills?: SkillAuthority; redactor?: Redactor; trustedHelpersAutoApprove?: boolean; getSandboxCapabilities?: () => Promise<readonly Capability[]>; canonicalizeCapabilities?: (c: readonly Capability[]) => Promise<readonly Capability[]>; commandIdentity?: (c: string) => CommandIdentity };
const digest = (v: string) => createHash("sha256").update(v).digest("hex");
const redact = (r: CommandResult, redactor?: Redactor): CommandResult => !redactor ? r : { ...r, stdout: redactor.redact(r.stdout), stderr: redactor.redact(r.stderr) };

export class SelectiveSandboxExecutor { constructor(private readonly options: SelectiveSandboxOptions) {}
  async execute(command: string, toolCallId: string, toolName = "bash"): Promise<ExecutionResult> {
    const { runtime, runner, policy, approvals, skills } = this.options;
    if (!runtime) return this.finish({ exitCode: 126, stdout: "", stderr: "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []);
    if (skills && this.options.trustedHelpersAutoApprove && await findTrustedHelper(command, skills)) return this.finish(await runner.runHost(command), "host", []);
    const stored = await this.options.getSandboxCapabilities?.() ?? [];
    let first: CommandResult; try { first = await this.runSandbox(command, toolCallId, stored); } catch { return this.finish({ exitCode: 126, stdout: "", stderr: "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []); }
    if (first.exitCode === 0) return this.finish(first, "sandbox", []);
    const violations = runtime.getViolationsForCommand(toolCallId); if (violations.length === 0) return this.finish(first, "sandbox", []);
    if (policy.decide(violations, { command, toolCallId }) === "deny" || !approvals) return this.finish(first, "denied", violations);
    const candidates = violations.filter(v => v.kind === "filesystem.write");
    const caps = candidates.length ? await (this.options.canonicalizeCapabilities?.(candidates) ?? candidates) : [];
    const response = await approvals.request({ kind: "escalation", toolCallId, toolName, inputDigest: digest(command), capabilities: caps, command, replayWarning: true, sessionGrantEligible: true, projectGrantEligible: true, commandIdentity: (this.options.commandIdentity ?? (shellCommand => ({ shellCommand, cwd: process.cwd(), executionMode: "shell" })))(command) });
    if (response === "host-allow-once") return this.finish(await runner.runHost(command), "host", violations);
    if (response === "deny" || caps.length === 0) return this.finish(first, "denied", violations);
    return this.finish(await this.runSandbox(command, toolCallId + ":widened", [...stored, ...caps]), "sandbox", violations);
  }
  private async runSandbox(command: string, commandId: string, caps: readonly Capability[]): Promise<CommandResult> { const runtime = this.options.runtime!; return this.options.runner.runSandbox(await runtime.wrap(command, { commandId, commandText: command, extraCapabilities: caps })); }
  private finish(result: CommandResult, disposition: ExecutionResult["disposition"], violations: ExecutionResult["violations"]): ExecutionResult { return { ...redact(result, this.options.redactor), disposition, violations }; }
}
