import { createHash } from "node:crypto";
import { findTrustedHelper } from "./skills.js";
import type {
  ApprovalProvider, Capability, CommandResult, CommandRunner, EscalationPolicy,
  ExecutionResult, Redactor, SandboxRuntime, SkillAuthority
} from "./types.js";

export type SelectiveSandboxOptions = {
  runtime?: SandboxRuntime;
  runner: CommandRunner;
  policy: EscalationPolicy;
  approvals?: ApprovalProvider;
  skills?: SkillAuthority;
  redactor?: Redactor;
  trustedHelpersAutoApprove?: boolean;
};

const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const redact = (result: CommandResult, redactor?: Redactor): CommandResult => !redactor ? result : {
  ...result, stdout: redactor.redact(result.stdout), stderr: redactor.redact(result.stderr)
};

export class SelectiveSandboxExecutor {
  constructor(private readonly options: SelectiveSandboxOptions) {}

  async execute(command: string, toolCallId: string, toolName = "bash"): Promise<ExecutionResult> {
    const { runtime, runner, policy, approvals, skills } = this.options;
    if (!runtime) return this.finish({ exitCode: 126, stdout: "", stderr: "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []);

    // This narrow pre-classification is only for authority-proven, syntactically pure helpers.
    if (skills && this.options.trustedHelpersAutoApprove && await findTrustedHelper(command, skills)) {
      return this.finish(await runner.runElevated(command, [{ kind: "host.execute", resource: "trusted-skill-helper" }]), "elevated", []);
    }

    let wrapped: string;
    try { wrapped = await runtime.wrap(command, { commandId: toolCallId, commandText: command }); }
    catch { return this.finish({ exitCode: 126, stdout: "", stderr: "Sandbox unavailable; host execution was not attempted." }, "sandbox-unavailable", []); }
    const first = await runner.run(wrapped);
    // A completed sandbox invocation is final: success never enters escalation.
    if (first.exitCode === 0) return this.finish(first, "sandbox", []);
    const violations = runtime.getViolationsForCommand(toolCallId);
    // Exit status is intentionally irrelevant without attributed runtime evidence.
    if (violations.length === 0) return this.finish(first, "sandbox", []);

    const decision = policy.decide(violations, { command, toolCallId });
    if (decision === "deny") return this.finish({ ...first, stderr: `${first.stderr}\nSandbox blocked: ${violations.map(v => `${v.kind}:${v.resource}`).join(", ")}`.trim() }, "denied", violations);
    if (decision === "ask" || decision === "auto-escalate") {
      if (!approvals) return this.finish({ ...first, stderr: `${first.stderr}\nSandbox escalation requires interactive approval.`.trim() }, "denied", violations);
      const response = await approvals.request({ toolCallId, toolName, inputDigest: digest(command), capabilities: violations, command, replayWarning: true });
      if (response === "deny") return this.finish(first, "denied", violations);
      // A generic command may have already changed allowed state. Never silently replay it.
      // Approval is bound to this exact request; callers must create a fresh call for mutations.
    }
    return this.finish(await runner.runElevated(command, violations as readonly Capability[]), "elevated", violations);
  }

  private finish(result: CommandResult, disposition: ExecutionResult["disposition"], violations: ExecutionResult["violations"]): ExecutionResult {
    return { ...redact(result, this.options.redactor), disposition, violations };
  }
}
