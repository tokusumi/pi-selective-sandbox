export type CapabilityKind = "filesystem.read" | "filesystem.write" | "network";
export type CanonicalResource = string;
export type SandboxCapabilityGrant = { kind: "sandbox-capability"; capability: CapabilityKind; resource: CanonicalResource; scope: "once" | "session" | "project" };
export type CommandIdentity = { shellCommand: string; cwd: CanonicalResource; executionMode: string };
export type HostCommandGrant = { kind: "host-command"; command: CommandIdentity; scope: "once" | "session" | "project" };

/** A sandbox capability/resource pair. It never authorizes host execution. */
export type Capability = {
  kind: CapabilityKind;
  resource: string;
};

export type SandboxViolation = Capability & { message?: string };

export type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type SandboxRuntime = {
  wrap(command: string, context: { commandId: string; commandText: string; extraCapabilities?: readonly Capability[] }): Promise<string>;
  getViolationsForCommand(commandId: string): readonly SandboxViolation[];
};

export type CommandRunner = {
  runSandbox(command: string): Promise<CommandResult>;
  runHost(command: string): Promise<CommandResult>;
};

export type SandboxApprovalRequest = {
  kind?: "sandbox-capability";
  toolCallId: string;
  toolName: string;
  inputDigest: string;
  capabilities: readonly Capability[];
  command: string;
  replayWarning: boolean;
  sessionGrantEligible?: boolean;
  projectGrantEligible?: boolean;
};

export type EscalationApprovalRequest = Omit<SandboxApprovalRequest, "kind"> & { kind: "escalation"; commandIdentity: CommandIdentity };
export type ApprovalRequest = SandboxApprovalRequest | EscalationApprovalRequest;
export type ApprovalResponse = "sandbox-allow-once" | "sandbox-allow-session" | "sandbox-allow-project" | "host-allow-once" | "allow-once" | "allow-session" | "allow-project" | "deny";
export type ApprovalProvider = { request(request: ApprovalRequest): Promise<ApprovalResponse> };

export type EscalationDecision = "deny" | "auto-escalate" | "ask";
export type EscalationPolicy = { decide(violations: readonly SandboxViolation[], context: { command: string; toolCallId: string }): EscalationDecision; };

export type ActiveSkill = { id: string; root: string; helperRoots?: readonly string[]; trusted: boolean; active: boolean };
export type SkillAuthority = { getActiveSkills(): Promise<readonly ActiveSkill[]> };
export type Redactor = { redact(text: string): string };

export type ExecutionResult = CommandResult & { disposition: "sandbox" | "host" | "denied" | "sandbox-unavailable"; violations: readonly SandboxViolation[]; };
