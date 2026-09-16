export type Capability = {
  kind: "filesystem.read" | "filesystem.write" | "network" | "host.execute";
  resource: string;
};

export type SandboxViolation = Capability & { message?: string };

export type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type SandboxRuntime = {
  wrap(command: string, context: { commandId: string; commandText: string }): Promise<string>;
  getViolationsForCommand(commandId: string): readonly SandboxViolation[];
};

export type CommandRunner = {
  run(command: string): Promise<CommandResult>;
  /** Runs with only the requested extra capabilities, or host execution as a last resort. */
  runElevated(command: string, capabilities: readonly Capability[]): Promise<CommandResult>;
};

export type ApprovalRequest = {
  toolCallId: string;
  toolName: string;
  inputDigest: string;
  capabilities: readonly Capability[];
  command: string;
  replayWarning: boolean;
};

export type ApprovalResponse = "allow-once" | "deny";
export type ApprovalProvider = { request(request: ApprovalRequest): Promise<ApprovalResponse> };

export type EscalationDecision = "deny" | "auto-escalate" | "ask";
export type EscalationPolicy = {
  decide(violations: readonly SandboxViolation[], context: { command: string; toolCallId: string }): EscalationDecision;
};

export type ActiveSkill = { id: string; root: string; helperRoots?: readonly string[]; trusted: boolean; active: boolean };
/** Implemented by pi-skills (or its adapter); this package stores no Skill trust state. */
export type SkillAuthority = { getActiveSkills(): Promise<readonly ActiveSkill[]> };
export type Redactor = { redact(text: string): string };

export type ExecutionResult = CommandResult & {
  disposition: "sandbox" | "elevated" | "denied" | "sandbox-unavailable";
  violations: readonly SandboxViolation[];
};
