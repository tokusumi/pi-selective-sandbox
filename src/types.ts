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

/** Observation metadata is diagnostic only, never evidence for an approval. */
export type SandboxObservationDiagnostic = { details: string; warning?: string };

export type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type SandboxRuntime = {
  /** True only when endpoint grants are enforced per invocation. */
  supportsNetworkWidening?: boolean;
  wrap(command: string, context: { commandId: string; commandText: string; cwd?: string; extraCapabilities?: readonly Capability[] }): Promise<string>;
  getViolationsForCommand(commandId: string): readonly SandboxViolation[] | Promise<readonly SandboxViolation[]>;
  /** Read before forgetCommand. Details are debug-only; only known monitor problems warn by default. */
  getObservationDiagnostic?(commandId: string): SandboxObservationDiagnostic | undefined;
  traceSinkForCommand?(commandId: string): ((chunk: Buffer) => void) | undefined;
  forgetCommand?(commandId: string): void | Promise<void>;
};

export type CommandRunner = {
  runSandbox(command: string, onTrace?: (chunk: Buffer) => void): Promise<CommandResult>;
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

/** Why a correlated denial cannot currently offer a sandbox resource retry. */
export type WideningUnavailableReason = "filesystem-write-scope-unavailable" | "network-runtime-unsupported" | "network-target-unavailable" | "filesystem-read-unsupported" | "no-additional-scope";

export type EscalationApprovalRequest = Omit<SandboxApprovalRequest, "kind"> & {
  kind: "escalation";
  commandIdentity?: CommandIdentity;
  /** Raw observed targets, distinct from prepared Git/directory-entry scopes. */
  observedCapabilities?: readonly SandboxViolation[];
  /** Diagnostic only; never authorizes host execution or infers a target from shell text. */
  wideningUnavailableReasons?: readonly WideningUnavailableReason[];
};
export type ApprovalRequest = SandboxApprovalRequest | EscalationApprovalRequest;
export type SandboxApprovalDecision = "sandbox-allow-once" | "sandbox-allow-session" | "sandbox-allow-project";
export type SandboxWideningApproval = { decision: SandboxApprovalDecision; capabilities: readonly Capability[] };
export type ApprovalResponse = SandboxApprovalDecision | "host-allow-once" | "host-allow-session" | "host-allow-project" | "deny" | SandboxWideningApproval;
export type ApprovalProvider = { request(request: ApprovalRequest): Promise<ApprovalResponse> };

export type EscalationDecision = "deny" | "auto-escalate" | "ask";
export type EscalationPolicy = { decide(violations: readonly SandboxViolation[], context: { command: string; toolCallId: string }): EscalationDecision; };

export type ActiveSkill = { id: string; root: string; helperRoots?: readonly string[]; trusted: boolean; active: boolean };
export type SkillAuthority = { getActiveSkills(): Promise<readonly ActiveSkill[]> };
export type Redactor = { redact(text: string): string };

export type ExecutionResult = CommandResult & { disposition: "sandbox" | "host" | "denied" | "sandbox-unavailable"; violations: readonly SandboxViolation[]; };
