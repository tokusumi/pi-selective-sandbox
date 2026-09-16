import type { EscalationDecision, EscalationPolicy, SandboxViolation } from "./types.js";

export type CapabilityRule = { kind: SandboxViolation["kind"]; resource?: RegExp; decision: EscalationDecision };

/** Resource/capability rules, deliberately not command-prefix rules. */
export class CapabilityPolicy implements EscalationPolicy {
  constructor(private readonly rules: readonly CapabilityRule[], private readonly fallback: EscalationDecision = "ask") {}
  decide(violations: readonly SandboxViolation[]): EscalationDecision {
    const decisions = violations.map(v => this.rules.find(r => r.kind === v.kind && (!r.resource || r.resource.test(v.resource)))?.decision ?? this.fallback);
    return decisions.includes("deny") ? "deny" : decisions.includes("ask") ? "ask" : "auto-escalate";
  }
}
