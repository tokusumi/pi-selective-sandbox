import { isIP } from "node:net";
import { networkDenialReason } from "./network-diagnostics.js";
import { canonicalNetworkEndpoint } from "./network-policy.js";
import type { Capability, SandboxObservationDiagnostic, SandboxViolation } from "./types.js";

/** Model-visible diagnostics, never an authorization input or persisted grant. */
export type SandboxDenialExplanation = {
  category: "external-network" | "local-ipc" | "network-unknown";
  reason: string;
  operation: string;
  target: string | null;
  targetTruncated?: true;
  sandboxRetry: "resource-approval" | "already-covered" | "unavailable";
  explanation: string;
  nextSteps: string[];
};
export type SandboxDenialReport = {
  version: 1;
  attempt: number;
  observation: "correlated-denial" | "unconfirmed";
  denials: SandboxDenialExplanation[];
  omittedDenials: number;
  nextSteps: string[];
  caution: string;
};

export type DenialExplanationContext = {
  attempt: number;
  supportsNetworkWidening: boolean;
  candidates: readonly Capability[];
  granted: readonly Capability[];
  observation?: SandboxObservationDiagnostic;
  writeScopePreparationRejected?: boolean;
};

function operation(message: string | undefined): string {
  return message?.match(/\bdeny(?:\(\d+\))?\s+(network-(?:bind|outbound|inbound)|file-(?:read|write)(?:-[\w-]+)?)\b/)?.[1] ?? "unknown";
}

/** Extract diagnostic targets from correlated proxy records, never from shell text. */
function proxyTarget(message: string | undefined): string | null {
  const match = message?.match(/\bdeny network-outbound (\S+):([1-9][0-9]{0,4}) \((?:host is not on the allow list|malformed host|resolved to [^\n]+)\)$/);
  if (!match) return null;
  const resource = `${isIP(match[1]) === 6 ? `[${match[1]}]` : match[1]}:${match[2]}`;
  return canonicalNetworkEndpoint(resource) ?? (message?.endsWith("(malformed host)") ? resource : null);
}

const ipcSteps = [
  "An external host:port approval or filesystem-write grant does not permit IPC.",
  "This runtime integration has no sandbox IPC grant. A scoped IPC runtime/broker change would be needed; do not enable all Unix sockets.",
  "Socket access is not read-only: the host service can act outside the client's sandbox. Host replay is a separate exact-command approval, not an IPC fix."
];

export function sandboxDenialReport(violations: readonly SandboxViolation[], context: DenialExplanationContext): SandboxDenialReport | undefined {
  const denials: SandboxDenialExplanation[] = violations.filter(violation => violation.kind === "network").map(violation => {
    let target = violation.resource === "unknown" ? null : violation.resource;
    const approvable = context.supportsNetworkWidening && context.candidates.some(capability => capability.kind === violation.kind && capability.resource === violation.resource);
    const covered = context.granted.some(capability => capability.kind === violation.kind && capability.resource === violation.resource);
    const sandboxRetry = approvable ? "resource-approval" as const : covered ? "already-covered" as const : "unavailable" as const;
    const reason = networkDenialReason(violation);
    if (reason.startsWith("proxy-")) target = proxyTarget(violation.message) ?? target;
    if (reason === "unix-socket") return {
      category: "local-ipc", reason, operation: operation(violation.message), target, sandboxRetry: "unavailable",
      explanation: "The kernel denied a Unix-domain socket operation at the observed path, not an external HTTP destination.", nextSteps: [...ipcSteps]
    };
    if (reason === "proxy-allowlist") {
      let explanation = "The proxy denied this exact endpoint because it is outside the allowlist.";
      const nextSteps = ["Review the exact endpoint; do not allow all external networking."];
      if (approvable) nextSteps.push("An exact host:port resource approval can retry inside the sandbox; the entire command will run again.");
      else if (covered) nextSteps.push("The endpoint is already granted; inspect runtime/proxy enforcement rather than requesting the same authority again.");
      else if (!context.supportsNetworkWidening) {
        explanation += " This runtime does not support per-command network widening.";
        nextSteps.push("An endpoint grant cannot change this runtime's enforcement capability; use a supported runtime integration rather than widening global networking.");
      }
      else if (context.writeScopePreparationRejected) {
        explanation += " Filesystem write-scope preparation was rejected, suppressing all resource retry for this attempt, including endpoints.";
        nextSteps.push("Inspect configured deny roots and the required filesystem/Git/directory scopes; an endpoint grant cannot resolve this blocker.");
      } else nextSteps.push("No resource retry was prepared for this attempt. Check other blocked scopes/deny rules before changing the endpoint policy.");
      return { category: "external-network", reason, operation: "proxy-connect", target, sandboxRetry, explanation, nextSteps };
    }
    if (reason === "proxy-address-guard" || reason === "proxy-host-invalid") return {
      category: "external-network", reason, operation: "proxy-connect", target, sandboxRetry: "unavailable",
      explanation: reason === "proxy-address-guard" ? "The proxy's resolved-address guard rejected the destination; this is not an allowlist miss."
        : "The proxy rejected a malformed destination host; this is not an allowlist miss.",
      nextSteps: [reason === "proxy-address-guard" ? "Check the actual destination's DNS/proxy routing and whether access to the resolved address is intended. An endpoint approval does not bypass the address guard."
        : "Correct the destination's host syntax in the client/proxy configuration; do not add the malformed value to the allowlist."]
    };
    return {
      category: "network-unknown", reason, operation: operation(violation.message), target, sandboxRetry,
      explanation: "A communication denial was observed, but it does not establish a Unix IPC path or an approvable external proxy endpoint.",
      nextSteps: ["Inspect this invocation's correlated observer/proxy evidence. Command names, stderr, raw IPs, and socket errors are not enough to infer an HTTP permission target.",
        "Do not guess a host:port, allow all sockets/networking, or automatically replay on the host."]
    };
  });
  for (const denial of context.observation?.communicationDenials ?? []) {
    const local = denial.operation === "mach-lookup" || denial.family === "unix";
    denials.push({
      category: local ? "local-ipc" : "network-unknown",
      reason: denial.operation === "mach-lookup" ? "mach-service-lookup" : local ? "unix-socket-create" : "socket-create-unknown",
      operation: denial.operation, target: denial.target ?? null, sandboxRetry: "unavailable",
      explanation: denial.operation === "mach-lookup" ? "The kernel denied lookup of a local Mach service; this is not external HTTP."
        : local ? "The kernel denied AF_UNIX socket creation. No peer socket path is identified by this operation."
          : "The kernel denied socket creation, but the socket family and peer target are not established.",
      nextSteps: local ? [...ipcSteps] : ["Obtain correlated socket-family and peer evidence before choosing a permission. Do not infer AF_UNIX from a tmux command or stderr."]
    });
  }
  if (denials.length === 0 && (violations.length > 0 || !context.observation)) return undefined;
  const bounded = denials.slice(0, 8).map(denial => {
    if (!denial.target || denial.target.length <= 1024) return denial;
    return { ...denial, target: denial.target.slice(0, 1024), targetTruncated: true as const,
      nextSteps: ["Target is truncated; retrieve the full correlated observer target before considering any approval.", ...denial.nextSteps] };
  });
  return {
    version: 1, attempt: context.attempt,
    observation: denials.length ? "correlated-denial" : "unconfirmed", denials: bounded,
    omittedDenials: denials.length - bounded.length,
    nextSteps: denials.length ? [] : [
      "Check any observation/monitor warning and obtain observer/proxy records correlated with this invocation before choosing a permission.",
      "If no sandbox denial can be established, diagnose the command's ordinary error instead of widening permissions."
    ],
    caution: denials.length
      ? "These observer denials are correlated with this sandbox attempt, not proof of the cause of every command error. Guidance grants no authority."
      : "No supported correlated denial was established. The command may have an ordinary error; do not infer a permission from stderr or retry on the host."
  };
}

/** JSON escapes observer-controlled strings; raw log/command text is deliberately omitted. */
export function renderSandboxDenialReport(report: SandboxDenialReport): string {
  const json = JSON.stringify(report).replaceAll("<", "\\u003c").replaceAll(">", "\\u003e");
  return `<sandbox-denial-report>\n${json}\n</sandbox-denial-report>`;
}
