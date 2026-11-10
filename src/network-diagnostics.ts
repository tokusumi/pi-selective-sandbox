import { canonicalNetworkEndpoint } from "./network-policy.js";
import type { NetworkDiagnostic, SandboxViolation } from "./types.js";

function family(endpoint: string | undefined): NetworkDiagnostic["family"] {
  if (!endpoint) return "other";
  const host = endpoint.replace(/:\d+$/, "");
  if (host === "results-receiver.actions.githubusercontent.com" || /^productionresultssa\d+\.blob\.core\.windows\.net$/.test(host)) return "github-actions";
  if (host === "github.com" || host.endsWith(".github.com") || host.endsWith(".githubusercontent.com")) return "github";
  if (["proxy.golang.org", "sum.golang.org"].includes(host)) return "go";
  if (host.endsWith(".amazonaws.com")) return "aws";
  if (["registry.terraform.io", "releases.hashicorp.com", "checkpoint-api.hashicorp.com"].includes(host)) return "terraform";
  return "other";
}

/** Classify only correlated observer messages, never shell stderr or guessed command destinations. */
export function networkDiagnostics(violations: readonly SandboxViolation[], identity: (resource: string) => string): NetworkDiagnostic[] {
  return violations.filter(v => v.kind === "network").map(v => {
    const message = v.message ?? "";
    const endpoint = canonicalNetworkEndpoint(v.resource);
    let reason: NetworkDiagnostic["reason"] = "unknown";
    if (/\bdeny network-outbound \S+:\d+ \(host is not on the allow list\)$/.test(message) && endpoint) reason = "proxy-allowlist";
    else if (/\bdeny network-outbound \S+:\d+ \(malformed host\)$/.test(message)) reason = "proxy-host-invalid";
    else if (/\bdeny network-outbound \S+:\d+ \(resolved to [^\n]+\)$/.test(message)) reason = "proxy-address-guard";
    else if (/\bdeny(?:\(\d+\))?\s+network-(?:bind|outbound|inbound)\b/.test(message)) {
      reason = v.resource.startsWith("/") || v.resource.startsWith("~/") ? "unix-socket" : "raw-socket";
    }
    return { id: identity(v.resource), reason, family: family(endpoint) };
  });
}
