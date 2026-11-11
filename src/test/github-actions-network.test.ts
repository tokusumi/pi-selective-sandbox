import assert from "node:assert/strict";
import test from "node:test";
import { matchesDomainPatternWithPort, splitDomainPatternPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";
import { createResolvedAddressGuard } from "@anthropic-ai/sandbox-runtime/dist/sandbox/resolved-address-guard.js";
import { canonicalizeHost } from "@anthropic-ai/sandbox-runtime/dist/sandbox/parent-proxy.js";
import { canonicalNetworkEndpoint, networkResourceFromLine, resolveNetworkDomains } from "../network-policy.js";
import { buildSandboxRuntimeConfig } from "../runtime-adapter.js";

const receiver = "results-receiver.actions.githubusercontent.com";
const endpoint = `${receiver}:443`;

// Use the SDK matcher on canonical approval endpoint identities. Proxy-only
// trailing-dot normalization is checked separately. No DNS or log downloads.
function permits(domains: readonly string[], resource: string): boolean {
  const canonical = canonicalNetworkEndpoint(resource);
  if (!canonical) return false;
  const { hostPattern, port } = splitDomainPatternPort(canonical);
  return port !== undefined && domains.some(pattern => matchesDomainPatternWithPort(hostPattern, port, pattern));
}

test("GitHub Actions receiver is an exact HTTPS-only git profile destination", () => {
  const defaults = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/project"], deny: [] } }).network.allowedDomains;
  assert.deepEqual(defaults.filter(pattern => matchesDomainPatternWithPort(receiver, 443, pattern)), [endpoint]);
  for (const resource of [endpoint, `${receiver.toUpperCase()}:443`]) {
    assert.equal(permits(defaults, resource), true, resource);
    assert.equal(canonicalNetworkEndpoint(resource), endpoint);
  }
  // Proxy host normalization accepts a trailing DNS dot; the existing approval
  // endpoint schema intentionally does not accept that spelling as a grant.
  assert.equal(canonicalNetworkEndpoint(`${receiver}.:443`), undefined);
  assert.equal(defaults.some(pattern => matchesDomainPatternWithPort(canonicalizeHost(`${receiver}.`)!, 443, pattern)), true);
  for (const resource of [
    `${receiver}:80`, `${receiver}:22`, `${receiver}:8443`, `${receiver}:65535`,
    `${receiver}:0443`, `${receiver}:0`, `${receiver}:65536`,
    `evil.${receiver}:443`, `${receiver}.evil.example:443`,
    "results-receiver-actions.githubusercontent.com:443", "results-receiver.actions.githubuserconten.com:443",
    "other.actions.githubusercontent.com:443", "actions.githubusercontent.com:443", "githubusercontent.com:443",
    `https://${receiver}:443`, `${receiver}:443/path`, `${receiver}:443@evil.example`, `${receiver}:443\0`
  ]) assert.equal(permits(defaults, resource), false, resource);

  const gitOnly = resolveNetworkDomains({ extraAllowedDomains: [], disabledDefaultProfiles: ["node", "rust", "python", "packages"] });
  assert.equal(permits(gitOnly, endpoint), true);
  const gitDisabled = resolveNetworkDomains({ extraAllowedDomains: [], disabledDefaultProfiles: ["git"] });
  assert.equal(permits(gitDisabled, endpoint), false);
  const explicit = resolveNetworkDomains({ extraAllowedDomains: [endpoint], disabledDefaultProfiles: ["git"] });
  assert.equal(permits(explicit, endpoint), true, "profile disable is not a hard deny of explicit additions");
  assert.equal(permits(explicit, `${receiver}:8443`), false);
  // Preserve the inherited GitHub all-port semantics, without copying them to the receiver.
  for (const port of [22, 80, 443, 8443]) assert.equal(permits(defaults, `api.github.com:${port}`), true);
});

test("log endpoint/redirect fixtures evaluate every destination, not just the receiver", () => {
  const domains = resolveNetworkDomains();
  // Synthetic policy fixtures, not a claim about any particular gh version's
  // redirect topology. The Blob name occurred in an older investigation;
  // ownership/necessity for other accounts has not been established.
  const fixtures = [
    { name: "receiver only", endpoints: [endpoint], allowed: [true] },
    { name: "API then receiver", endpoints: ["api.github.com:443", endpoint], allowed: [true, true] },
    { name: "API redirect to Blob", endpoints: ["api.github.com:443", "productionresultssa2.blob.core.windows.net:443"], allowed: [true, false] },
    { name: "receiver plus Blob", endpoints: ["api.github.com:443", endpoint, "productionresultssa2.blob.core.windows.net:443"], allowed: [true, true, false] },
    { name: "third-party Blob account", endpoints: [endpoint, "attacker-account.blob.core.windows.net:443"], allowed: [true, false] },
    { name: "redirect changes port", endpoints: [endpoint, `${receiver}:8443`], allowed: [true, false] }
  ];
  for (const fixture of fixtures) {
    const decisions = fixture.endpoints.map(resource => permits(domains, resource));
    assert.deepEqual(decisions, fixture.allowed, fixture.name);
    assert.equal(decisions.every(Boolean), fixture.allowed.every(Boolean), `${fixture.name}: full route policy result`);
  }
  assert.equal(domains.includes("*.blob.core.windows.net"), false);
  assert.equal(domains.includes("*.blob.core.windows.net:443"), false);
  assert.equal(domains.includes("*"), false);
});

test("receiver allowance does not bypass address guards or turn guard/deny failures into grants", () => {
  const guard = createResolvedAddressGuard({ allowedDomains: resolveNetworkDomains(), localAddresses: () => [] });
  for (const address of ["127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "168.63.129.16"]) {
    assert.equal(guard.permits(receiver, address, 443), false, address);
  }
  const deniedAddress = createResolvedAddressGuard({ allowedDomains: resolveNetworkDomains(), deniedDomains: ["203.0.113.1:443"], localAddresses: () => [] });
  assert.equal(deniedAddress.permits(receiver, "203.0.113.1", 443), false);
  assert.equal(networkResourceFromLine(`deny network-outbound ${endpoint} (host is not on the allow list)`), endpoint);
  for (const reason of ["resolved to a loopback address", "host is on the deny list", "malformed host"]) {
    assert.equal(networkResourceFromLine(`deny network-outbound ${endpoint} (${reason})`), undefined);
  }
});
