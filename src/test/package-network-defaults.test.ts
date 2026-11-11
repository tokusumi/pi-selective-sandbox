import assert from "node:assert/strict";
import test from "node:test";
import { matchesDomainPatternWithPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";
import { parseConfig } from "../config.js";
import { DEFAULT_NETWORK_PROFILES, resolveNetworkDomains } from "../network-policy.js";

// Independent inventory: these concrete service hosts, not their parent domains
// or upstream products' wildcard/method semantics, are the selected defaults.
const packageHosts = [
  "proxy.golang.org", "sum.golang.org", "repo.maven.apache.org", "repo1.maven.org",
  "rubygems.org", "index.rubygems.org", "api.nuget.org", "repo.packagist.org", "packagist.org", "getcomposer.org"
];
const allows = (domains: readonly string[], host: string, port = 443) => domains.some(pattern => matchesDomainPatternWithPort(host, port, pattern));

test("additional package defaults are exact HTTPS endpoints with an independent opt-out", () => {
  const defaults = resolveNetworkDomains();
  const disabled = resolveNetworkDomains(parseConfig({ network: { disabledDefaultProfiles: ["packages"] } }).network);
  assert.deepEqual(defaults.filter(pattern => !disabled.includes(pattern)), packageHosts.map(host => `${host}:443`));
  for (const host of packageHosts) {
    assert.equal(allows(defaults, host), true, host);
    assert.equal(allows(defaults, host.toUpperCase()), true, host);
    assert.equal(allows(disabled, host), false, host);
    for (const port of [22, 80, 8443, 65535]) assert.equal(allows(defaults, host, port), false, `${host}:${port}`);
    for (const other of [`evil.${host}`, `${host}.evil.example`, `${host.replaceAll(".", "-")}.example`]) {
      assert.equal(allows(defaults, other), false, other);
    }
  }
  for (const host of ["api.github.com", "registry.npmjs.org", "static.crates.io", "files.pythonhosted.org"]) {
    assert.equal(allows(disabled, host), true, host);
  }
});

test("legacy full opt-out stays closed after adding a default profile; explicit entries still work", () => {
  const legacyDisabled = ["git", "node", "rust", "python"];
  for (const disabledDefaultProfiles of [legacyDisabled, [...DEFAULT_NETWORK_PROFILES], [...legacyDisabled, ...legacyDisabled]]) {
    const config = parseConfig({ network: { disabledDefaultProfiles } });
    assert.deepEqual(resolveNetworkDomains(config.network), []);
    const explicit = resolveNetworkDomains(parseConfig({ network: {
      disabledDefaultProfiles, extraAllowedDomains: ["proxy.golang.org:443", "proxy.golang.org:443"]
    } }).network);
    assert.deepEqual(explicit, ["proxy.golang.org:443"]);
  }
  const explicit = resolveNetworkDomains(parseConfig({ network: {
    disabledDefaultProfiles: ["packages"], extraAllowedDomains: ["api.nuget.org:443"]
  } }).network);
  assert.equal(allows(explicit, "api.nuget.org"), true);
  assert.equal(allows(explicit, "api.nuget.org", 80), false);
  assert.equal(allows(explicit, "index.rubygems.org"), false);
});

test("package metadata hosts do not grant mirrors, shared storage, or whole download routes", () => {
  const defaults = resolveNetworkDomains();
  // Go's proxy can redirect to object storage. Metadata/package-host access is
  // not proof that the full download route succeeds; never infer a CDN grant.
  for (const route of [
    ["proxy.golang.org", "storage.googleapis.com"],
    ["api.nuget.org", "nugetregistryv2prod.blob.core.windows.net"],
    ["repo.packagist.org", "private-dist.example"],
    ["repo.maven.apache.org", "mirror.example"],
    ["rubygems.org", "gems.example"]
  ]) assert.deepEqual(route.map(host => allows(defaults, host)), [true, false], route.join(" -> "));
  for (const host of [
    "azure.com", "google.com", "microsoft.com", "oracle.com", "golang.org", "nuget.org",
    "attacker.blob.core.windows.net", "attacker.storage.googleapis.com", "attacker.s3.amazonaws.com"
  ]) assert.equal(allows(defaults, host), false, host);
  assert.deepEqual(defaults.filter(pattern => pattern.includes("*")), ["*.github.com"], "no new wildcard defaults");
});
