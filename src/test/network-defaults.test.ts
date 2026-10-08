import assert from "node:assert/strict";
import test from "node:test";
import { parseConfig } from "../config.js";
import { buildSandboxRuntimeConfig } from "../runtime-adapter.js";
import { resolveNetworkDomains } from "../network-policy.js";
import { matchesDomainPatternWithPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";

// These are independently named product requirements, not expectations derived
// from the profile arrays themselves. Adding a profile must not grant all hosts.
test("default network policy permits common Git, Node, Rust and Python HTTPS endpoints", () => {
  const allowed = buildSandboxRuntimeConfig({ cwd: "/project", writePolicy: { allow: ["/project"], deny: [] } }).network.allowedDomains;
  for (const host of [
    "github.com", "api.github.com", "gitlab.com", "bitbucket.org", "raw.githubusercontent.com", "release-assets.githubusercontent.com",
    "registry.npmjs.org", "registry.yarnpkg.com", "nodejs.org", "get.pnpm.io",
    "crates.io", "index.crates.io", "static.crates.io", "static.rust-lang.org", "sh.rustup.rs",
    "pypi.org", "files.pythonhosted.org", "python.org", "www.python.org", "astral.sh"
  ]) {
    assert.ok(allowed.some(pattern => matchesDomainPatternWithPort(host, 443, pattern)), host);
  }
  for (const host of ["unknown.example.com", "registry.npmjs.org.evil.example", "npmjs.org", "other.crates.io", "evil.pythonhosted.org"]) {
    assert.equal(allowed.some(pattern => matchesDomainPatternWithPort(host, 443, pattern)), false, host);
  }
  assert.equal(allowed.some(pattern => matchesDomainPatternWithPort("registry.npmjs.org", 80, pattern)), false);
});

test("network profile configuration accepts independent disables and rejects unknown or malformed profiles", () => {
  assert.deepEqual(parseConfig({ network: { disabledDefaultProfiles: ["node", "rust"] } }).network,
    { extraAllowedDomains: [], disabledDefaultProfiles: ["node", "rust"] });
  for (const value of [["cargo-cache"], ["pyhton"], [""], [1], "node", null]) {
    assert.throws(() => parseConfig({ network: { disabledDefaultProfiles: value } }));
  }
});

test("disabling a network profile changes only that group and keeps explicit additions", () => {
  const examples = [["git", "gitlab.com"], ["node", "registry.npmjs.org"], ["rust", "static.crates.io"], ["python", "files.pythonhosted.org"]] as const;
  for (const [profile, host] of examples) {
    const domains = resolveNetworkDomains(parseConfig({ network: { disabledDefaultProfiles: [profile] } }).network);
    for (const [otherProfile, otherHost] of examples) {
      assert.equal(domains.some(pattern => matchesDomainPatternWithPort(otherHost, 443, pattern)), otherProfile !== profile, otherHost);
    }
    assert.equal(domains.some(pattern => matchesDomainPatternWithPort(host, 443, pattern)), false);
  }
  assert.deepEqual(resolveNetworkDomains(parseConfig({ network: { disabledDefaultProfiles: ["git", "node", "rust", "python"] } }).network), []);
  const domains = resolveNetworkDomains(parseConfig({ network: {
    disabledDefaultProfiles: ["node"], extraAllowedDomains: ["Registry.NPMJS.org:443", "registry.npmjs.org:443"]
  } }).network);
  assert.equal(domains.filter(domain => domain === "registry.npmjs.org:443").length, 1);
  assert.equal(domains.some(pattern => matchesDomainPatternWithPort("registry.yarnpkg.com", 443, pattern)), false);
});
