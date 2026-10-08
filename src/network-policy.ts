import { NetworkConfigSchema } from "@anthropic-ai/sandbox-runtime";
import { isIP } from "node:net";
import { canonicalizeHost, isValidHost } from "@anthropic-ai/sandbox-runtime/dist/sandbox/parent-proxy.js";
import { splitDomainPatternPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";

export const DEFAULT_NETWORK_PROFILES = ["git", "node", "rust", "python"] as const;
type DefaultNetworkProfile = typeof DEFAULT_NETWORK_PROFILES[number];

const PROFILE_DOMAINS: Record<DefaultNetworkProfile, readonly string[]> = {
  // Retain the existing GitHub allowance; new defaults are HTTPS-only.
  git: ["api.github.com", "github.com", "*.github.com", "gitlab.com:443", "bitbucket.org:443",
    "raw.githubusercontent.com:443", "objects.githubusercontent.com:443", "release-assets.githubusercontent.com:443"],
  node: ["registry.npmjs.org:443", "registry.yarnpkg.com:443", "nodejs.org:443", "get.pnpm.io:443"],
  rust: ["crates.io:443", "index.crates.io:443", "static.crates.io:443", "static.rust-lang.org:443", "sh.rustup.rs:443"],
  python: ["pypi.org:443", "files.pythonhosted.org:443", "python.org:443", "www.python.org:443", "astral.sh:443"]
};

export function resolveNetworkDomains(config?: { extraAllowedDomains: readonly string[]; disabledDefaultProfiles?: readonly string[] }): string[] {
  const disabled = new Set(config?.disabledDefaultProfiles ?? []);
  return [...new Set([
    ...DEFAULT_NETWORK_PROFILES.filter(profile => !disabled.has(profile)).flatMap(profile => PROFILE_DOMAINS[profile]),
    ...(config?.extraAllowedDomains ?? [])
  ])];
}

export const DEFAULT_ALLOWED_DOMAINS: readonly string[] = Object.freeze(resolveNetworkDomains());

/** Config may use SDK wildcard patterns; approval resources may not. */
export function normalizeNetworkPattern(value: string): string {
  if (!NetworkConfigSchema.shape.allowedDomains.safeParse([value]).success) throw new Error(`Invalid network domain pattern: ${JSON.stringify(value)}`);
  const { hostPattern, port } = splitDomainPatternPort(value);
  const wildcard = hostPattern.startsWith("*.");
  const host = wildcard ? hostPattern.slice(2) : hostPattern;
  if (!isValidHost(host) || /[\s/@?#\\]/.test(host)) throw new Error(`Invalid network host: ${JSON.stringify(value)}`);
  const canonical = canonicalizeHost(host);
  if (!canonical) throw new Error(`Invalid network host: ${JSON.stringify(value)}`);
  return (wildcard ? "*." : "") + (isIP(canonical) === 6 ? `[${canonical}]` : canonical) + (port === undefined ? "" : `:${port}`);
}

/** Narrow, canonical host:port identity. No URL, wildcard, path or inferred port. */
export function canonicalNetworkEndpoint(resource: string): string | undefined {
  if (!/^(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):[1-9][0-9]{0,4}$/.test(resource)) return undefined;
  try { return normalizeNetworkPattern(resource); } catch { return undefined; }
}

export function networkResourceFromLine(line: string): string | undefined {
  // Only the proxy knows the hostname. Seatbelt IP/socket denials and HTTP
  // request-filter denials must not be guessed from a command or turned into grants.
  const match = line.match(/^deny network-outbound (\S+):([1-9][0-9]{0,4}) \(host is not on the allow list\)$/);
  if (!match) return undefined;
  const host = match[1];
  return canonicalNetworkEndpoint(`${isIP(host) === 6 ? `[${host}]` : host}:${match[2]}`);
}
