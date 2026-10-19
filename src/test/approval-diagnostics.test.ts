import assert from "node:assert/strict";
import test from "node:test";
import { SelectiveSandboxExecutor } from "../executor.js";
import { createApprovalProvider } from "../pi-extension.js";
import { CapabilityPolicy } from "../policy.js";
import { SessionGrantStore } from "../session-grants.js";
import type { ApprovalResponse, Capability, EscalationApprovalRequest, SandboxViolation } from "../types.js";

const command = "git status -sb -- . ':(exclude).symphonia'; gh pr view --json number,title,url,state,isDraft,body";
const stderr = 'Post "https://api.github.com/graphql": tls: failed to verify certificate: x509: OSStatus -26276\n';
const network = (resource: string, message?: string): SandboxViolation => ({ kind: "network", resource, ...(message ? { message } : {}) });
const write: Capability = { kind: "filesystem.write", resource: "/repo/.git/worktrees/issue/index.lock" };

async function scenario(violations: readonly SandboxViolation[], options: {
  networkSupported?: boolean; writeScopeUnavailable?: boolean; answers?: string[]; response?: ApprovalResponse; stored?: readonly Capability[];
} = {}) {
  const titles: string[] = [], markers: string[] = [], sandboxCommands: string[] = [], hostCommands: string[] = [];
  const requests: EscalationApprovalRequest[] = [];
  const applied: (readonly Capability[])[] = [];
  const answers = [...(options.answers ?? ["Deny"])];
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async (title, choices) => {
    titles.push(title);
    const answer = answers.shift();
    assert.ok(answer === undefined || choices.includes(answer));
    return answer;
  } } }, new SessionGrantStore());
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      supportsNetworkWidening: options.networkSupported ?? true,
      wrap: async (text, context) => { applied.push([...(context.extraCapabilities ?? [])]); return text; },
      getViolationsForCommand: () => violations
    },
    runner: {
      runSandbox: async text => { sandboxCommands.push(text); return { exitCode: sandboxCommands.length === 1 ? 1 : 0, stdout: "## task/issue\n", stderr }; },
      runHost: async text => { hostCommands.push(text); return { exitCode: 0, stdout: "host fixture", stderr: "" }; }
    },
    canonicalizeCapabilities: async caps => options.writeScopeUnavailable ? undefined : caps,
    getSandboxCapabilities: async () => options.stored ?? [],
    policy: new CapabilityPolicy([]),
    commandIdentity: async shellCommand => ({ shellCommand, cwd: "/workspace/issue", executionMode: "shell" }),
    onStatus: marker => markers.push(marker),
    approvals: { request: async request => {
      assert.equal(request.kind, "escalation");
      requests.push(request as EscalationApprovalRequest);
      return options.response ?? provider.request(request);
    } }
  });
  const result = await executor.execute(command, "pr-view");
  return { result, titles, markers, sandboxCommands, hostCommands, requests, applied };
}

test("TLS certificate error without correlated denials never requests approval", async () => {
  const s = await scenario([]);
  assert.equal(s.result.disposition, "sandbox");
  assert.equal(s.result.stderr, stderr);
  assert.deepEqual(s.requests, []);
  assert.deepEqual(s.markers, []);
  assert.deepEqual(s.sandboxCommands, [command]);
  assert.deepEqual(s.hostCommands, []);
});

test("network socket denial with a TLS error shows the observed socket, not a write-scope explanation", async () => {
  const s = await scenario([network("/private/var/run/example.sock", "gh(123) deny(1) network-outbound /private/var/run/example.sock")]);
  assert.deepEqual(s.requests[0].capabilities, []);
  assert.deepEqual(s.requests[0].wideningUnavailableReasons, ["network-target-unavailable"]);
  assert.equal(s.titles.length, 1);
  assert.match(s.titles[0], /network: \/private\/var\/run\/example.sock/);
  assert.match(s.titles[0], /gh\(123\) deny\(1\) network-outbound/);
  assert.match(s.titles[0], /does not identify an approvable exact proxy host:port/);
  assert.match(s.titles[0], /do not establish the cause/);
  assert.match(s.titles[0], /entire command will run again/);
  assert.ok(s.titles[0].includes(command));
  assert.doesNotMatch(s.titles[0], /write scope|deny root/i);
  assert.equal(s.result.stderr, stderr);
  assert.equal(s.result.exitCode, 1);
  assert.equal(s.result.disposition, "denied");
  assert.deepEqual(s.markers, ["<sandbox: approval-required network>", "<sandbox: approval-denied>"]);
  assert.deepEqual(s.sandboxCommands, [command]);
  assert.deepEqual(s.hostCommands, []);
});

test("unsupported network runtime and read denials give capability-specific reasons", async () => {
  const cases = [
    { violations: [network("api.github.com:443")], options: { networkSupported: false }, reason: "network-runtime-unsupported", text: /runtime does not support sandbox network widening/ },
    { violations: [{ kind: "filesystem.read" as const, resource: "/config/file" }], options: {}, reason: "filesystem-read-unsupported", text: /filesystem-read widening is not supported/ },
    { violations: [network("unknown"), { kind: "filesystem.read" as const, resource: "/config/file" }], options: {}, reason: "network-target-unavailable", text: /filesystem-read widening is not supported/ }
  ] as const;
  for (const c of cases) {
    const s = await scenario(c.violations, c.options);
    assert.ok(s.requests[0].wideningUnavailableReasons?.includes(c.reason));
    assert.match(s.titles[0], c.text);
    assert.doesNotMatch(s.titles[0], /write scope|deny root/i);
    for (const v of c.violations) assert.ok(s.titles[0].includes(`${v.kind}: ${v.resource}`));
    assert.deepEqual(s.hostCommands, []);
  }
});

test("deny-root write scope preparation suppresses all widening and discloses mixed targets in either order", async () => {
  for (const violations of [[network("api.github.com:443"), write], [write, network("api.github.com:443")], [write]]) {
    const s = await scenario(violations, { writeScopeUnavailable: true });
    assert.deepEqual(s.requests[0].capabilities, []);
    assert.deepEqual(s.requests[0].wideningUnavailableReasons, ["filesystem-write-scope-unavailable"]);
    assert.match(s.titles[0], /Filesystem write scope preparation rejected widening/);
    assert.match(s.titles[0], /deny root may cover a target or its required Git\/directory scope/);
    for (const v of violations) assert.ok(s.titles[0].includes(`${v.kind}: ${v.resource}`));
    assert.deepEqual(s.hostCommands, []);
    assert.deepEqual(s.sandboxCommands, [command]);
  }
});

test("a stored write grant cannot hide the deny-root target from mixed-denial diagnostics", async () => {
  const s = await scenario([write, network("api.github.com:443")], { writeScopeUnavailable: true, stored: [write] });
  assert.deepEqual(s.requests[0].capabilities, []);
  assert.deepEqual(s.requests[0].observedCapabilities, [write, network("api.github.com:443")]);
  assert.deepEqual(s.requests[0].wideningUnavailableReasons, ["filesystem-write-scope-unavailable"]);
  assert.ok(s.titles[0].includes(`${write.kind}: ${write.resource}`));
  assert.match(s.titles[0], /network: api.github.com:443/);
  assert.deepEqual(s.sandboxCommands, [command]);
  assert.deepEqual(s.hostCommands, []);
});

test("an exact proxy endpoint offers sandbox-only retry and reruns the full compound command", async () => {
  const target = network("api.github.com:443");
  const s = await scenario([target], { answers: ["Once", "Allow and retry"] });
  assert.deepEqual(s.requests[0].capabilities, [target]);
  assert.deepEqual(s.requests[0].wideningUnavailableReasons, []);
  assert.match(s.titles[0], /network: api.github.com:443/);
  assert.doesNotMatch(s.titles.join("\n"), /write scope|deny root/i);
  assert.deepEqual(s.sandboxCommands, [command, command]);
  assert.deepEqual(s.hostCommands, []);
  assert.deepEqual(s.applied, [[], [target]]);
  assert.equal(s.result.exitCode, 0);
});

test("host-only choice still requires separate duration and exact-command confirmation", async () => {
  for (const confirm of ["Deny", "Run on host"]) {
    const s = await scenario([network("unknown")], { answers: ["Run outside sandbox…", "Once", confirm] });
    assert.equal(s.titles.length, 3);
    assert.match(s.titles[2], /Sandbox protections will not apply/);
    assert.ok(s.titles[2].includes(command));
    assert.match(s.titles[2], /Working directory: \/workspace\/issue/);
    assert.deepEqual(s.sandboxCommands, [command]);
    assert.deepEqual(s.hostCommands, confirm === "Run on host" ? [command] : []);
    assert.equal(s.result.disposition, confirm === "Run on host" ? "host" : "denied");
  }
});

test("a forged sandbox approval cannot retry a host-only denial", async () => {
  const s = await scenario([network("unknown")], { response: "sandbox-allow-once" });
  assert.equal(s.result.disposition, "denied");
  assert.deepEqual(s.sandboxCommands, [command]);
  assert.deepEqual(s.hostCommands, []);
});

test("legacy host-only requests without diagnostics use a neutral fallback and escape terminal controls", async () => {
  let title = "";
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async text => { title = text; return "Deny"; } } }, new SessionGrantStore());
  assert.equal(await provider.request({ kind: "escalation", toolCallId: "legacy", toolName: "bash", inputDigest: "digest", capabilities: [], command, replayWarning: true,
    observedCapabilities: [network("unknown\x1b[31m", "deny network-outbound unknown\x1b[31m")] }), "deny");
  assert.match(title, /No supported sandbox resource scope/);
  assert.doesNotMatch(title, /write scope|deny root/i);
  assert.ok(!title.includes("\x1b"));
  assert.ok(title.includes("\\u001b[31m"));
});
