import assert from "node:assert/strict";
import test from "node:test";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";

const localRules = [
  '(allow network-bind (local ip "*:*"))',
  '(allow network-inbound (local ip "*:*"))',
  '(allow network-outbound (remote ip "localhost:*"))'
];

// Exercise the real SDK manager -> macOS profile boundary on every CI platform.
// Synthetic external proxy ports avoid opening sockets; no command is executed.
for (const first of [true, false]) {
  test(`real SDK profiles use per-attempt local binding after ${first} startup`, async t => {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "darwin" });
    t.after(async () => {
      try { await SandboxManager.reset(); }
      finally { Object.defineProperty(process, "platform", platform); }
    });
    const config = (allowLocalBinding: boolean) => ({
      filesystem: { allowRead: [], denyRead: [], allowWrite: ["/profile-fixture"], denyWrite: ["/profile-fixture/blocked"] },
      network: { allowedDomains: [], deniedDomains: [], allowLocalBinding, httpProxyPort: 43101, socksProxyPort: 43101 }
    });
    await SandboxManager.initialize(config(first), undefined, false);
    await SandboxManager.initialize(config(!first), undefined, false);
    assert.equal(SandboxManager.getConfig()?.network.allowLocalBinding, first);
    // Both explicit values, alternating retries, and both forms of omission.
    for (const [index, requested] of [first, !first, first, !first, undefined, undefined].entries()) {
      const custom = requested === undefined
        ? (index === 4 ? { network: { allowedDomains: [], deniedDomains: [] } } : undefined)
        : config(requested);
      const port = 43102 + index;
      const wrapped = await SandboxManager.wrapWithSandbox("true", undefined, custom, undefined, {
        commandId: `profile-${first}-${index}`, networkProxy: { port, token: "unused-fixture" }
      });
      assert.ok(wrapped.includes("(version 1)\n"));
      for (const rule of localRules) {
        assert.equal(wrapped.includes(rule), requested ?? first, `${requested ?? "omitted"}: ${rule}`);
      }
      assert.ok(wrapped.includes(`(allow network-outbound (remote ip "localhost:${port}"))`));
      assert.ok(!wrapped.includes('(remote ip "localhost:43101")'));
      assert.ok(!wrapped.includes("(allow network*)"));
      assert.ok(!wrapped.includes("(allow system-socket (socket-domain AF_UNIX))"));
      assert.ok(!wrapped.includes("unix-socket"));
      assert.ok(wrapped.includes('(subpath "/profile-fixture/blocked")'));
      assert.ok(!wrapped.includes("(allow file-write*)"));
    }
  });
}
