import { randomBytes } from "node:crypto";
import { createHttpProxyServer } from "@anthropic-ai/sandbox-runtime/dist/sandbox/http-proxy.js";
import { createSocksProxyServer } from "@anthropic-ai/sandbox-runtime/dist/sandbox/socks-proxy.js";
import { createMuxProxyServer } from "@anthropic-ai/sandbox-runtime/dist/sandbox/mux-proxy.js";
import { canonicalizeHost, isValidHost, resolveParentProxy } from "@anthropic-ai/sandbox-runtime/dist/sandbox/parent-proxy.js";
import { matchesDomainPatternWithPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";
import { createResolvedAddressGuard, isResolvedAddressDenied } from "@anthropic-ai/sandbox-runtime/dist/sandbox/resolved-address-guard.js";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import type { DirectLookup } from "@anthropic-ai/sandbox-runtime/dist/sandbox/parent-proxy.js";

export type CommandNetworkProxy = { port: number; token: string; close(): Promise<void> };
const active = new Set<CommandNetworkProxy>();

/** Immutable per-attempt rules, independent of client-supplied attribution IDs. */
export async function createCommandNetworkProxy(commandId: string, allowedDomains: readonly string[]): Promise<CommandNetworkProxy> {
  const token = randomBytes(32).toString("hex");
  const encodedCommand = Buffer.from(commandId).toString("base64");
  const record = (host: string, port: number, reason: string) => SandboxManager.getSandboxViolationStore().addViolation({
    line: `deny network-outbound ${host}:${port} (${reason})`, encodedCommand, timestamp: new Date()
  });
  const filter = (port: number, host: string) => {
    const canonical = isValidHost(host) ? canonicalizeHost(host) : undefined;
    const allowed = canonical !== undefined && allowedDomains.some(pattern => matchesDomainPatternWithPort(canonical, port, pattern));
    if (!allowed) record(host, port, canonical === undefined ? "malformed host" : "host is not on the allow list");
    return allowed;
  };
  // Preserve the SDK's DNS-rebinding protection; approving a name must not
  // silently open loopback/private addresses to which that name resolves.
  const guard = createResolvedAddressGuard({ allowedDomains });
  const lookupFor: DirectLookup = port => (host, options, callback) => guard.lookupFor(port)(host, options, (error, address, family) => {
    if (isResolvedAddressDenied(error)) record(host, port, error.reason);
    callback(error, address, family);
  });
  // Match the SDK's explicit config / HTTP(S)_PROXY / NO_PROXY resolution.
  // The destination allowlist still runs before any upstream tunnel is opened.
  const parentProxy = resolveParentProxy(SandboxManager.getConfig()?.network.parentProxy);
  const httpServer = createHttpProxyServer({ filter, lookupFor, parentProxy, proxyAuthToken: token });
  const socks = createSocksProxyServer({ filter, lookupFor, parentProxy, proxyAuthToken: token });
  const mux = createMuxProxyServer({ httpServer, handleSocksConnection: socket => socks.handleConnection(socket) });
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    httpServer.closeAllConnections();
    await Promise.all([mux.close(), socks.close()]);
  })();
  try {
    await mux.listenHttpBackend();
    await new Promise<void>((resolve, reject) => {
      mux.server.once("error", reject);
      mux.server.listen(0, "127.0.0.1", () => { mux.server.removeListener("error", reject); resolve(); });
    });
    const port = mux.getPort();
    if (port === undefined) throw new Error("Command network proxy has no listening port");
    const proxy: CommandNetworkProxy = { port, token, async close() { active.delete(proxy); await close(); } };
    active.add(proxy);
    return proxy;
  } catch (error) {
    await close();
    throw error;
  }
}

export async function closeCommandNetworkProxies(): Promise<void> {
  await Promise.all([...active].map(proxy => proxy.close()));
}
