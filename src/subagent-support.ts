import { createRequire } from "node:module";
import { realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";
import { getAgentDir, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { parseConfig, type ConfigLoadResult } from "./config.js";
import { canonicalPath, expandPath } from "./filesystem-policy.js";
import { SUBAGENT_BINDING_EVENT, startApprovalBridge, validBridgeBinding, type ApprovalBridgeBinding } from "./subagent-approval.js";
import type { EscalationUI } from "./widening-dialog.js";

export type ChildSandboxBinding = { version: 1; bridge: ApprovalBridgeBinding; config: ConfigLoadResult; protectedRoot: string };
export type RequiredChildApi = {
  registerRequiredChildExtensions(input: { sessionId: string; extensions: { id: string; path: string }[] }): { dispose(): void };
};

/** Pi packages can be independently installed; do not require a private subagents import. */
export async function loadRequiredChildApi(): Promise<RequiredChildApi | undefined> {
  const resolvers = [createRequire(import.meta.url), createRequire(join(getAgentDir(), "npm", "node_modules", "pi-selective-sandbox-resolver.cjs"))];
  for (const resolver of resolvers) {
    let path: string;
    try { path = resolver.resolve("pi-subagents/required-child-extensions"); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "MODULE_NOT_FOUND") continue;
      throw error;
    }
    const api = await import(pathToFileURL(path).href) as RequiredChildApi;
    if (typeof api.registerRequiredChildExtensions !== "function") throw new Error("Unsupported pi-subagents required-extension API");
    return api;
  }
  return undefined;
}

export function validChildSandboxBinding(value: unknown): value is ChildSandboxBinding {
  if (typeof value !== "object" || value === null) return false;
  const binding = value as ChildSandboxBinding;
  if (binding.version !== 1 || !validBridgeBinding(binding.bridge) || typeof binding.protectedRoot !== "string") return false;
  if (!isAbsolute(binding.protectedRoot) || /[\x00-\x1f\x7f-\x9f]/.test(binding.protectedRoot) || !binding.bridge.directory.startsWith(binding.protectedRoot + "/")) return false;
  if (binding.config?.valid === false) return true;
  try { return binding.config?.valid === true && JSON.stringify(parseConfig(binding.config.config)) === JSON.stringify(binding.config.config); }
  catch { return false; }
}

export function createSubagentSupport(pi: ExtensionAPI, options: { entryPath: string; loadApi?: () => Promise<RequiredChildApi | undefined> }) {
  let childBinding: ChildSandboxBinding | undefined;
  let parentSessionId: string | undefined;
  let bridge: Awaited<ReturnType<typeof startApprovalBridge>> | undefined;
  let registration: { dispose(): void } | undefined;
  let unavailable = false;
  let bindingFailed = false;
  const unsubscribe = pi.events?.on(SUBAGENT_BINDING_EVENT, value => {
    const request = value as { version?: number; binding?: ChildSandboxBinding; accepted?: boolean } | undefined;
    if (request?.version !== 1 || !validChildSandboxBinding(request.binding) || childBinding) {
      bindingFailed = true;
      throw new Error("Invalid or duplicate subagent sandbox binding");
    }
    childBinding = request.binding;
    request.accepted = true;
  });
  return {
    get binding() { return childBinding; },
    get bindingFailed() { return bindingFailed; },
    get unavailable() { return unavailable; },
    async start(context: EscalationUI & { cwd: string }, config: ConfigLoadResult, protectedRoot: string) {
      if (childBinding || unavailable || !context.hasUI || !context.ui) return;
      try {
        const sessionId = context.sessionManager?.getSessionId();
        if (!sessionId) throw new Error("Sandbox subagent support requires a parent session ID");
        if (parentSessionId === sessionId && registration) return;
        const api = await (options.loadApi ?? loadRequiredChildApi)();
        if (!api) {
          if (pi.getAllTools?.().some(tool => tool.name === "subagent")) throw new Error("pi-subagents/required-child-extensions is unavailable; use pi-subagents >=0.76.1");
          return;
        }
        if (registration) throw new Error("Parent sandbox registration must be shut down before session replacement");
        parentSessionId = sessionId;
        bridge = await startApprovalBridge({ root: protectedRoot, parentSessionId: sessionId,
          select: (title, choices, promptOptions) => context.hasUI && context.sessionManager?.getSessionId() === sessionId
            ? context.ui!.select(title, choices, promptOptions) : Promise.resolve(undefined) });
        // Resolve relative extra roots in the parent's startup cwd once. The
        // workspace default is still resolved independently in each child cwd.
        const inherited: ConfigLoadResult = config.valid ? { valid: true, config: {
          ...config.config, filesystem: { ...config.config.filesystem, extraWritableRoots: await Promise.all(config.config.filesystem.extraWritableRoots.map(path => canonicalPath(expandPath(path, context.cwd)))) }
        } } : { valid: false };
        const binding: ChildSandboxBinding = { version: 1, bridge: bridge.binding, config: inherited, protectedRoot };
        const companion = join(bridge.binding.directory, "child-parent.mjs");
        // Claim at load time when the sandbox factory is already loaded. If
        // loader ordering puts the companion first, its session_start handler
        // runs first and binds before the sandbox's startup policy is resolved.
        await writeFile(companion, `export default function(pi) {
  const request = { version: 1, binding: ${JSON.stringify(binding)}, accepted: false };
  const bind = () => { pi.events.emit(${JSON.stringify(SUBAGENT_BINDING_EVENT)}, request); return request.accepted; };
  if (!bind()) pi.on("session_start", () => { if (!bind()) throw new Error("Child sandbox binding was not acknowledged"); });
}\n`, { flag: "wx", mode: 0o600 });
        const receipt = api.registerRequiredChildExtensions({ sessionId, extensions: [
          { id: "pi-selective-sandbox", path: await realpath(options.entryPath) },
          { id: "pi-selective-sandbox-parent", path: companion }
        ] });
        if (typeof receipt?.dispose !== "function") throw new Error("Unsupported required-extension registration receipt");
        registration = receipt;
      } catch (error) {
        unavailable = true;
        await bridge?.close();
        bridge = undefined;
        // The tool_call guard blocks admission; never silently run a child
        // without the extension after a registration or transport failure.
        console.warn(`Subagent sandbox setup failed (${error instanceof Error ? error.name : "Error"}); subagent launches are blocked.`);
      }
    },
    async close() {
      registration?.dispose();
      registration = undefined;
      parentSessionId = undefined;
      try { await bridge?.close(); } finally { bridge = undefined; unsubscribe?.(); }
    }
  };
}
