import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { WritePolicy } from "./filesystem-policy.js";
import { StraceViolationObserver, STRACE_ARGS, STRACE_BINARY } from "./strace-observer.js";
import type { SandboxRuntime, SandboxViolation } from "./types.js";
import { DEFAULT_ALLOWED_DOMAINS, canonicalNetworkEndpoint, networkResourceFromLine } from "./network-policy.js";
import { createCommandNetworkProxy, closeCommandNetworkProxies, type CommandNetworkProxy } from "./network-proxy.js";

export type SandboxSettings = { cwd: string; writePolicy: WritePolicy; allowRead?: readonly string[]; allowedDomains?: readonly string[]; commandNamespace?: string; allowLocalBinding?: boolean };

// Foreground children share a process. Jiti reloads may instantiate another
// copy of this module, so both SDK ownership and leases must be process-wide.
type SharedRuntime = { manager: typeof SandboxManager; instances: Set<AnthropicSandboxRuntime> };
function sharedRuntime(): SharedRuntime {
  const key = Symbol.for("pi-selective-sandbox.runtime.v1");
  const root = globalThis as typeof globalThis & { [key: symbol]: SharedRuntime | undefined };
  let shared = root[key];
  if (!shared) {
    shared = { manager: SandboxManager, instances: new Set() };
    root[key] = shared;
  }
  return shared;
}

/** Carries the configured flag even when initialization fails; not process health. */
export class SandboxInitializationFailure extends Error {
  constructor(cause: unknown, readonly logMonitorEnabled: boolean) {
    super(cause instanceof Error ? cause.message : "Sandbox initialization failed", { cause });
    this.name = "SandboxInitializationFailure";
  }
}

export function isUbuntuRelease(osRelease: string): boolean {
  const values = new Map(osRelease.split("\n").map(line => {
    const separator = line.indexOf("=");
    if (separator < 0) return [line, ""];
    return [line.slice(0, separator), line.slice(separator + 1).replace(/^["']|["']$/g, "")];
  }));
  return values.get("ID")?.toLowerCase() === "ubuntu";
}

export async function isUbuntu(osReleasePath = "/etc/os-release"): Promise<boolean> {
  if (process.platform !== "linux") return false;
  try { return isUbuntuRelease(await readFile(osReleasePath, "utf8")); } catch { return false; }
}

export function buildSandboxRuntimeConfig(settings: SandboxSettings, allowAllUnixSockets = false): SandboxRuntimeConfig {
  const policy = settings.writePolicy;
  return {
    filesystem: {
      // Runtime reads are broad by default; credential visibility is handled at the model boundary.
      allowRead: [...(settings.allowRead ?? [])], denyRead: [],
      allowWrite: [...policy.allow], denyWrite: [...policy.deny]
    },
    network: {
      // GitHub CLI remains usable with its normal credential helpers.
      allowedDomains: [...(settings.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS)], deniedDomains: [],
      // SDK semantics: all-interface listeners + direct loopback connections,
      // not just binding to 127.0.0.1. External egress still requires the proxy.
      ...(process.platform === "darwin" ? { allowLocalBinding: settings.allowLocalBinding ?? true } : {}),
      ...(allowAllUnixSockets ? { allowAllUnixSockets: true } : {})
    }
  };
}

export function sandboxInitializationError(error: unknown): string {
  if (error instanceof SandboxInitializationFailure) error = error.cause;
  const detail = error instanceof Error ? `${error.message}\n${error.cause instanceof Error ? error.cause.message : ""}` : String(error);
  if (/strace|ptrace|PTRACE/i.test(detail)) {
    return "Linux sandbox observation is unavailable because strace could not trace commands. Host execution was not attempted.";
  }
  if (/apply-seccomp|seccomp|nested.{0,20}(user namespace|userns)|user namespace.{0,20}(denied|not permitted|operation not permitted)/is.test(detail)) {
    return "Linux sandbox is unavailable because the host blocks the nested user namespace required for Unix-socket isolation. Host execution was not attempted.";
  }
  if (/apparmor|unprivileged_userns|user namespace|userns/i.test(detail)) {
    return "Linux sandbox is unavailable because Bubblewrap is blocked by the host AppArmor/user-namespace policy. Host execution was not attempted.";
  }
  if (/\bbwrap\b|bubblewrap/i.test(detail)) {
    return "Linux sandbox is unavailable because Bubblewrap could not be started. Host execution was not attempted.";
  }
  return "Sandbox unavailable; host execution was not attempted.";
}

function resourceFromLine(line: string): string {
  const filesystem = line.match(/\bdeny(?:\(\d+\))?\s+file-(?:read|write)(?:-[\w-]+)?\s+(.+)$/)?.[1];
  if (filesystem) return filesystem.replace(/^(['"])(.*)\1$/, "$2");
  const quoted = line.match(/['"]((?:\/|~\/)[^'"\s]+)['"]/);
  const path = quoted ?? line.match(/((?:\/|~\/)[^\s,;]+)/);
  return path?.[1] ?? "unknown";
}

function operationFromLine(line: string): string {
  return line.match(/\bdeny(?:\(\d+\))?\s+([\w-]+)/i)?.[1] ?? "";
}

function violationFromLine(line: string): SandboxViolation {
  const operation = operationFromLine(line);
  if (/^(?:network(?:-|$)|http-request$|connect$|outbound$)/i.test(operation)) return { kind: "network", resource: networkResourceFromLine(line) ?? resourceFromLine(line), message: line };
  if (/^file-read(?:-|$)/i.test(operation)) return { kind: "filesystem.read", resource: resourceFromLine(line), message: line };
  return { kind: "filesystem.write", resource: resourceFromLine(line), message: line };
}

/** Concrete adapter for @anthropic-ai/sandbox-runtime's per-command telemetry. */
export class AnthropicSandboxRuntime implements SandboxRuntime {
  readonly supportsNetworkWidening = process.platform === "darwin";
  private readonly proxies = new Map<string, CommandNetworkProxy>();
  private readonly strace = new Map<string, StraceViolationObserver>();
  private disposed = false;
  private commandKey(id: string): string { return this.settings.commandNamespace ? `${this.settings.commandNamespace}:${id}` : id; }
  private constructor(private readonly settings: SandboxSettings, private readonly useStrace: boolean, readonly logMonitorEnabled: boolean) {}

  static async initialize(settings: SandboxSettings, enableLogMonitor = process.platform === "darwin"): Promise<AnthropicSandboxRuntime> {
    const ubuntu = await isUbuntu();
    if (ubuntu) {
      try { await promisify(execFile)(STRACE_BINARY, [...STRACE_ARGS, "/usr/bin/true"], { timeout: 5000 }); }
      catch (cause) { throw new Error("Ubuntu filesystem observation requires working strace.", { cause }); }
    }
    // Linux's startup-policy observer cannot account for per-command grants.
    enableLogMonitor = process.platform === "darwin" && enableLogMonitor;
    const instance = new AnthropicSandboxRuntime(settings, ubuntu, enableLogMonitor);
    const shared = sharedRuntime();
    shared.instances.add(instance);
    try { await shared.manager.initialize(buildSandboxRuntimeConfig(settings, ubuntu), undefined, enableLogMonitor); }
    catch (cause) { shared.instances.delete(instance); throw new SandboxInitializationFailure(cause, enableLogMonitor); }
    return instance;
  }

  async wrap(command: string, context: { commandId: string; commandText: string; cwd?: string; extraCapabilities?: readonly import("./types.js").Capability[] }): Promise<string> {
    if (this.disposed) throw new Error("Sandbox runtime has been disposed");
    const extraWrites = context.extraCapabilities?.filter(capability => capability.kind === "filesystem.write").map(capability => capability.resource) ?? [];
    const policy = this.settings.writePolicy;
    const networkGrants = context.extraCapabilities?.filter(capability => capability.kind === "network") ?? [];
    if (networkGrants.length > 0 && !this.supportsNetworkWidening) throw new Error("Network widening is currently supported only on macOS");
    const endpoints = networkGrants.map(capability => {
      const endpoint = canonicalNetworkEndpoint(capability.resource);
      if (endpoint === undefined || endpoint !== capability.resource) throw new Error("Invalid canonical network grant");
      return endpoint;
    });
    let proxy: CommandNetworkProxy | undefined;
    if (this.supportsNetworkWidening) {
      if (this.proxies.has(context.commandId)) throw new Error("Duplicate active sandbox command ID");
      proxy = await createCommandNetworkProxy(this.commandKey(context.commandId), [...(this.settings.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS), ...endpoints], sharedRuntime().manager);
      this.proxies.set(context.commandId, proxy);
    }
    let wrapped: string;
    try {
      wrapped = await sharedRuntime().manager.wrapWithSandbox(command, undefined, {
        filesystem: { allowWrite: [...policy.allow, ...extraWrites], allowRead: [...(this.settings.allowRead ?? [])], denyRead: [], denyWrite: [...policy.deny] },
        // A foreground sibling may have initialized the shared SDK with a
        // different policy. Preserve this session's strict opt-out per attempt.
        ...(process.platform === "darwin" ? { network: {
          allowedDomains: [...(this.settings.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS), ...endpoints], deniedDomains: [],
          allowLocalBinding: this.settings.allowLocalBinding ?? true
        } } : {})
      }, undefined, { ...context, commandId: this.commandKey(context.commandId), ...(proxy ? { networkProxy: proxy } : {}) });
    } catch (error) {
      await this.forgetCommand(context.commandId);
      throw error;
    }
    if (this.useStrace) this.strace.set(context.commandId, new StraceViolationObserver(context.cwd ?? this.settings.cwd, { allow: [...policy.allow, ...extraWrites], deny: policy.deny }));
    return wrapped;
  }

  traceSinkForCommand(commandId: string): ((chunk: Buffer) => void) | undefined {
    const observer = this.strace.get(commandId);
    return observer ? chunk => observer.ingest(chunk) : undefined;
  }

  async forgetCommand(commandId: string): Promise<void> {
    this.strace.delete(commandId);
    const proxy = this.proxies.get(commandId);
    this.proxies.delete(commandId);
    await proxy?.close();
  }

  async getViolationsForCommand(commandId: string): Promise<readonly SandboxViolation[]> {
    const observer = this.strace.get(commandId);
    this.strace.delete(commandId);
    const store = sharedRuntime().manager.getSandboxViolationStore();
    const read = (): SandboxViolation[] => store.getViolationsForCommand(this.commandKey(commandId)).flatMap(event => {
      // Seatbelt also reports sysctl/Mach noise, which is not a supported
      // filesystem or network capability and must not become "unknown" writes.
      if (process.platform === "darwin" && !/^(?:file-(?:read|write)(?:-|$)|network(?:-|$)|http-request$)/i.test(operationFromLine(event.line))) return [];
      let raw = event.line;
      if (process.platform === "darwin") {
        if (typeof event.rawLine !== "string") throw new Error("SDK raw violation data is unavailable. Reinstall dependencies with lifecycle scripts enabled.");
        raw = event.rawLine;
        if (/[\x00-\x1f\x7f-\x9f]/.test(raw)) throw new Error("SDK violation contains unsupported control characters; resource approval was not attempted.");
      }
      return [{ ...violationFromLine(raw), message: event.line }];
    });
    let upstream = read();
    if (process.platform === "darwin" && this.logMonitorEnabled && upstream.length === 0) {
      // SDK log events can arrive after process exit. Only this invocation's
      // events end the bounded wait; an ordinary failure still returns empty.
      upstream = await new Promise<SandboxViolation[]>((resolve, reject) => {
        let unsubscribe: (() => void) | undefined;
        let finished = false;
        const finish = (result: SandboxViolation[], error?: unknown) => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          unsubscribe?.();
          if (error !== undefined) reject(error);
          else resolve(result);
        };
        const check = (deadline = false) => {
          try {
            const result = read();
            if (result.length > 0 || deadline) finish(result);
          } catch (error) { finish([], error); }
        };
        const timer = setTimeout(() => check(true), 1000);
        try {
          unsubscribe = store.subscribe(() => check());
          // subscribe delivers the current store synchronously as well.
          if (finished) unsubscribe();
        } catch (error) { finish([], error); }
      });
    }
    return observer ? [...upstream, ...await observer.getViolations()] : upstream;
  }

  /** Release only this session's proxies; keep siblings' SDK monitoring alive. */
  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    await Promise.all([...this.proxies.keys()].map(id => this.forgetCommand(id)));
    this.strace.clear();
    const shared = sharedRuntime();
    shared.instances.delete(this);
    if (shared.instances.size === 0) await shared.manager.reset();
  }

  static async reset(): Promise<void> {
    const shared = sharedRuntime();
    for (const instance of shared.instances) { instance.disposed = true; instance.strace.clear(); }
    shared.instances.clear();
    await closeCommandNetworkProxies();
    await shared.manager.reset();
  }
}
