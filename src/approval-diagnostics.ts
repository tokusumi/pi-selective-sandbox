import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, unlink, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import type { ApprovalRequest, Capability, NetworkDiagnostic, WideningUnavailableReason } from "./types.js";
import type { EscalationUI } from "./widening-dialog.js";

export type ApprovalCorrelation = { operationId: string; attempt: number; requestId?: string };
/** callId is an instance-keyed token, never the raw transcript tool-call identifier. */
export type ApprovalTrace = ApprovalCorrelation & { requestId: string; originId: string; actor: "parent" | "child"; tool: "bash" | "native"; callId?: string };
export type SelectorTrace = ApprovalTrace & { selectorId: string };
export type DiagnosticFields = {
  event: "provider.start" | "provider.skip" | "provider.response" | "lookup.start" | "lookup" | "grant.load" | "coverage" | "approval.selection" | "persist" | "selector.dispatch" | "selector.open" | "selector.render" | "selector.response" | "bridge.response" | "attempt.denial" | "retry" | "attempt.result" | "operation.end";
  outcome?: "hit" | "miss" | "skipped" | "success" | "error" | "selected" | "dismissed" | "aborted" | "timeout" | "unavailable" | "deny" | "allow";
  authority?: "resource" | "host";
  duration?: "once" | "session" | "project";
  renderer?: "local" | "parent" | "bridge";
  selectorId?: string;
  stage?: "scope" | "duration" | "action" | "host-duration" | "host-confirm" | "native" | "custom";
  scopes?: { kind: Capability["kind"]; id: string }[];
  observed?: { kind: Capability["kind"]; id: string }[];
  project?: string;
  network?: NetworkDiagnostic[];
  unavailableReasons?: readonly WideningUnavailableReason[];
  execution?: "sandbox" | "host";
  disposition?: "sandbox" | "host" | "denied" | "sandbox-unavailable";
  exitCode?: number;
  relation?: "first" | "same" | "new" | "mixed";
  reason?: "headless" | "aborted" | "covered" | "limit" | "policy" | "widen" | "host" | "not-requested";
};
export type ApprovalDiagnosticEvent = ApprovalTrace & DiagnosticFields & { version: 1; emitterId: string; sequence: number; time: number };
export type DiagnosticSink = (event: ApprovalDiagnosticEvent) => unknown;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

/** Optional bridge metadata is never authority. Invalid metadata is ignored, not a reason to deny. */
export function selectorTrace(value: unknown): SelectorTrace | undefined {
  if (!value || typeof value !== "object") return undefined;
  const v = value as SelectorTrace;
  if (![v.operationId, v.requestId, v.originId, v.selectorId].every(id => typeof id === "string" && uuid.test(id))
    || !Number.isSafeInteger(v.attempt) || v.attempt < 0 || v.attempt > 16
    || !["parent", "child"].includes(v.actor) || !["bash", "native"].includes(v.tool)) return undefined;
  // Copy only known fields, never transport extras.
  return { operationId: v.operationId, requestId: v.requestId, originId: v.originId, selectorId: v.selectorId, attempt: v.attempt, actor: v.actor, tool: v.tool,
    ...(typeof v.callId === "string" && /^[a-f0-9]{64}$/.test(v.callId) ? { callId: v.callId } : {}) };
}

/** No raw input, command digest, title, choice, path, session identity or error enters a sink. */
export class ApprovalDiagnostics {
  readonly originId = randomUUID();
  private readonly key = randomBytes(32);
  private sequence = 0;
  constructor(private readonly sink: DiagnosticSink) {}
  trace(request: ApprovalRequest, actor: ApprovalTrace["actor"] = "parent"): ApprovalTrace {
    const correlation = request.diagnosticContext;
    const valid = correlation && uuid.test(correlation.operationId) && Number.isSafeInteger(correlation.attempt) && correlation.attempt >= 0 && correlation.attempt <= 16;
    return { originId: this.originId, requestId: valid && correlation.requestId && uuid.test(correlation.requestId) ? correlation.requestId : randomUUID(), operationId: valid ? correlation.operationId : randomUUID(),
      attempt: valid ? correlation.attempt : 0, actor, tool: request.kind === "escalation" ? "bash" : "native", callId: this.token("call", request.toolCallId) };
  }
  token(domain: "project" | "scope" | "host" | "call", identity: string): string {
    return createHmac("sha256", this.key).update(domain).update("\0").update(identity).digest("hex");
  }
  scopes(capabilities: readonly Capability[]): NonNullable<DiagnosticFields["scopes"]> {
    return capabilities.map(c => ({ kind: c.kind, id: this.token("scope", `${c.kind}\0${c.resource}`) }));
  }
  emit(trace: ApprovalTrace, fields: DiagnosticFields): void {
    try {
      // Sink work is never awaited by an authorization or execution path.
      const result = this.sink({ ...trace, ...fields, version: 1, emitterId: this.originId, sequence: ++this.sequence, time: Date.now() });
      void Promise.resolve(result).catch(() => {});
    } catch { /* Diagnostic failure must not affect authority. */ }
  }
}

export type ApprovalAudit = { diagnostics: ApprovalDiagnostics; trace: ApprovalTrace; pendingLookup?: { authority: "resource" | "host"; duration: "session" | "project" } };
export function auditEvent(audit: ApprovalAudit | undefined, fields: DiagnosticFields): void { audit?.diagnostics.emit(audit.trace, fields); }

export function lookupStart(audit: ApprovalAudit | undefined, authority: "resource" | "host", duration: "session" | "project"): void {
  if (audit) audit.pendingLookup = { authority, duration };
  auditEvent(audit, { event: "lookup.start", authority, duration });
}

/** Record an already performed lookup without turning synchronous session operations into promises. */
export function lookupResult(audit: ApprovalAudit | undefined, authority: "resource" | "host", duration: "session" | "project", hit: boolean | undefined): boolean {
  if (audit) audit.pendingLookup = undefined;
  auditEvent(audit, { event: "lookup", authority, duration, outcome: hit === undefined ? "skipped" : hit ? "hit" : "miss" });
  return hit === true;
}

/** Session storage stays synchronous, including its original exception behavior. */
export function sessionPersistence(audit: ApprovalAudit | undefined, authority: "resource" | "host", grant: () => void): void {
  try { grant(); }
  catch (error) { auditEvent(audit, { event: "persist", authority, duration: "session", outcome: "error" }); throw error; }
  auditEvent(audit, { event: "persist", authority, duration: "session", outcome: "success" });
}

/** Preserve the selector's values and cancellation semantics; never record its text or choices. */
export function approvalSelect(context: EscalationUI, stage: DiagnosticFields["stage"], title: string, choices: string[], options?: { signal?: AbortSignal }): Promise<string | undefined> {
  const audit = context.approvalAudit;
  if (!audit) return context.ui!.select(title, choices, options);
  const selectorId = randomUUID();
  const fields = { selectorId, stage, renderer: context.diagnosticBridge ? "bridge" as const : "local" as const };
  auditEvent(audit, { event: context.diagnosticBridge ? "selector.dispatch" : "selector.open", ...fields });
  try {
    const pending = context.ui!.select(title, choices, context.diagnosticBridge
      ? { ...options, diagnostic: { ...audit.trace, selectorId } } : options);
    // Observe the original promise; do not put another awaited promise in the approval path.
    void pending.then(selected => {
      auditEvent(audit, { event: "selector.response", ...fields, outcome: options?.signal?.aborted ? "aborted" : selected === undefined ? "dismissed" : "selected" });
    }, () => { auditEvent(audit, { event: "selector.response", ...fields, outcome: "error" }); }).catch(() => {});
    return pending;
  } catch (error) { auditEvent(audit, { event: "selector.response", ...fields, outcome: "error" }); throw error; }
}

/** Bounded, best-effort opt-in storage. One exclusive file per extension instance; no shared append. */
export function createDiagnosticFileSink(directory: string) {
  const name = `${randomUUID()}.jsonl`;
  let file: FileHandle | undefined, failed = false, closed = false, pending = 0, bytes = 0;
  let queue = Promise.resolve();
  const maxBytes = 4 * 1024 * 1024;
  const retentionMs = 7 * 24 * 60 * 60 * 1000;
  let lastCleanup = 0;
  async function prepare() {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) throw new Error("Unsafe diagnostic directory");
    if (Date.now() - lastCleanup > 24 * 60 * 60 * 1000) {
      lastCleanup = Date.now();
      for (const entry of await readdir(directory)) {
        if (!uuid.test(entry.replace(/\.jsonl$/, "")) || !entry.endsWith(".jsonl")) continue;
        const path = join(directory, entry);
        const info = await lstat(path);
        if (info.isFile() && !info.isSymbolicLink() && info.mtimeMs < Date.now() - retentionMs) await unlink(path);
      }
    }
    file ??= await open(join(directory, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  }
  return {
    sink(event: ApprovalDiagnosticEvent): void {
      if (failed || closed || pending >= 256) return;
      let line: string;
      try { line = JSON.stringify(event) + "\n"; } catch { return; }
      if (bytes + Buffer.byteLength(line) > maxBytes) return;
      bytes += Buffer.byteLength(line); pending++;
      queue = queue.then(async () => {
        if (!failed) { await prepare(); await file!.writeFile(line); }
      }).catch(() => { failed = true; }).finally(() => { pending--; });
    },
    async flush() { await queue; },
    async close() { closed = true; await queue; await file?.close().catch(() => {}); file = undefined; }
  };
}
