import type { ApprovalDiagnosticEvent } from "./approval-diagnostics.js";

export const SESSION_AUDIT_TYPE = "pi-selective-sandbox:approval-audit:v1";
export const SESSION_AUDIT_STATUS_TYPE = "pi-selective-sandbox:approval-audit-status:v1";
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const token = /^[a-f0-9]{64}$/;
const events = ["provider.start", "provider.skip", "provider.response", "lookup.start", "lookup", "grant.load", "coverage", "approval.selection", "persist", "selector.dispatch", "selector.open", "selector.render", "selector.response", "bridge.response", "attempt.denial", "retry", "attempt.result", "operation.end"];
const enums: Record<string, readonly string[]> = {
  outcome: ["hit", "miss", "skipped", "success", "error", "selected", "dismissed", "aborted", "timeout", "unavailable", "deny", "allow"],
  authority: ["resource", "host"], duration: ["once", "session", "project"], renderer: ["local", "parent", "bridge"],
  stage: ["scope", "duration", "action", "host-duration", "host-confirm", "native", "custom"], relation: ["first", "same", "new", "mixed"],
  reason: ["headless", "aborted", "covered", "limit", "policy", "widen", "host", "not-requested"], execution: ["sandbox", "host"],
  disposition: ["sandbox", "host", "denied", "sandbox-unavailable"],
};
const unavailableReasons = ["filesystem-write-scope-unavailable", "network-runtime-unsupported", "network-target-unavailable", "filesystem-read-unsupported", "no-additional-scope"];
const networkReasons = ["proxy-allowlist", "proxy-address-guard", "proxy-host-invalid", "unix-socket", "raw-socket", "unknown"];
const networkFamilies = ["github", "github-actions", "go", "aws", "terraform", "other"];
const kinds = ["filesystem.read", "filesystem.write", "network"];

/** Strict projection: neither accidental extra fields nor arbitrary enum strings enter session history. */
export function sessionAuditEvent(input: ApprovalDiagnosticEvent): Record<string, unknown> | undefined {
  if (!input || typeof input !== "object" || input.version !== 1 || !events.includes(input.event) || ![input.originId, input.emitterId, input.operationId, input.requestId].every(id => typeof id === "string" && uuid.test(id))
    || !Number.isSafeInteger(input.sequence) || input.sequence <= 0 || !Number.isSafeInteger(input.time)
    || !Number.isSafeInteger(input.attempt) || input.attempt < 0 || input.attempt > 16
    || !["parent", "child"].includes(input.actor) || !["bash", "native"].includes(input.tool)) return undefined;
  const result: Record<string, unknown> = { version: 1, event: input.event, originId: input.originId, emitterId: input.emitterId,
    operationId: input.operationId, requestId: input.requestId, sequence: input.sequence, time: input.time,
    attempt: input.attempt, actor: input.actor, tool: input.tool };
  const fields: Record<string, unknown> = input;
  for (const [key, values] of Object.entries(enums)) {
    const value = fields[key];
    if (typeof value === "string" && values.includes(value)) result[key] = value;
  }
  for (const key of ["project", "callId"] as const) if (typeof input[key] === "string" && token.test(input[key])) result[key] = input[key];
  if (typeof input.selectorId === "string" && uuid.test(input.selectorId)) result.selectorId = input.selectorId;
  if (Number.isInteger(input.exitCode) && input.exitCode! >= -32768 && input.exitCode! <= 32767) result.exitCode = input.exitCode;
  for (const key of ["scopes", "observed"] as const) {
    const scopes = input[key];
    if (!Array.isArray(scopes)) continue;
    if (scopes.length > 128) return undefined;
    result[key] = scopes.filter(scope => scope && kinds.includes(scope.kind) && typeof scope.id === "string" && token.test(scope.id)).map(({ kind, id }) => ({ kind, id }));
  }
  if (Array.isArray(input.unavailableReasons)) {
    if (input.unavailableReasons.length > 16) return undefined;
    result.unavailableReasons = input.unavailableReasons.filter(reason => unavailableReasons.includes(reason));
  }
  if (Array.isArray(input.network)) {
    if (input.network.length > 128) return undefined;
    result.network = input.network.filter(target => target && typeof target.id === "string" && token.test(target.id) && networkReasons.includes(target.reason) && networkFamilies.includes(target.family))
      .map(({ id, reason, family }) => ({ id, reason, family }));
  }
  return result;
}

/** Default session persistence. No queue, background resource, raw identity or model-facing message. */
export function createSessionAuditSink(append: (type: string, data: unknown) => void, originId: string,
  limits: { maxBytes?: number; maxEvents?: number } = {}) {
  const maxBytes = limits.maxBytes ?? 4 * 1024 * 1024, maxEvents = limits.maxEvents ?? 8192;
  let started = false, closed = false, stopped = false, bytes = 0, count = 0;
  const status = (value: "recording" | "truncated" | "write-error") => {
    try { append(SESSION_AUDIT_STATUS_TYPE, { version: 1, originId, status: value, maxBytes, maxEvents, bytes, events: count,
      features: ["opaque-call-link", "network-reasons", "attempt-results", "retry-intent"] }); } catch { /* Best effort even if session persistence is unavailable. */ }
  };
  return {
    start() { if (started || closed) return; started = true; status("recording"); },
    get active() { return started && !closed; },
    sink(event: ApprovalDiagnosticEvent) {
      if (!started || closed || stopped) return;
      try {
        const safe = sessionAuditEvent(event);
        const size = safe ? Buffer.byteLength(JSON.stringify(safe)) : 0;
        if (!safe || size > 32 * 1024 || count >= maxEvents || bytes + size > maxBytes) {
          stopped = true; status("truncated"); return;
        }
        append(SESSION_AUDIT_TYPE, safe);
        count++; bytes += size;
      } catch { stopped = true; status("write-error"); }
    },
    close() { closed = true; }
  };
}

/** Join with the existing transcript call without adding its raw ID to diagnostic events. */
export function withSessionAuditLink<T>(result: T, originId: string, callId: string): T {
  try {
    if (!result || typeof result !== "object" || Array.isArray(result) || typeof originId !== "string" || typeof callId !== "string" || !uuid.test(originId) || !token.test(callId)) return result;
    const details = (result as { details?: unknown }).details;
    if (details !== undefined && (!details || typeof details !== "object" || Array.isArray(details))) return result;
    return { ...result, details: { ...details, selectiveSandboxAudit: { version: 1, originId, callId } } };
  } catch { return result; }
}
