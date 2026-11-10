#!/usr/bin/env node
// Reads safe diagnostic records, never searches tool stdout for approval markers.
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

const counts = { providerCalls: 0, responses: {}, selectorsInvoked: 0, customFirstRenders: 0, requestsWithSelectorInvocation: 0,
  childDispatches: 0, bridgeOutcomes: {}, lookups: {}, persistence: {}, denialTargetRelations: {}, invalidLines: 0,
  sessionFiles: 0, sessionFilesWithAudit: 0, sessionFilesWithoutAudit: 0, sessionStatusGaps: 0, sessionTruncated: 0, sessionWriteErrors: 0,
  hostFailures: 0, attemptResults: {}, operationResults: {}, networkReasons: {}, networkFamilies: {}, wideningUnavailableReasons: {},
  linkedToolResults: 0, requestsWithLinkedToolResult: 0 };
const seen = new Set(), statuses = new Set(), uiRequests = new Set(), linkedCalls = new Set(), requestCalls = new Map();
const sessionType = "pi-selective-sandbox:approval-audit:v1", statusType = "pi-selective-sandbox:approval-audit-status:v1";
const reasons = new Set(["proxy-allowlist", "proxy-address-guard", "proxy-host-invalid", "unix-socket", "raw-socket", "unknown"]);
const families = new Set(["github", "github-actions", "go", "aws", "terraform", "other"]);
const wideningReasons = new Set(["network-runtime-unsupported", "network-target-unavailable", "filesystem-read-unsupported", "filesystem-write-scope-unavailable", "no-additional-scope"]);
const increment = (object, key) => { object[key] = (object[key] ?? 0) + 1; };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/, token = /^[a-f0-9]{64}$/;
const isUuid = value => typeof value === "string" && uuid.test(value);
const isToken = value => typeof value === "string" && token.test(value);
for (const path of process.argv.slice(2)) {
  let isSession = false, hasAudit = false, hasStatus = false;
  for await (const line of createInterface({ input: createReadStream(path), crlfDelay: Infinity })) {
    let row;
    try { row = JSON.parse(line); } catch { counts.invalidLines++; continue; }
    if (!row || typeof row !== "object" || Array.isArray(row)) { counts.invalidLines++; continue; }
    if (typeof row.type === "string") {
      isSession = true; // Content, not filenames: sessions and private files can both have UUID names.
      if (row.type === "message") {
        const link = row.message?.role === "toolResult" ? row.message.details?.selectiveSandboxAudit : undefined;
        if (link?.version === 1 && isUuid(link.originId) && isToken(link.callId)) linkedCalls.add(`${link.originId}/${link.callId}`);
        continue;
      }
      if (row.type !== "custom") continue; // Never interpret custom_message or quoted text as audit metadata.
      if (row.customType === statusType) {
        const s = row.data;
        if (s?.version === 1 && isUuid(s.originId) && ["recording", "truncated", "write-error"].includes(s.status)) {
          hasStatus = true; hasAudit = true;
          const identity = `${s.originId}/${s.status}`;
          if (!statuses.has(identity)) {
            statuses.add(identity);
            if (s.status === "truncated") counts.sessionTruncated++;
            if (s.status === "write-error") counts.sessionWriteErrors++;
          }
        }
        continue;
      }
      if (row.customType !== sessionType) continue;
      row = row.data;
    }
    const e = row;
    if (!e || typeof e !== "object" || e.version !== 1 || ![e.originId, e.requestId, e.emitterId].every(isUuid)
      || !Number.isSafeInteger(e.sequence) || e.sequence <= 0 || !["parent", "child"].includes(e.actor) || !["bash", "native"].includes(e.tool)) { counts.invalidLines++; continue; }
    if (isSession) hasAudit = true;
    const identity = `${e.emitterId}/${e.sequence}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const request = `${e.originId}/${e.requestId}`;
    if (isToken(e.callId)) requestCalls.set(request, `${e.originId}/${e.callId}`);
    if (e.event === "provider.start") counts.providerCalls++;
    if (e.event === "selector.dispatch") counts.childDispatches++;
    if (e.event === "selector.open" && isUuid(e.selectorId) && ["local", "parent"].includes(e.renderer)) {
      counts.selectorsInvoked++; uiRequests.add(request);
    }
    if (e.event === "selector.render" && isUuid(e.selectorId)) counts.customFirstRenders++;
    if (e.event === "provider.response" && ["allow", "deny", "aborted", "error"].includes(e.outcome)) {
      const authority = ["resource", "host"].includes(e.authority) ? e.authority : "none";
      const duration = ["once", "session", "project"].includes(e.duration) ? e.duration : "none";
      increment(counts.responses, `${e.actor}/${e.tool}/${authority}/${duration}/${e.outcome}`);
    }
    if (["lookup", "persist"].includes(e.event) && ["resource", "host"].includes(e.authority)
      && ["session", "project"].includes(e.duration) && ["hit", "miss", "skipped", "success", "error"].includes(e.outcome)) {
      increment(e.event === "lookup" ? counts.lookups : counts.persistence, `${e.actor}/${e.tool}/${e.authority}/${e.duration}/${e.outcome}`);
    }
    if (e.event === "bridge.response" && ["selected", "dismissed", "aborted", "timeout", "unavailable"].includes(e.outcome)) increment(counts.bridgeOutcomes, e.outcome);
    if (e.event === "attempt.denial" && ["first", "same", "new", "mixed"].includes(e.relation)) increment(counts.denialTargetRelations, e.relation);
    if (e.event === "attempt.result" && ["sandbox", "host"].includes(e.execution)) {
      const failed = Number.isSafeInteger(e.exitCode) ? e.exitCode !== 0 : e.outcome === "error";
      if (e.execution === "host" && failed) counts.hostFailures++;
      if (Number.isSafeInteger(e.exitCode)) increment(counts.attemptResults, `${e.execution}/${failed ? "failure" : "success"}`);
      else if (e.outcome === "error") increment(counts.attemptResults, `${e.execution}/error`);
    }
    if (e.event === "operation.end" && ["sandbox", "host", "denied", "sandbox-unavailable"].includes(e.disposition)) {
      increment(counts.operationResults, `${e.disposition}/${Number.isSafeInteger(e.exitCode) ? e.exitCode === 0 ? "success" : "failure" : "error"}`);
    }
    if (e.event === "attempt.denial" && Array.isArray(e.network)) for (const item of e.network) {
      if (reasons.has(item?.reason)) increment(counts.networkReasons, item.reason);
      if (families.has(item?.family)) increment(counts.networkFamilies, item.family);
    }
    if (e.event === "provider.start" && Array.isArray(e.unavailableReasons)) for (const reason of e.unavailableReasons)
      if (wideningReasons.has(reason)) increment(counts.wideningUnavailableReasons, reason);
  }
  if (isSession) {
    counts.sessionFiles++;
    if (hasAudit) counts.sessionFilesWithAudit++; else counts.sessionFilesWithoutAudit++;
    if (!hasStatus) counts.sessionStatusGaps++;
  }
}
counts.requestsWithSelectorInvocation = uiRequests.size;
counts.linkedToolResults = linkedCalls.size;
counts.requestsWithLinkedToolResult = [...requestCalls.values()].filter(call => linkedCalls.has(call)).length;
console.log(JSON.stringify({ schema: 1, coverage: "best-effort; sessions without audit are unknown, not zero approvals; invocation is not pixel visibility; approval-required is not a UI count", ...counts }, null, 2));
