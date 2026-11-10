#!/usr/bin/env node
// Counts diagnostic events only. Executor approval-required markers are NOT UI evidence.
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

const counts = { providerCalls: 0, responses: {}, selectorsInvoked: 0, customFirstRenders: 0, requestsWithSelectorInvocation: 0,
  childDispatches: 0, bridgeOutcomes: {}, lookups: {}, persistence: {}, denialTargetRelations: {}, invalidLines: 0 };
const seen = new Set(), uiRequests = new Set();
const increment = (object, key) => { object[key] = (object[key] ?? 0) + 1; };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
for (const path of process.argv.slice(2)) {
  for await (const line of createInterface({ input: createReadStream(path), crlfDelay: Infinity })) {
    let e;
    try { e = JSON.parse(line); } catch { counts.invalidLines++; continue; }
    if (e.version !== 1 || ![e.originId, e.requestId, e.emitterId].every(id => typeof id === "string" && uuid.test(id))
      || !Number.isSafeInteger(e.sequence) || e.sequence <= 0 || !["parent", "child"].includes(e.actor) || !["bash", "native"].includes(e.tool)) { counts.invalidLines++; continue; }
    const identity = `${e.emitterId}/${e.sequence}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    const request = `${e.originId}/${e.requestId}`;
    if (e.event === "provider.start") counts.providerCalls++;
    if (e.event === "selector.dispatch") counts.childDispatches++;
    if (e.event === "selector.open" && uuid.test(e.selectorId) && ["local", "parent"].includes(e.renderer)) {
      counts.selectorsInvoked++; uiRequests.add(request);
    }
    if (e.event === "selector.render" && uuid.test(e.selectorId)) counts.customFirstRenders++;
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
  }
}
counts.requestsWithSelectorInvocation = uiRequests.size;
console.log(JSON.stringify({ schema: 1, coverage: "best-effort; invocation is not pixel visibility; approval-required is not a UI count", ...counts }, null, 2));
