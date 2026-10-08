import type { ExtensionUIContext, Theme } from "@earendil-works/pi-coding-agent";
import { Key, matchesKey, SelectList, truncateToWidth, wrapTextWithAnsi, type Component } from "@earendil-works/pi-tui";
import { ancestorPaths, collapseWriteScopes } from "./resource-selection.js";
import { pathContains } from "./git-write-paths.js";
import type { Capability, EscalationApprovalRequest } from "./types.js";

export type ApprovalDuration = "once" | "session" | "project";
export const durationLabels = { once: "Once", session: "This session", project: "This project" } satisfies Record<ApprovalDuration, string>;
export type WideningChoice = { action: "allow"; capabilities: readonly Capability[]; duration: ApprovalDuration } | { action: "host" | "deny" };
export type WideningDialogOptions = {
  request: EscalationApprovalRequest;
  durations(capabilities: readonly Capability[]): ApprovalDuration[];
  warnings(capabilities: readonly Capability[]): string[];
  projectId?: string;
};
export type EscalationUI = {
  hasUI?: boolean;
  mode?: string;
  signal?: AbortSignal;
  ui?: Pick<ExtensionUIContext, "select"> & Partial<Pick<ExtensionUIContext, "custom">>;
  sessionManager?: { getSessionId(): string };
};

/** Escape terminal controls for presentation only; resource identities are never rewritten. */
export function displayText(text: string): string {
  return text.replace(/[\x00-\x09\x0b-\x1f\x7f-\x9f]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export function wideningSummary(options: WideningDialogOptions, selected: readonly Capability[], duration: ApprovalDuration): string {
  const { request } = options;
  const targets = request.observedCapabilities ?? request.capabilities;
  return [
    "Allow write access in sandbox", "", "Blocked target", ...targets.map(target => `  ${displayText(target.resource)}`),
    "", "Allow access to", ...selected.map(scope => `  ${displayText(scope.resource)}`),
    selected.some(scope => scope.resource === "/")
      ? "WARNING: Allows writes across the entire filesystem. Existing deny rules still apply."
      : "Allows writes to each selected path and everything beneath it. Existing deny rules still apply.",
    ...options.warnings(selected), "", `Duration: ${durationLabels[duration]}`,
    ...(duration === "project" && options.projectId ? [`Project: ${displayText(options.projectId)}`] : []),
    "", "Command", displayText(request.command),
    ...(request.commandIdentity ? [`Working directory: ${displayText(request.commandIdentity.cwd)}`] : []),
    "", "The entire command will run again and may repeat earlier side effects.",
    "This approval keeps the command inside the sandbox."
  ].join("\n");
}

/** Single TUI screen. The only editable values are predefined ancestor paths and durations. */
export function createWideningDialog(options: WideningDialogOptions, theme: Pick<Theme, "fg" | "bold">, refresh: () => void, done: (choice: WideningChoice) => void, height: () => number = () => Infinity): Component {
  const selected = options.request.capabilities.map(capability => ({ ...capability }));
  let duration: ApprovalDuration = "once";
  let focus = 0;
  let completed = false;
  let scrollTop = 0;
  let viewportHeight = 0;
  let contentHeight = 0;
  let lastWidth = 0;
  let revealFocus = true;
  // Keep hidden selections so narrowing an earlier parent restores later fields.
  const scopeIndices = () => {
    const indices: number[] = [];
    for (let index = 0; index < selected.length; index++) {
      if (!indices.some(previous => pathContains(selected[previous].resource, options.request.capabilities[index].resource))) indices.push(index);
    }
    return indices;
  };
  const selectedScopes = () => collapseWriteScopes(scopeIndices().map(index => selected[index]));
  const fields = () => [...scopeIndices(), selected.length, selected.length + 1];
  const finish = (choice: WideningChoice) => { if (!completed) { completed = true; done(choice); } };
  const listTheme = {
    selectedPrefix: (text: string) => theme.fg("accent", text), selectedText: (text: string) => theme.fg("accent", text),
    description: (text: string) => theme.fg("muted", text), scrollInfo: (text: string) => theme.fg("dim", text), noMatch: (text: string) => theme.fg("warning", text)
  };
  let durationList: SelectList;
  const updateDurations = () => {
    const available = options.durations(selectedScopes());
    if (!available.includes(duration)) duration = "once";
    durationList = new SelectList(available.map(value => ({ value, label: durationLabels[value] })), 3, listTheme);
    durationList.setSelectedIndex(available.indexOf(duration));
    durationList.onSelectionChange = item => { duration = item.value as ApprovalDuration; refresh(); };
    durationList.onSelect = () => { focus = selected.length + 1; refresh(); };
  };
  updateDurations();
  const scopeLists = selected.map((scope, index) => {
    const list = new SelectList(ancestorPaths(scope.resource).map((value, depth) => ({ value, label: displayText(value), description: depth === 0 ? "initial scope" : undefined })), 4, listTheme);
    list.onSelectionChange = item => { selected[index] = { kind: "filesystem.write", resource: item.value }; updateDurations(); refresh(); };
    list.onSelect = () => { focus = fields()[fields().indexOf(index) + 1]; refresh(); };
    return list;
  });
  const actions = new SelectList([
    { value: "allow", label: "Allow and retry" }, { value: "deny", label: "Deny" }, { value: "host", label: "Run outside sandbox…" }
  ], 3, listTheme);
  actions.onSelect = item => finish(item.value === "allow" ? { action: "allow", capabilities: selectedScopes(), duration } : { action: item.value as "host" | "deny" });
  return {
    invalidate() { for (const list of [...scopeLists, durationList, actions]) list.invalidate(); },
    handleInput(data) {
      if (completed) return;
      if (matchesKey(data, Key.escape)) { finish({ action: "deny" }); return; }
      if (matchesKey(data, Key.pageUp) || matchesKey(data, Key.pageDown)) {
        scrollTop = Math.max(0, Math.min(Math.max(0, contentHeight - viewportHeight), scrollTop + (matchesKey(data, Key.pageUp) ? -1 : 1) * Math.max(1, viewportHeight - 1)));
        revealFocus = false;
        refresh(); return;
      }
      revealFocus = true;
      if (matchesKey(data, Key.tab) || matchesKey(data, Key.shift("tab"))) {
        const active = fields();
        focus = active[(active.indexOf(focus) + (matchesKey(data, Key.tab) ? 1 : -1) + active.length) % active.length];
        refresh(); return;
      }
      let list = actions;
      if (focus < selected.length) list = scopeLists[focus];
      else if (focus === selected.length) list = durationList;
      list.handleInput(data); refresh();
    },
    render(width) {
      const lines: string[] = [];
      const w = Math.max(1, width);
      const indices = scopeIndices();
      const scopes = selectedScopes();
      let focusStart = 0, focusEnd = 0;
      const markFocus = (start: number) => { focusStart = start; focusEnd = lines.length; };
      const add = (text: string, color: "text" | "muted" | "warning" | "accent" = "text") => lines.push(...wrapTextWithAnsi(theme.fg(color, text), w));
      add(theme.bold("Allow write access in sandbox"), "accent");
      add("Blocked target", "muted");
      for (const target of options.request.observedCapabilities ?? options.request.capabilities) add(displayText(target.resource));
      lines.push("");
      for (const [position, index] of indices.entries()) {
        const start = lines.length;
        add(`${focus === index ? "> " : ""}Allow access to${indices.length > 1 ? ` (${position + 1}/${indices.length})` : ""}`, "accent");
        if (focus === index) lines.push(...scopeLists[index].render(w));
        add(`Selected: ${displayText(selected[index].resource)}`);
        if (focus === index) markFocus(start);
      }
      add(scopes.some(scope => scope.resource === "/")
        ? "WARNING: Allows writes across the entire filesystem. Existing deny rules still apply."
        : "Allows writes to each selected path and everything beneath it. Existing deny rules still apply.", scopes.some(scope => scope.resource === "/") ? "warning" : "muted");
      for (const warning of options.warnings(scopes)) add(warning, "warning");
      lines.push("");
      const durationStart = lines.length;
      add(`${focus === selected.length ? "> " : ""}Duration`, "accent");
      if (focus === selected.length) lines.push(...durationList.render(w));
      else add(durationLabels[duration]);
      if (focus === selected.length) markFocus(durationStart);
      if (duration === "project" && options.projectId) add(`Project: ${displayText(options.projectId)}`, "muted");
      lines.push("");
      add("Command", "muted");
      add(displayText(options.request.command));
      if (options.request.commandIdentity) add(`Working directory: ${displayText(options.request.commandIdentity.cwd)}`, "muted");
      add("The entire command will run again and may repeat earlier side effects.", "warning");
      lines.push("");
      const actionStart = lines.length;
      if (focus === selected.length + 1) { lines.push(...actions.render(w)); markFocus(actionStart); }
      else add("[Allow and retry]   [Deny]   [Run outside sandbox…]", "muted");
      const help = "PgUp/PgDn: scroll · Tab/Shift+Tab: field · ↑↓: select · Enter: continue/confirm · Esc: deny";
      const availableHeight = Math.max(2, Math.floor(height()));
      const nextViewportHeight = availableHeight - 1;
      if (nextViewportHeight !== viewportHeight || lastWidth !== w) revealFocus = true;
      viewportHeight = nextViewportHeight;
      lastWidth = w;
      contentHeight = lines.length;
      if (revealFocus) {
        if (focusStart < scrollTop || focusEnd > scrollTop + viewportHeight) scrollTop = focusStart;
        revealFocus = false;
      }
      scrollTop = Math.max(0, Math.min(scrollTop, Math.max(0, contentHeight - viewportHeight)));
      const visible = lines.slice(scrollTop, scrollTop + viewportHeight);
      const position = contentHeight > viewportHeight ? ` [${scrollTop + 1}-${Math.min(contentHeight, scrollTop + viewportHeight)}/${contentHeight}]` : "";
      return [...visible, theme.fg("muted", help + position)].map(line => truncateToWidth(line, w));
    }
  };
}

export async function showWideningDialog(context: EscalationUI, options: WideningDialogOptions): Promise<WideningChoice> {
  if (!context.hasUI || !context.ui || context.signal?.aborted) return { action: "deny" };
  if (context.mode === "tui" && context.ui.custom) {
    return await context.ui.custom<WideningChoice>((tui, theme, _keys, done) => {
      let settled = false;
      const finish = (choice: WideningChoice) => {
        if (settled) return;
        settled = true;
        context.signal?.removeEventListener("abort", abort);
        done(choice);
      };
      const abort = () => finish({ action: "deny" });
      const component = createWideningDialog(options, theme, () => tui.requestRender(), finish, () => Math.max(2, (tui.terminal?.rows ?? 24) - 4));
      context.signal?.addEventListener("abort", abort, { once: true });
      if (context.signal?.aborted) abort();
      return { ...component, dispose() { context.signal?.removeEventListener("abort", abort); } };
    }) ?? { action: "deny" };
  }
  // RPC cannot render custom terminal components. Preserve the same three decisions with built-in selectors.
  const selected: Capability[] = [];
  for (const target of options.request.capabilities) {
    if (selected.some(scope => pathContains(scope.resource, target.resource))) continue;
    const candidates = ancestorPaths(target.resource);
    const choice = await context.ui.select(`Allow write access in sandbox\n\nAllow access to\nInitial scope: ${displayText(target.resource)}`, candidates, { signal: context.signal });
    if (!choice || !candidates.includes(choice)) return { action: "deny" };
    selected.push({ kind: "filesystem.write", resource: choice });
  }
  const available = options.durations(selected);
  const chosen = await context.ui.select("Duration", available.map(value => durationLabels[value]), { signal: context.signal });
  const duration = available.find(value => durationLabels[value] === chosen);
  if (!duration) return { action: "deny" };
  const action = await context.ui.select(wideningSummary(options, selected, duration), ["Allow and retry", "Deny", "Run outside sandbox…"], { signal: context.signal });
  if (action === "Allow and retry") return { action: "allow", capabilities: selected, duration };
  return { action: action === "Run outside sandbox…" ? "host" : "deny" };
}
