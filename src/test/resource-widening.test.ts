import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApprovalProvider } from "../pi-extension.js";
import { SessionGrantStore } from "../session-grants.js";
import { ProjectGrantStore } from "../project-grants.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import { ancestorPaths, validateWideningSelection } from "../resource-selection.js";
import { createWideningDialog, type WideningChoice, type WideningDialogOptions } from "../widening-dialog.js";
import { visibleWidth } from "@earendil-works/pi-tui";
import type { Capability, EscalationApprovalRequest } from "../types.js";

const write = (resource: string): Capability => ({ kind: "filesystem.write", resource });
const request = (resource: string): EscalationApprovalRequest => ({
  kind: "escalation", toolCallId: "widen", toolName: "bash", inputDigest: "digest",
  capabilities: [write(resource)], command: "touch output", replayWarning: true,
  sessionGrantEligible: true, projectGrantEligible: true,
  commandIdentity: { shellCommand: "touch output", cwd: "/project", executionMode: "shell" }
});

async function paths() {
  const base = await realpath(await mkdtemp(join(tmpdir(), "pi-widening-")));
  const parent = join(base, "outside");
  await mkdir(join(parent, "nested"), { recursive: true });
  return { base, parent, target: join(parent, "nested", "output") };
}

test("resource approval separates ancestor selection, duration, and final confirmation", async () => {
  const { parent, target } = await paths();
  const seen: { title: string; choices: string[] }[] = [];
  const answers = [parent, "This session", "Allow and retry"];
  const grants = new SessionGrantStore();
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: {
    select: async (title, choices) => { seen.push({ title, choices }); return answers.shift(); }
  } }, grants);
  assert.deepEqual(await provider.request(request(target)), { decision: "sandbox-allow-session", capabilities: [write(parent)] });
  assert.equal(seen.length, 3);
  assert.equal(seen[0].choices[0], target);
  assert.ok(seen[0].choices.includes(parent));
  assert.ok(seen[0].choices.includes("/"));
  assert.equal(seen[1].choices[0], "Once");
  assert.match(seen[2].title, /Blocked target/);
  assert.match(seen[2].title, /everything beneath/);
  assert.match(seen[2].title, /entire command/);
  assert.equal(grants.covers("A", [write(parent)]), true);
  assert.equal(grants.covers("A", [write(target)]), false);
});

test("executor retries with the selected ancestor, never on the host", async () => {
  const attempts: Capability[][] = [];
  const executor = new SelectiveSandboxExecutor({
    runtime: {
      wrap: async (command, context) => { attempts.push([...(context.extraCapabilities ?? [])]); return command; },
      getViolationsForCommand: () => [write("/outside/nested/file")]
    },
    runner: { runSandbox: async () => ({ exitCode: attempts.length === 1 ? 1 : 0, stdout: "", stderr: "" }), runHost: async () => { throw new Error("Unexpected host replay"); } },
    policy: new CapabilityPolicy([]),
    approvals: { request: async () => ({ decision: "sandbox-allow-once", capabilities: [write("/outside")] }) }
  });
  assert.equal((await executor.execute("touch output", "ancestor")).exitCode, 0);
  assert.deepEqual(attempts, [[], [write("/outside")]]);
});


test("ancestors are selectable through root without a HOME special case", async () => {
  assert.deepEqual(ancestorPaths("/Users/me/work/nested/file"), ["/Users/me/work/nested/file", "/Users/me/work/nested", "/Users/me/work", "/Users/me", "/Users", "/"]);
  assert.deepEqual(ancestorPaths("/"), ["/"]);
  assert.deepEqual(ancestorPaths("relative/file"), []);
  assert.deepEqual(ancestorPaths("/path/with\ncontrol"), []);
  assert.equal(await validateWideningSelection([write("/outside/file")], [write("/")]), true);
  assert.equal(await validateWideningSelection([write("/outside/file")], [write("/outside-sibling")]), false);
  assert.equal(await validateWideningSelection([write("/outside/file")], [{ kind: "network", resource: "/outside" }]), false);
  assert.equal(await validateWideningSelection([write("/outside/file"), write("/other/file")], [write("/outside")]), false);
});

test("project approval persists only the selected canonical ancestor", async () => {
  const { base, parent, target } = await paths();
  const store = new ProjectGrantStore(join(base, "grants.json"));
  const answers = [parent, "This project", "Allow and retry"];
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async () => answers.shift() } }, new SessionGrantStore(), { projectId: "/project", grants: store });
  assert.deepEqual(await provider.request(request(target)), { decision: "sandbox-allow-project", capabilities: [write(parent)] });
  const stored = JSON.parse(await readFile(store.storagePath, "utf8"));
  assert.deepEqual(stored.projects["/project"], [write(parent)]);
  assert.equal(await new ProjectGrantStore(store.storagePath).covers("/project", [write(parent)]), true);
  assert.equal(await store.covers("/another-project", [write(parent)]), false);
});

test("invalid free-form answers and cancellation cannot create grants", async () => {
  const { parent, target } = await paths();
  for (const answers of [[parent + "-sibling"], [parent, undefined], [parent, "This session", "Deny"]]) {
    const grants = new SessionGrantStore();
    const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => answers.shift() } }, grants);
    assert.equal(await provider.request(request(target)), "deny");
    assert.deepEqual(grants.capabilities("A"), []);
  }
});

test("retargeting a canonical ancestor while the dialog is open denies approval", async () => {
  const { base, parent, target } = await paths();
  const elsewhere = join(base, "elsewhere");
  await mkdir(elsewhere);
  const answers = [parent, "This session", "Allow and retry"];
  const grants = new SessionGrantStore();
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => {
    const answer = answers.shift();
    if (answer === "Allow and retry") { await rm(parent, { recursive: true }); await symlink(elsewhere, parent); }
    return answer;
  } } }, grants);
  assert.equal(await provider.request(request(target)), "deny");
  assert.deepEqual(grants.capabilities("A"), []);
});

test("executor rejects unrelated or incomplete selected resources without rerunning", async () => {
  for (const capabilities of [[write("/sibling")], [], [{ kind: "network" as const, resource: "/outside" }]]) {
    let runs = 0;
    const executor = new SelectiveSandboxExecutor({
      runtime: { wrap: async command => command, getViolationsForCommand: () => [write("/outside/file")] },
      runner: { runSandbox: async () => { runs++; return { exitCode: 1, stdout: "", stderr: "blocked" }; }, runHost: async () => { throw new Error("Unexpected host replay"); } },
      policy: new CapabilityPolicy([]), approvals: { request: async () => ({ decision: "sandbox-allow-once", capabilities }) }
    });
    assert.equal((await executor.execute("touch output", "invalid-choice")).disposition, "denied");
    assert.equal(runs, 1);
  }
});

test("a denial beneath an already approved ancestor does not ask for the same authority again", async () => {
  let prompts = 0, runs = 0;
  const executor = new SelectiveSandboxExecutor({
    runtime: { wrap: async command => command, getViolationsForCommand: () => [write("/outside/file")] },
    runner: { runSandbox: async () => { runs++; return { exitCode: 1, stdout: "", stderr: "blocked" }; }, runHost: async () => { throw new Error("Unexpected host replay"); } },
    policy: new CapabilityPolicy([]),
    approvals: { request: async () => { prompts++; return { decision: "sandbox-allow-once", capabilities: [write("/outside")] }; } }
  });
  assert.equal((await executor.execute("touch output", "repeat-ancestor")).disposition, "sandbox");
  assert.equal(prompts, 1);
  assert.equal(runs, 2);
});

function dialogOptions(target = "/Users/me/長いディレクトリ/cache/output"): WideningDialogOptions {
  return {
    request: request(target),
    durations: () => ["once", "session", "project"], warnings: () => [], projectId: "/project"
  };
}
const plainTheme = { fg: (_color: string, text: string) => text, bold: (text: string) => text };

test("TUI starts narrow and once; pasted paths do nothing; Enter requires final confirmation", () => {
  const results: WideningChoice[] = [];
  const options = dialogOptions();
  const dialog = createWideningDialog(options, plainTheme, () => {}, choice => results.push(choice));
  assert.match(dialog.render(80).join("\n"), /Duration\nOnce/);
  dialog.handleInput?.("/arbitrary/path");
  dialog.handleInput?.("\r"); // scope -> duration
  dialog.handleInput?.("\r"); // duration -> actions
  assert.deepEqual(results, []);
  dialog.handleInput?.("\r");
  assert.deepEqual(results, [{ action: "allow", capabilities: options.request.capabilities, duration: "once" }]);
});

test("TUI selects a multi-level ancestor, warns at root, and fits narrow/wide-character terminals", () => {
  const results: WideningChoice[] = [];
  const dialog = createWideningDialog(dialogOptions(), plainTheme, () => {}, choice => results.push(choice));
  for (let index = 0; index < ancestorPaths(dialogOptions().request.capabilities[0].resource).length - 1; index++) dialog.handleInput?.("\x1b[B");
  assert.match(dialog.render(80).join("\n"), /entire filesystem/);
  for (const width of [1, 12, 40, 100]) {
    dialog.invalidate();
    const lines = dialog.render(width);
    assert.ok(lines.every(line => visibleWidth(line) <= width));
  }
  dialog.handleInput?.("\r");
  dialog.handleInput?.("\r");
  dialog.handleInput?.("\r");
  assert.deepEqual(results, [{ action: "allow", capabilities: [write("/")], duration: "once" }]);
});

test("TUI Escape always denies without confirming or persisting a scope", () => {
  const results: WideningChoice[] = [];
  const dialog = createWideningDialog(dialogOptions(), plainTheme, () => {}, choice => results.push(choice));
  dialog.handleInput?.("\x1b");
  dialog.handleInput?.("\r");
  assert.deepEqual(results, [{ action: "deny" }]);
});


test("an already aborted approval does not open UI or create a grant", async () => {
  const { parent, target } = await paths();
  const controller = new AbortController(); controller.abort();
  const grants = new SessionGrantStore();
  let prompts = 0;
  const answers = [parent, "This session", "Allow and retry"];
  const provider = createApprovalProvider({ hasUI: true, signal: controller.signal, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => { prompts++; return answers.shift(); } } }, grants);
  assert.equal(await provider.request(request(target)), "deny");
  assert.equal(prompts, 0);
  assert.deepEqual(grants.capabilities("A"), []);
});

test("selecting a parent skips covered later targets before final confirmation", async () => {
  const { parent, target } = await paths();
  const other = join(parent, "other", "output");
  const answers = [parent, "This session", "Allow and retry"];
  const grants = new SessionGrantStore();
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async () => answers.shift() } }, grants);
  assert.deepEqual(await provider.request({ ...request(target), capabilities: [write(target), write(other)] }), {
    decision: "sandbox-allow-session", capabilities: [write(parent)]
  });
  assert.deepEqual(grants.capabilities("A"), [write(parent)]);
});

test("RPC still asks for a sibling outside the selected parent", async () => {
  const { parent, target } = await paths();
  const sibling = `${parent}-sibling/output`;
  const answers = [parent, sibling, "Once", "Allow and retry"];
  const seen: string[] = [];
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async title => { seen.push(title); return answers.shift(); } } }, new SessionGrantStore());
  assert.deepEqual(await provider.request({ ...request(target), capabilities: [write(target), write(join(parent, "other")), write(sibling)] }), {
    decision: "sandbox-allow-once", capabilities: [write(parent), write(sibling)]
  });
  assert.equal(seen.length, 4);
  assert.match(seen[3], /other/); // skipped targets remain in the final disclosure
});

test("TUI skips covered fields, restores them on narrowing, and still requires confirmation", () => {
  const options = dialogOptions("/aaa/bbb/ccc");
  options.request.capabilities = [write("/aaa/bbb/ccc"), write("/aaa/bbb/ddd"), write("/aaa/bbb/eee")];
  const results: WideningChoice[] = [];
  const dialog = createWideningDialog(options, plainTheme, () => {}, choice => results.push(choice));
  dialog.handleInput?.("\x1b[B"); // select /aaa/bbb
  dialog.handleInput?.("\r"); // skip remaining paths -> duration
  assert.match(dialog.render(100).join("\n"), /> Duration/);
  assert.doesNotMatch(dialog.render(100).join("\n"), /Selected: \/aaa\/bbb\/(ddd|eee)/);
  dialog.handleInput?.("\x1b[Z"); // Shift+Tab -> parent field
  dialog.handleInput?.("\x1b[A"); // narrow to original
  dialog.handleInput?.("\r");
  assert.match(dialog.render(100).join("\n"), /> Allow access to \(2\/3\)/);
  dialog.handleInput?.("\x1b[Z");
  dialog.handleInput?.("\x1b[B"); // widen again
  dialog.handleInput?.("\r");
  dialog.handleInput?.("\r"); // duration -> actions
  assert.deepEqual(results, []);
  dialog.handleInput?.("\r");
  assert.deepEqual(results, [{ action: "allow", capabilities: [write("/aaa/bbb")], duration: "once" }]);
});

test("TUI does not hide a similarly named sibling, and reverse Tab skips covered fields", () => {
  const options = dialogOptions("/aaa/bbb/ccc");
  options.request.capabilities = [write("/aaa/bbb/ccc"), write("/aaa/bbb/ddd"), write("/aaa/bbb-other/eee")];
  const dialog = createWideningDialog(options, plainTheme, () => {}, () => {});
  dialog.handleInput?.("\x1b[B");
  dialog.handleInput?.("\r");
  assert.match(dialog.render(100).join("\n"), /> Allow access to \(2\/2\)/);
  assert.match(dialog.render(100).join("\n"), /Selected: \/aaa\/bbb-other\/eee/);
  dialog.handleInput?.("\r");
  dialog.handleInput?.("\x1b[Z");
  assert.match(dialog.render(100).join("\n"), /> Allow access to \(2\/2\)/);
  dialog.handleInput?.("\x1b[Z");
  assert.match(dialog.render(100).join("\n"), /> Allow access to \(1\/2\)/);
});

test("a root choice keeps its filesystem warning visible in a bounded approval", () => {
  const options = dialogOptions("/outside/dir-0/output");
  options.request.capabilities = Array.from({ length: 50 }, (_, index) => write(`/outside/dir-${index}/output`));
  const dialog = createWideningDialog(options, plainTheme, () => {}, () => {}, () => 20);
  dialog.render(80);
  for (let index = 0; index < 3; index++) { dialog.handleInput?.("\x1b[B"); dialog.render(80); }
  assert.match(dialog.render(80).join("\n"), /entire filesystem/);
});

test("TUI bounds long approvals, scrolls without changing grants, and follows focus after resize", async () => {
  const capabilities = Array.from({ length: 50 }, (_, index) => write(`/outside/dir-${index}/長い名前/output`));
  let rows = 24;
  const provider = createApprovalProvider({ mode: "tui", hasUI: true, ui: {
    select: async () => { throw new Error("Unexpected selector"); },
    custom: async factory => new Promise(resolve => {
      const dialog = factory({ terminal: { get rows() { return rows; } }, requestRender() {} } as any, plainTheme as any, {} as any, resolve);
      assert.ok(!(dialog instanceof Promise));
      if (dialog instanceof Promise) return;
      const render = (width = 80) => {
        const lines = dialog.render(width);
        assert.ok(lines.length <= rows - 4, `rendered ${lines.length} lines in ${rows} rows`);
        assert.ok(lines.every(line => visibleWidth(line) <= width));
        return lines.join("\n");
      };
      const initial = render();
      assert.match(initial, /> Allow access to \(1\/50\)/);
      for (let index = 0; index < 20; index++) dialog.handleInput?.("\x1b[5~"); // inspect blocked targets at the top
      assert.match(render(), /Blocked target/);
      dialog.handleInput?.("\x1b[6~"); // PageDown: scroll, not select
      assert.notEqual(render(), initial);
      dialog.handleInput?.("\r"); // follow next field, independent of manual scroll
      assert.match(render(), /> Allow access to \(2\/50\)/);
      for (let index = 2; index < 50; index++) dialog.handleInput?.("\r");
      assert.match(render(), /> Allow access to \(50\/50\)/);
      dialog.handleInput?.("\r");
      assert.match(render(), /> Duration/);
      dialog.handleInput?.("\r");
      assert.match(render(), /Allow and retry/);
      rows = 12;
      dialog.invalidate();
      assert.match(render(40), /Allow and retry/);
      for (const width of [1, 12, 80]) render(width);
      rows = 30;
      dialog.invalidate();
      assert.match(render(), /Allow and retry/);
      dialog.handleInput?.("\x1b");
    })
  } }, new SessionGrantStore());
  assert.equal(await provider.request({ ...request(capabilities[0].resource), capabilities }), "deny");
});

test("observed Git leaf stays visible separately from the prepared metadata scope", async () => {
  const { parent } = await paths();
  const answers = [parent, "Once", "Deny"];
  let summary = "";
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async (title) => { summary = title; return answers.shift(); } } }, new SessionGrantStore());
  await provider.request({ ...request(parent), observedCapabilities: [write(join(parent, "index.lock"))] });
  assert.match(summary, /Blocked target[\s\S]*index\.lock/);
  assert.ok(summary.includes("Allow access to\n  " + parent));
});

test("TUI mode uses custom UI while RPC mode never invokes custom components", async () => {
  const { target } = await paths();
  let customCalls = 0, selectCalls = 0;
  const provider = createApprovalProvider({ mode: "tui", hasUI: true, ui: {
    select: async () => { selectCalls++; return "Deny"; },
    custom: async factory => {
      customCalls++;
      return new Promise(resolve => {
        // SAFETY: The component only needs requestRender and the two theme helpers exercised here.
        const dialog = factory({ requestRender() {} } as any, plainTheme as any, {} as any, resolve);
        assert.ok(!(dialog instanceof Promise));
        if (!(dialog instanceof Promise)) { dialog.handleInput?.("\r"); dialog.handleInput?.("\r"); dialog.handleInput?.("\r"); }
      });
    }
  } }, new SessionGrantStore());
  assert.deepEqual(await provider.request(request(target)), { decision: "sandbox-allow-once", capabilities: [write(target)] });
  assert.equal(customCalls, 1); assert.equal(selectCalls, 0);
  const rpc = createApprovalProvider({ mode: "rpc", hasUI: true, ui: {
    select: async () => "Deny", custom: async () => { throw new Error("RPC cannot render custom UI"); }
  } }, new SessionGrantStore());
  assert.equal(await rpc.request(request(target)), "deny");
});

test("project persistence failure denies the selected ancestor", async t => {
  const { base, parent, target } = await paths();
  const store = new ProjectGrantStore(join(base, "grants.json"));
  t.mock.method(store, "grant", async () => { throw new Error("storage unavailable"); });
  const answers = [parent, "This project", "Allow and retry"];
  const provider = createApprovalProvider({ hasUI: true, ui: { select: async () => answers.shift() } }, new SessionGrantStore(), { projectId: "/project", grants: store });
  assert.equal(await provider.request(request(target)), "deny");
  assert.deepEqual(await store.capabilities("/project"), []);
});

test("selecting a parent of shared Git metadata restricts durations to Once", async () => {
  const { base, parent, target } = await paths();
  const commonDir = join(parent, "nested");
  const seen: string[][] = [];
  const answers = [parent, "Once", "Allow and retry"];
  const provider = createApprovalProvider({ hasUI: true, sessionManager: { getSessionId: () => "A" }, ui: { select: async (_title, choices) => { seen.push(choices); return answers.shift(); } } }, new SessionGrantStore(), {
    projectId: "/project", grants: new ProjectGrantStore(join(base, "grants.json"))
  }, undefined, { commonDir, worktreeDir: join(commonDir, "worktrees", "one") });
  assert.deepEqual(await provider.request(request(target)), { decision: "sandbox-allow-once", capabilities: [write(parent)] });
  assert.deepEqual(seen[1], ["Once"]);
});


test("aborting an open TUI closes it as denial and stores no grant", async () => {
  const { target } = await paths();
  const controller = new AbortController();
  const grants = new SessionGrantStore();
  let disposed = false;
  const provider = createApprovalProvider({ mode: "tui", hasUI: true, signal: controller.signal, sessionManager: { getSessionId: () => "A" }, ui: {
    select: async () => { throw new Error("Unexpected selector"); },
    custom: async factory => {
      const result = new Promise(resolve => {
        // SAFETY: This rendering-independent cancellation test only requires requestRender and theme helpers.
        const component = factory({ requestRender() {} } as any, plainTheme as any, {} as any, resolve);
        assert.ok(!(component instanceof Promise));
        controller.abort();
        if (!(component instanceof Promise)) { component.dispose?.(); disposed = true; }
      });
      return await result as any;
    }
  } }, grants);
  assert.equal(await provider.request(request(target)), "deny");
  assert.equal(disposed, true);
  assert.deepEqual(grants.capabilities("A"), []);
});

test("a root selection does not turn a configured-deny violation into another resource approval", async () => {
  let attempts = 0;
  const seen: Capability[][] = [];
  const executor = new SelectiveSandboxExecutor({
    runtime: { wrap: async command => command, getViolationsForCommand: () => [write(attempts === 1 ? "/outside/file" : "/denied/secret")] },
    runner: { runSandbox: async () => { attempts++; return { exitCode: 1, stdout: "", stderr: "denied" }; }, runHost: async () => { throw new Error("Unexpected host replay"); } },
    policy: new CapabilityPolicy([]),
    canonicalizeCapabilities: async capabilities => capabilities.some(capability => capability.resource.startsWith("/denied/")) ? undefined : capabilities,
    approvals: { request: async approval => {
      seen.push([...approval.capabilities]);
      return seen.length === 1 ? { decision: "sandbox-allow-once", capabilities: [write("/")] } : "deny";
    } }
  });
  assert.equal((await executor.execute("touch output", "root-deny")).disposition, "denied");
  assert.equal(attempts, 2);
  assert.deepEqual(seen, [[write("/outside/file")], []]);
});
