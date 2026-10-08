import { randomBytes, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, mkdtemp, open, readdir, realpath, rename, rm, unlink, access } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { displayText, type EscalationUI } from "./widening-dialog.js";

export const SUBAGENT_BINDING_EVENT = "pi-selective-sandbox:child-binding:v1";
export type ApprovalBridgeBinding = { version: 1; parentSessionId: string; directory: string; nonce: string };
const MAX_BYTES = 256 * 1024;
const MAX_PENDING = 32;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const control = /[\x00-\x1f\x7f-\x9f]/;
type SelectionRequest = { version: 1; id: string; parentSessionId: string; nonce: string; childSessionId: string; cwd: string; title: string; choices: string[]; expiresAt: number };
type SelectionReply = { version: 1; id: string; parentSessionId: string; nonce: string; index: number };
type Select = (title: string, choices: string[], options: { signal: AbortSignal }) => Promise<string | undefined>;
const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const bounded = (value: unknown, length: number): value is string => typeof value === "string" && value.length > 0 && value.length <= length;

export function validBridgeBinding(value: unknown): value is ApprovalBridgeBinding {
  return record(value) && value.version === 1 && bounded(value.parentSessionId, 256) && !control.test(value.parentSessionId)
    && bounded(value.directory, 4096) && isAbsolute(value.directory) && !control.test(value.directory)
    && typeof value.nonce === "string" && /^[a-f0-9]{64}$/.test(value.nonce);
}

/** Never follow a model-created symlink or consume an unbounded queue file. */
async function readJson(path: string): Promise<unknown> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_BYTES) throw new Error("Invalid approval transport file");
    if (process.getuid && stat.uid !== process.getuid()) throw new Error("Invalid approval transport owner");
    return JSON.parse(await file.readFile("utf8"));
  } finally { await file.close(); }
}
async function writeJson(path: string, value: unknown): Promise<void> {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text) > MAX_BYTES) throw new Error("Approval request too large");
  const temporary = `${path}.${randomUUID()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(text); } finally { await file.close(); }
  try { await rename(temporary, path); } finally { await removeFile(temporary); }
}
async function removeFile(path: string): Promise<void> {
  try { await unlink(path); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}
const reportError = (error: unknown) => console.warn(`Subagent sandbox approval transport failed (${error instanceof Error ? error.name : "Error"}); access was denied.`);
function validRequest(value: unknown, binding: ApprovalBridgeBinding, id: string): value is SelectionRequest {
  return record(value) && value.version === 1 && value.id === id && value.parentSessionId === binding.parentSessionId && value.nonce === binding.nonce
    && bounded(value.childSessionId, 256) && !control.test(value.childSessionId) && bounded(value.cwd, 4096) && isAbsolute(value.cwd) && !control.test(value.cwd)
    && bounded(value.title, 128 * 1024) && Array.isArray(value.choices) && value.choices.length > 0 && value.choices.length <= 128
    && value.choices.every(choice => bounded(choice, 4096) && !control.test(choice)) && new Set(value.choices).size === value.choices.length
    && typeof value.expiresAt === "number" && Number.isFinite(value.expiresAt) && value.expiresAt > Date.now() && value.expiresAt <= Date.now() + DEFAULT_TIMEOUT_MS;
}

/** The root is explicitly deny-listed for sandbox/native tools, even beneath a widened ancestor. */
export async function startApprovalBridge(options: { root: string; parentSessionId: string; select: Select; pollIntervalMs?: number }) {
  await mkdir(options.root, { recursive: true, mode: 0o700 });
  const directory = await realpath(await mkdtemp(join(options.root, "session-")));
  const binding: ApprovalBridgeBinding = { version: 1, parentSessionId: options.parentSessionId, directory, nonce: randomBytes(32).toString("hex") };
  if (!validBridgeBinding(binding)) throw new Error("Invalid approval bridge identity");
  await writeJson(join(directory, "alive.json"), binding);
  let closed = false, polling = false;
  let queue = Promise.resolve();
  let closing: Promise<void> | undefined;
  const pending = new Map<string, { controller: AbortController; expiresAt: number }>();
  async function serve(id: string, request: SelectionRequest, controller: AbortController) {
    const requestPath = join(directory, `${id}.request.json`);
    const cancelled = new Promise<undefined>(resolve => {
      if (controller.signal.aborted) resolve(undefined);
      else controller.signal.addEventListener("abort", () => resolve(undefined), { once: true });
    });
    try {
      if (closed || controller.signal.aborted || request.expiresAt <= Date.now()) return;
      await access(requestPath); // A queued child may have cancelled before its turn.
      if (closed || controller.signal.aborted || request.expiresAt <= Date.now()) return;
      const title = `Subagent sandbox approval\nChild session: ${request.childSessionId}\nWorking directory: ${request.cwd}\n\n${displayText(request.title)}`;
      const choice = await Promise.race([Promise.resolve().then(() => controller.signal.aborted ? undefined : options.select(title, [...request.choices], { signal: controller.signal })), cancelled]);
      if (closed || controller.signal.aborted || request.expiresAt <= Date.now()) return;
      await access(requestPath); // Child cancellation revokes the still-pending request.
      const reply: SelectionReply = { version: 1, id, parentSessionId: binding.parentSessionId, nonce: binding.nonce, index: choice === undefined ? -1 : request.choices.indexOf(choice) };
      const replyPath = join(directory, `${id}.reply.json`);
      await writeJson(replyPath, reply);
      // A child can cancel while the atomic response is being written. Do not
      // accumulate orphan replies that could starve the bounded queue scan.
      try { await access(requestPath); } catch { await removeFile(replyPath); }
    } catch (error) {
      if (!closed && !controller.signal.aborted && (error as NodeJS.ErrnoException).code !== "ENOENT") reportError(error);
    } finally {
      controller.abort();
      try { await removeFile(requestPath); } catch (error) { if (!closed) reportError(error); }
      pending.delete(id);
    }
  }
  async function poll() {
    if (closed || polling) return;
    polling = true;
    try {
      for (const [id, item] of pending) {
        if (item.expiresAt <= Date.now()) item.controller.abort();
        else try { await access(join(directory, `${id}.request.json`)); } catch { item.controller.abort(); }
      }
      for (const name of (await readdir(directory)).filter(name => name.endsWith(".request.json")).slice(0, 128)) {
        const id = name.slice(0, -".request.json".length);
        if (!UUID.test(id) || pending.has(id)) continue;
        const path = join(directory, name);
        try {
          const request = await readJson(path);
          if (closed) break;
          if (!validRequest(request, binding, id) || pending.size >= MAX_PENDING) { await removeFile(path); continue; }
          const controller = new AbortController();
          pending.set(id, { controller, expiresAt: request.expiresAt });
          queue = queue.then(() => serve(id, request, controller));
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") { reportError(error); await removeFile(path); }
        }
      }
    } catch (error) { if (!closed) reportError(error); }
    finally { polling = false; }
  }
  const timer = setInterval(() => { void poll(); }, options.pollIntervalMs ?? 50);
  timer.unref();
  return {
    binding,
    close(): Promise<void> {
      return closing ??= (async () => {
        closed = true;
        clearInterval(timer);
        for (const item of pending.values()) item.controller.abort();
        await queue;
        // Delete only the directory this instance created, never a replaced path.
        if (await realpath(directory).catch(() => undefined) === directory) await rm(directory, { recursive: true, force: true });
      })();
    }
  };
}

async function requestSelection(binding: ApprovalBridgeBinding, child: EscalationUI & { cwd?: string }, title: string, choices: string[], options: { signal?: AbortSignal; timeoutMs?: number; pollIntervalMs?: number }): Promise<string | undefined> {
  const signal = options.signal ?? child.signal;
  if (!validBridgeBinding(binding) || signal?.aborted) return undefined;
  const id = randomUUID();
  const requestPath = join(binding.directory, `${id}.request.json`), replyPath = join(binding.directory, `${id}.reply.json`);
  const request: SelectionRequest = { ...binding, id, childSessionId: child.sessionManager?.getSessionId() ?? "unknown-child", cwd: child.cwd ?? "", title, choices: [...choices],
    expiresAt: Date.now() + Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, DEFAULT_TIMEOUT_MS) };
  if (!validRequest(request, binding, id)) return undefined;
  try {
    if (await realpath(binding.directory) !== binding.directory) return undefined;
    const alive = await readJson(join(binding.directory, "alive.json"));
    if (!record(alive) || alive.nonce !== binding.nonce || alive.parentSessionId !== binding.parentSessionId) return undefined;
    await writeJson(requestPath, request);
    if (signal?.aborted) return undefined;
    return await new Promise<string | undefined>(resolve => {
      let finished = false, checking = false;
      const finish = (choice?: string) => {
        if (finished) return;
        finished = true; clearInterval(timer); clearTimeout(deadline); signal?.removeEventListener("abort", abort); resolve(choice);
      };
      const abort = () => finish();
      const check = async () => {
        if (finished || checking) return;
        checking = true;
        try {
          const reply = await readJson(replyPath);
          if (record(reply) && reply.version === 1 && reply.id === id && reply.parentSessionId === binding.parentSessionId && reply.nonce === binding.nonce
            && typeof reply.index === "number" && Number.isInteger(reply.index) && reply.index >= 0 && reply.index < request.choices.length) finish(request.choices[reply.index]);
          else finish();
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") { reportError(error); finish(); }
          else try { await access(join(binding.directory, "alive.json")); } catch { finish(); }
        } finally { checking = false; }
      };
      const timer = setInterval(() => { void check(); }, options.pollIntervalMs ?? 25);
      const deadline = setTimeout(abort, Math.max(0, request.expiresAt - Date.now()));
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      else void check();
    });
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") reportError(error); return undefined; }
  finally {
    try { await Promise.all([removeFile(requestPath), removeFile(replyPath)]); } catch (error) { reportError(error); }
  }
}

/** Use built-in selectors (RPC semantics), preserving child-side validation and grant storage. */
export function bridgeApprovalContext(child: EscalationUI & { cwd?: string }, binding: ApprovalBridgeBinding, options: { timeoutMs?: number; pollIntervalMs?: number } = {}): EscalationUI & { cwd?: string } {
  return { ...child, mode: "rpc", hasUI: true, ui: {
    select: (title, choices, promptOptions) => requestSelection(binding, child, title, choices, { ...options, signal: promptOptions?.signal ?? child.signal })
  } };
}
