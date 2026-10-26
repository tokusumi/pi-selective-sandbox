import { createEditTool, createWriteTool, type EditToolInput, type WriteToolInput } from "@earendil-works/pi-coding-agent";
import { dirname } from "node:path";
import { NativeMutationIO } from "./native-mutation-io.js";
import { MutationBoundary, defaultWritableRoots, inputDigest } from "./filesystem-boundary.js";
import type { ApprovalProvider } from "./types.js";
import type { WritePolicy } from "./filesystem-policy.js";

type MutationInput = { path: string };
type NativeTool<T extends MutationInput> = {
  execute(id: string, params: T, signal: AbortSignal, onUpdate: (result: never) => void, context?: unknown): Promise<unknown>;
  [key: string]: unknown;
};

export type MutationToolOptions = {
  cwd: string;
  isEnabled?: (context?: unknown) => boolean | Promise<boolean>;
  writePolicy?: WritePolicy | (() => WritePolicy);
  writableRoots?: readonly string[] | ((cwd: string, context: unknown) => readonly string[]);
  approvals: ApprovalProvider | ((context: unknown, signal?: AbortSignal) => ApprovalProvider);
};

type ToolContext = { cwd?: string };

function contextCwd(context: unknown, fallback: string): string {
  return typeof context === "object" && context !== null && typeof (context as ToolContext).cwd === "string"
    ? (context as ToolContext).cwd!
    : fallback;
}

type PreparedMutation<T extends MutationInput> = {
  native: NativeTool<T>;
  validate(): Promise<void>;
  close(): Promise<void>;
};
type PrepareMutation<T extends MutationInput> = (
  canonical: string, cwd: string, signal: AbortSignal, beforeIO: () => Promise<void>
) => Promise<PreparedMutation<T>>;

/** Authorizes the canonical resource. Production factories additionally bind all
 * native I/O to a prepared cwd/file-handle-bound backend, never the input alias.
 */
export async function boundaryAwareTool<T extends MutationInput>(
  toolName: "write" | "edit", native: NativeTool<T>, options: MutationToolOptions,
  prepare?: PrepareMutation<T>
): Promise<NativeTool<T>> {
  return {
    ...native,
    async execute(id, params, signal, onUpdate, context?: unknown) {
      if (signal?.aborted) throw new Error("File mutation cancelled before execution");
      if (await options.isEnabled?.(context) === false) return native.execute(id, params, signal, onUpdate, context);
      const effectiveCwd = contextCwd(context, options.cwd);
      const writableRoots = typeof options.writableRoots === "function"
        ? options.writableRoots(effectiveCwd, context)
        : options.writableRoots ?? defaultWritableRoots(effectiveCwd);
      const writePolicy = typeof options.writePolicy === "function" ? options.writePolicy() : options.writePolicy;
      const boundary = await MutationBoundary.create(effectiveCwd, writePolicy ?? writableRoots);
      const target = await boundary.resolve(params.path);
      if (target.denied) throw new Error(`Permission denied: ${toolName} targets a configured deny root`);
      let prepared: PreparedMutation<T> | undefined;
      const beforeIO = async () => {
        if (signal?.aborted) throw new Error("File mutation cancelled before execution");
        const current = await boundary.resolve(params.path);
        if (current.denied) throw new Error(`Permission denied: ${toolName} targets a configured deny root`);
        if (current.canonical !== target.canonical) throw new Error("File mutation target changed after preflight");
        await prepared?.validate();
      };
      try {
        // Preparation opens only non-truncating handles, with no target creation
        // or content reads. Hold them across the approval wait, then revalidate.
        prepared = await prepare?.(target.canonical, effectiveCwd, signal, beforeIO);
        await beforeIO();
        if (!target.allowed) {
          const provider = typeof options.approvals === "function" ? options.approvals(context, signal) : options.approvals;
          const decision = await provider.request({
            toolCallId: id,
            toolName,
            inputDigest: inputDigest(params),
            capabilities: [{ kind: "filesystem.write", resource: target.canonical }],
            command: `${toolName} ${target.canonical}`,
            replayWarning: false,
            sessionGrantEligible: true,
            projectGrantEligible: true
          });
          if (decision === "deny") throw new Error(`Permission denied: ${toolName} outside configured writable roots`);
        }
        await beforeIO();
        const input = { ...params, path: target.canonical };
        return await (prepared?.native ?? native).execute(id, input, signal, onUpdate, context);
      } finally {
        await prepared?.close();
      }
    }
  };
}

export async function createBoundaryAwareWriteTool(options: MutationToolOptions) {
  const native = createWriteTool(options.cwd);
  // The unguarded tool is used only when the user explicitly disables boundaries.
  // SAFETY: Pi's WriteToolInput and execute arguments are unchanged; the result is widened to unknown.
  const disabledNative = { ...native, execute: (id, params, signal, onUpdate, context) =>
    (createWriteTool(contextCwd(context, options.cwd)) as unknown as NativeTool<WriteToolInput>).execute(id, params, signal, onUpdate, context)
  } as NativeTool<WriteToolInput>;
  return boundaryAwareTool("write", disabledNative, options, async (canonical, cwd, signal, beforeIO) => {
    const io = await NativeMutationIO.prepare("write", canonical, signal);
    const guarded = createWriteTool(cwd, { operations: {
      async mkdir(path) {
        if (path !== dirname(canonical)) throw new Error("Unexpected native mkdir target");
        await beforeIO();
        await io.mkdir();
      },
      async writeFile(path, content) {
        if (path !== canonical) throw new Error("Unexpected native write target");
        await beforeIO();
        await io.writeFile(content);
      }
    } });
    // SAFETY: This unchanged Pi tool accepts WriteToolInput; only its result is widened to unknown.
    return { native: guarded as unknown as NativeTool<WriteToolInput>, validate: () => io.validate(), close: () => io.close() };
  });
}

export async function createBoundaryAwareEditTool(options: MutationToolOptions) {
  const native = createEditTool(options.cwd);
  // SAFETY: Pi's EditToolInput and execute arguments are unchanged; the result is widened to unknown.
  const disabledNative = { ...native, execute: (id, params, signal, onUpdate, context) =>
    (createEditTool(contextCwd(context, options.cwd)) as unknown as NativeTool<EditToolInput>).execute(id, params, signal, onUpdate, context)
  } as NativeTool<EditToolInput>;
  return boundaryAwareTool("edit", disabledNative, options, async (canonical, cwd, signal, beforeIO) => {
    const io = await NativeMutationIO.prepare("edit", canonical, signal);
    const check = async (path: string) => {
      if (path !== canonical) throw new Error("Unexpected native edit target");
      await beforeIO();
    };
    const guarded = createEditTool(cwd, { operations: {
      async access(path) { await check(path); await io.access(); },
      async readFile(path) { await check(path); return io.readFile(); },
      async writeFile(path, content) { await check(path); await io.writeFile(content); }
    } });
    // SAFETY: This unchanged Pi tool accepts EditToolInput; only its result is widened to unknown.
    return { native: guarded as unknown as NativeTool<EditToolInput>, validate: () => io.validate(), close: () => io.close() };
  });
}
