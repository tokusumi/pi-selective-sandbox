import { createEditTool, createWriteTool, type EditToolInput, type WriteToolInput } from "@earendil-works/pi-coding-agent";
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

/** Wraps Pi's native tool: authorization happens before it can read or mutate. */
export async function boundaryAwareTool<T extends MutationInput>(
  toolName: "write" | "edit", native: NativeTool<T>, options: MutationToolOptions
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
      if (signal?.aborted) throw new Error("File mutation cancelled before execution");
      return native.execute(id, params, signal, onUpdate, context);
    }
  };
}

export async function createBoundaryAwareWriteTool(options: MutationToolOptions) {
  const native = createWriteTool(options.cwd);
  // SAFETY: This is Pi's write tool with its unchanged WriteToolInput and execute arguments; the port only widens its result to unknown.
  return boundaryAwareTool("write", { ...native, execute: (id, params, signal, onUpdate, context) =>
    (createWriteTool(contextCwd(context, options.cwd)) as unknown as NativeTool<WriteToolInput>).execute(id, params, signal, onUpdate, context)
  } as NativeTool<WriteToolInput>, options);
}

export async function createBoundaryAwareEditTool(options: MutationToolOptions) {
  const native = createEditTool(options.cwd);
  // SAFETY: This is Pi's edit tool with its unchanged EditToolInput and execute arguments; the port only widens its result to unknown.
  return boundaryAwareTool("edit", { ...native, execute: (id, params, signal, onUpdate, context) =>
    (createEditTool(contextCwd(context, options.cwd)) as unknown as NativeTool<EditToolInput>).execute(id, params, signal, onUpdate, context)
  } as NativeTool<EditToolInput>, options);
}
