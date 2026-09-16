import { createEditTool, createWriteTool, type EditToolInput, type WriteToolInput } from "@earendil-works/pi-coding-agent";
import { MutationBoundary, defaultWritableRoots, inputDigest } from "./filesystem-boundary.js";
import type { ApprovalProvider } from "./types.js";

type MutationInput = { path: string };
type NativeTool<T extends MutationInput> = {
  execute(id: string, params: T, signal: AbortSignal, onUpdate: (result: never) => void, context?: unknown): Promise<unknown>;
  [key: string]: unknown;
};

export type MutationToolOptions = {
  cwd: string;
  writableRoots?: readonly string[] | ((cwd: string, context: unknown) => readonly string[]);
  approvals: ApprovalProvider | ((context: unknown) => ApprovalProvider);
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
      const effectiveCwd = contextCwd(context, options.cwd);
      const writableRoots = typeof options.writableRoots === "function"
        ? options.writableRoots(effectiveCwd, context)
        : options.writableRoots ?? defaultWritableRoots(effectiveCwd);
      const boundary = await MutationBoundary.create(effectiveCwd, writableRoots);
      const target = await boundary.resolve(params.path);
      if (!target.allowed) {
        const provider = typeof options.approvals === "function" ? options.approvals(context) : options.approvals;
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
      return native.execute(id, params, signal, onUpdate, context);
    }
  };
}

export async function createBoundaryAwareWriteTool(options: MutationToolOptions) {
  return boundaryAwareTool("write", createWriteTool(options.cwd) as unknown as NativeTool<WriteToolInput>, options);
}

export async function createBoundaryAwareEditTool(options: MutationToolOptions) {
  return boundaryAwareTool("edit", createEditTool(options.cwd) as unknown as NativeTool<EditToolInput>, options);
}
