import { spawn } from "node:child_process";
import type { BashOperations } from "@earendil-works/pi-coding-agent";
import { STRACE_ARGS, STRACE_BINARY } from "./strace-observer.js";
import type { CommandResult } from "./types.js";

/** Runs bwrap under strace, keeping tracer stderr separate from workload output. */
export async function runTracedSandbox(
  wrapped: string,
  cwd: string,
  options: Parameters<BashOperations["exec"]>[2],
  onTrace: (chunk: Buffer) => void,
  binary = STRACE_BINARY
): Promise<CommandResult> {
  if (options.signal?.aborted) throw new Error("aborted");
  if (options.timeout !== undefined && (!Number.isFinite(options.timeout) || options.timeout <= 0 || options.timeout * 1000 > 2_147_483_647)) {
    throw new Error("Invalid timeout: must be a positive number of seconds within the timer range");
  }
  // strace writes its trace to its own stderr. The tracee redirects stderr to
  // stdout before execing bwrap, so sandboxed processes cannot write trace
  // lines. bwrap's PID namespace also hides the outer tracer's /proc/fd.
  const child = spawn(binary, [...STRACE_ARGS, "/bin/bash", "-c", `exec ${wrapped} 2>&1`], {
    cwd, env: options.env, detached: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  const trace = child.stderr;
  if (!trace) throw new Error("strace telemetry pipe unavailable");
  let timedOut = false;
  const kill = () => {
    if (!child.pid) return;
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  };
  const timeout = options.timeout === undefined ? undefined : setTimeout(() => { timedOut = true; kill(); }, options.timeout * 1000);
  options.signal?.addEventListener("abort", kill, { once: true });
  child.stdout?.on("data", options.onData);
  trace.on("data", onTrace);
  try {
    const exitCode = await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", code => resolve(code ?? 1));
    });
    if (options.signal?.aborted) throw new Error("aborted");
    if (timedOut) throw new Error(`timeout:${options.timeout}`);
    return { exitCode, stdout: "", stderr: "" };
  } finally {
    if (timeout) clearTimeout(timeout);
    options.signal?.removeEventListener("abort", kill);
  }
}
