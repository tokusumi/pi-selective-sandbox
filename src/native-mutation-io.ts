import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";

/** Trusted package script, interpreted by Pi's own Node executable. No compiler,
 * binary download, environment loader, or temporary executable cache is used.
 */
function helperScript(): string {
  if (process.platform !== "darwin" && process.platform !== "linux") {
    throw new Error("Safe native file mutations are unavailable on this platform");
  }
  return fileURLToPath(new URL("../scripts/native-mutation-helper.mjs", import.meta.url));
}

/** One isolated child pins the nearest existing parent as its cwd and holds a
 * non-truncating file handle. Its protocol accepts no path after preparation.
 * The parent's cwd is never changed; content is not read before authorization.
 */
export class NativeMutationIO {
  private buffer: Buffer = Buffer.alloc(0);
  private readonly output: AsyncIterator<Buffer>;
  private readonly exited: Promise<void>;
  private failure: Error | undefined;
  private closed = false;
  private readonly abort = () => { this.child.kill(); };

  private constructor(private readonly child: ChildProcessWithoutNullStreams, private readonly signal?: AbortSignal) {
    this.output = child.stdout[Symbol.asyncIterator]() as AsyncIterator<Buffer>;
    child.on("error", error => { this.failure = error; });
    child.stdin.on("error", error => { this.failure = error; });
    // The helper only emits fixed diagnostics on stdout; drain stderr regardless.
    child.stderr.resume();
    this.exited = new Promise(resolve => child.once("close", () => resolve()));
    signal?.addEventListener("abort", this.abort, { once: true });
    if (signal?.aborted) this.abort();
  }

  static async prepare(kind: "write" | "edit", canonical: string, signal?: AbortSignal): Promise<NativeMutationIO> {
    if (signal?.aborted) throw new Error("File mutation cancelled before preparation");
    const helper = helperScript();
    if (signal?.aborted) throw new Error("File mutation cancelled before preparation");
    const child = spawn(process.execPath, [helper, kind, canonical], { cwd: "/", stdio: "pipe", env: { PATH: "/usr/bin:/bin" } });
    const io = new NativeMutationIO(child, signal);
    try {
      await io.response();
      return io;
    } catch (error) {
      await io.close();
      if (io.failure) {
        throw new Error("Safe native file backend unavailable; reinstall the package to restore scripts/native-mutation-helper.mjs. Refusing path-only I/O", { cause: io.failure });
      }
      throw error;
    }
  }

  private async more(): Promise<void> {
    const chunk = await this.output.next();
    if (chunk.done) throw new Error("Safe native file backend unavailable or exited unexpectedly; reinstall the package to restore scripts/native-mutation-helper.mjs. Refusing path-only I/O", { cause: this.failure });
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk.value]) : chunk.value;
  }

  private async response(): Promise<Buffer> {
    let newline: number;
    while ((newline = this.buffer.indexOf(10)) < 0) {
      if (this.buffer.length > 4096) throw new Error("Invalid native file backend response");
      await this.more();
    }
    const header = this.buffer.subarray(0, newline).toString("utf8");
    this.buffer = this.buffer.subarray(newline + 1);
    if (header.startsWith("ERR ")) throw new Error(`Safe native file mutation refused: ${header.slice(4)}`);
    const match = /^OK (\d+)$/.exec(header);
    const length = match ? Number(match[1]) : NaN;
    if (!Number.isSafeInteger(length) || length < 0) throw new Error("Invalid native file backend response");
    const result = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      if (this.buffer.length === 0) await this.more();
      const take = Math.min(length - offset, this.buffer.length);
      this.buffer.copy(result, offset, 0, take);
      this.buffer = this.buffer.subarray(take);
      offset += take;
    }
    return result;
  }

  private async send(command: string, content?: Buffer): Promise<Buffer> {
    if (this.closed || this.signal?.aborted) throw new Error("File mutation cancelled or closed");
    await new Promise<void>((resolve, reject) => this.child.stdin.write(command, error => error ? reject(error) : resolve()));
    if (content?.length) {
      await new Promise<void>((resolve, reject) => this.child.stdin.write(content, error => error ? reject(error) : resolve()));
    }
    return this.response();
  }

  async validate(): Promise<void> { await this.send("V\n"); }
  async mkdir(): Promise<void> { await this.send("M\n"); }
  async access(): Promise<void> { await this.send("A\n"); }
  async readFile(): Promise<Buffer> { return this.send("R\n"); }
  async writeFile(content: string): Promise<void> {
    const data = Buffer.from(content, "utf8");
    await this.send(`W ${data.length}\n`, data);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.signal?.removeEventListener("abort", this.abort);
    // Kill also handles callers throwing between protocol messages. No descriptors
    // or approval-waiting children are retained for the next invocation.
    this.child.kill();
    await this.exited;
  }
}
