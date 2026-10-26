// Per-invocation Node backend. Only this child changes cwd: the kernel-held
// working directory supplies relative directory operations without openat/FFI.
// Never use this module in-process in Pi, or run concurrent cwd-changing work.
import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { posix } from "node:path";

const metadata = { bigint: true };
const parents = [];
let parts, file, fileIdentity, kind;

function changed() { throw new Error("File mutation target changed"); }
function same(a, b) { return a.dev === b.dev && a.ino === b.ino && (a.mode & 0o170000n) === (b.mode & 0o170000n); }
function regular(stat) {
  if (!stat.isFile() || stat.nlink !== 1n) throw new Error("File mutation requires a regular file with one link");
}
async function inspect(path) {
  try { return await lstat(path, metadata); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

// lstat observes a single component relative to the already pinned cwd. chdir
// may race with a replacement, so accept the resulting cwd only if its identity
// equals that observation. No content I/O occurs while traversing directories.
async function enter(name, expected) {
  if (!expected.isDirectory() || expected.isSymbolicLink()) changed();
  process.chdir(name);
  const actual = await lstat(".", metadata);
  if (!same(actual, expected)) changed();
  parents.push({ path: posix.join(parents.at(-1).path, name), identity: actual });
}

async function prepare(path) {
  if ((kind !== "write" && kind !== "edit") || !path?.startsWith("/") || path.includes("\0") || posix.normalize(path) !== path) {
    throw new Error("Expected mutation kind and canonical absolute path");
  }
  parts = path.slice(1).split("/");
  if (!parts.length || parts.length > 1024 || parts.some(part => !part || part === "." || part === "..")) {
    throw new Error("Invalid canonical mutation path");
  }
  // The parent spawns this child at /; do not trust a caller-controlled cwd.
  process.chdir("/");
  parents.push({ path: "/", identity: await lstat(".", metadata) });
  for (const name of parts.slice(0, -1)) {
    const expected = await inspect(name);
    if (!expected) break;
    await enter(name, expected);
  }
  if (parents.length === parts.length) {
    const expected = await inspect(parts.at(-1));
    if (expected) {
      regular(expected);
      file = await open(parts.at(-1), (kind === "edit" ? constants.O_RDWR : constants.O_WRONLY) | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      fileIdentity = await file.stat(metadata);
      regular(fileIdentity);
      if (!same(fileIdentity, expected)) changed();
    }
  }
  await validate();
}

async function validate() {
  // Namespace checks detect observed ancestor/entry changes. They do not bind
  // I/O: relative cwd operations and the held file handle provide that binding.
  for (const parent of parents) {
    const current = await inspect(parent.path);
    if (!current || !same(current, parent.identity)) changed();
  }
  if (!same(await lstat(".", metadata), parents.at(-1).identity)) changed();
  if (parents.length < parts.length) {
    if (await inspect(parts[parents.length - 1])) changed();
  } else {
    const current = await inspect(parts.at(-1));
    if (!file) {
      if (current) changed();
    } else {
      if (!current || !same(current, fileIdentity)) changed();
      regular(await file.stat(metadata));
    }
  }
}

async function makeParents() {
  await validate();
  while (parents.length < parts.length) {
    const name = parts[parents.length - 1];
    await mkdir(name);
    const expected = await inspect(name);
    if (!expected) changed();
    await enter(name, expected);
    await validate();
  }
}

async function readContent() {
  await validate();
  if (!file) throw new Error("File does not exist");
  const chunks = [];
  let position = 0;
  for (;;) {
    const chunk = Buffer.allocUnsafe(64 * 1024);
    const { bytesRead } = await file.read(chunk, 0, chunk.length, position);
    if (!bytesRead) return Buffer.concat(chunks, position);
    chunks.push(chunk.subarray(0, bytesRead));
    position += bytesRead;
  }
}

async function writeContent(content) {
  await validate();
  if (parents.length !== parts.length) throw new Error("Parent directory does not exist");
  if (!file) {
    file = await open(parts.at(-1), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o666);
    fileIdentity = await file.stat(metadata);
    regular(fileIdentity);
  }
  await file.truncate(0);
  let offset = 0;
  while (offset < content.length) {
    const { bytesWritten } = await file.write(content, offset, content.length - offset, offset);
    if (!bytesWritten) throw new Error("Incomplete file write");
    offset += bytesWritten;
  }
}

class Input {
  source = process.stdin[Symbol.asyncIterator]();
  buffer = Buffer.alloc(0);
  async more() {
    const chunk = await this.source.next();
    if (chunk.done) return false;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk.value]) : chunk.value;
    return true;
  }
  async line() {
    for (;;) {
      const end = this.buffer.indexOf(10);
      if (end >= 0) {
        if (end > 128) throw new Error("Invalid native file backend command");
        const line = this.buffer.subarray(0, end).toString("utf8");
        this.buffer = this.buffer.subarray(end + 1);
        return line;
      }
      if (this.buffer.length > 128) throw new Error("Invalid native file backend command");
      if (!await this.more()) {
        if (this.buffer.length) throw new Error("Incomplete backend command");
        return undefined;
      }
    }
  }
  async bytes(length) {
    const content = Buffer.allocUnsafe(length);
    let offset = 0;
    while (offset < length) {
      if (!this.buffer.length && !await this.more()) throw new Error("Incomplete write request");
      const take = Math.min(length - offset, this.buffer.length);
      this.buffer.copy(content, offset, 0, take);
      this.buffer = this.buffer.subarray(take);
      offset += take;
    }
    return content;
  }
}

const output = data => new Promise((resolve, reject) => process.stdout.write(data, error => error ? reject(error) : resolve()));
async function respond(content = Buffer.alloc(0)) {
  await output(`OK ${content.length}\n`);
  if (content.length) await output(content);
}

try {
  if (process.argv.length !== 4) throw new Error("Invalid helper invocation");
  kind = process.argv[2];
  await prepare(process.argv[3]);
  await respond();
  const input = new Input();
  for (let command; (command = await input.line()) !== undefined;) {
    if (command === "Q") break;
    if (command === "V") await validate();
    else if (command === "M") await makeParents();
    else if (command === "A") { await validate(); if (!file) throw new Error("File does not exist"); }
    else if (command === "R") { await respond(await readContent()); continue; }
    else if (/^W \d+$/.test(command)) {
      const length = Number(command.slice(2));
      if (!Number.isSafeInteger(length) || length < 0) throw new Error("Invalid write size");
      await writeContent(await input.bytes(length));
    } else throw new Error("Unknown helper command");
    await respond();
  }
} catch (error) {
  const reason = String(error.message ?? error).replace(/[\r\n]/g, " ").slice(0, 2048);
  try { await output(`ERR ${reason}\n`); } catch { /* Caller already closed. */ }
  process.exitCode = 1;
} finally {
  await file?.close();
  process.stdin.destroy();
}
