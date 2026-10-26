import assert from "node:assert/strict";
import test from "node:test";
import { execFile, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { join } from "node:path";
import { AnthropicSandboxRuntime } from "../runtime-adapter.js";
import { SelectiveSandboxExecutor } from "../executor.js";
import { CapabilityPolicy } from "../policy.js";
import type { CommandResult } from "../types.js";

const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
// Public fixture values only. Never call a real user's credential get/store/erase.
const credential = "protocol=http\nhost=fixture.invalid\nusername=fixture-user\npassword=fixture-password-not-a-secret\n\n";

function run(file: string, args: string[], cwd: string, env: NodeJS.ProcessEnv, input = ""): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { cwd, env, encoding: "utf8", timeout: 15000 }, (error, stdout, stderr) => {
      if (error && typeof error.code !== "number") {
        // execFile errors can include the wrapped command and proxy token.
        reject(new Error("Fixture subprocess did not return an exit code; error details withheld."));
        return;
      }
      resolve({ exitCode: error && typeof error.code === "number" ? error.code : 0, stdout, stderr });
    });
    child.stdin!.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "EPIPE") reject(error); });
    child.stdin!.end(input);
  });
}

async function fixture(t: test.TestContext) {
  // Outside /tmp/claude, which the SDK implicitly allows. A nested client root
  // makes the fixture HOME readable but not writable by the sandboxed Git.
  const root = await realpath(await mkdtemp(join(process.cwd(), ".git-credentials-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = join(root, "home"), cwd = join(root, "client");
  await Promise.all([mkdir(home), mkdir(cwd)]);
  // Deliberately do not inherit Git config/trace/askpass, HTTP headers, proxies,
  // or real credential-manager environment variables from the operator.
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config"),
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "/usr/bin/false", SSH_ASKPASS: "/usr/bin/false", LC_ALL: "C" };
  const git = async (...args: string[]) => {
    const result = await run("git", args, cwd, env);
    assert.equal(result.exitCode, 0, result.stderr);
    return result.stdout.trim();
  };
  return { root, home, cwd, env, git };
}

// Authenticated smart HTTP backed solely by a disposable bare repository.
// Nothing is forwarded to a real host and authorization values are never logged.
async function serveGit(root: string, env: NodeJS.ProcessEnv) {
  const failures: string[] = [];
  let authenticatedRequests = 0;
  const authorization = `Basic ${Buffer.from("fixture-user:fixture-password-not-a-secret").toString("base64")}`;
  const server = http.createServer((request, response) => {
    if (request.headers.authorization !== authorization) {
      request.resume();
      response.writeHead(401, { "WWW-Authenticate": 'Basic realm="isolated-git-fixture"' });
      response.end("Authentication required\n");
      return;
    }
    authenticatedRequests++;
    const url = new URL(request.url!, "http://fixture.invalid");
    const backend = spawn("git", ["http-backend"], { cwd: root, env: { ...env,
      GIT_PROJECT_ROOT: root, GIT_HTTP_EXPORT_ALL: "1", PATH_INFO: url.pathname,
      QUERY_STRING: url.search.slice(1), REQUEST_METHOD: request.method!, REMOTE_USER: "fixture-user",
      CONTENT_TYPE: request.headers["content-type"] ?? "", CONTENT_LENGTH: request.headers["content-length"] ?? ""
    } });
    const chunks: Buffer[] = [];
    backend.stdout.on("data", chunk => chunks.push(chunk));
    // Do not publish raw CGI diagnostics (even though this server has only dummy credentials).
    backend.stderr.resume();
    backend.stdin.on("error", () => { failures.push("CGI input failed"); });
    backend.on("error", () => { failures.push("CGI spawn failed"); });
    backend.on("close", code => {
      if (code !== 0) { failures.push("CGI exited unsuccessfully"); response.writeHead(500); response.end(); return; }
      const output = Buffer.concat(chunks), separator = output.indexOf("\r\n\r\n");
      if (separator < 0) { failures.push("CGI headers missing"); response.writeHead(500); response.end(); return; }
      const headers: Record<string, string> = {};
      let status = 200;
      for (const line of output.subarray(0, separator).toString().split("\r\n")) {
        const colon = line.indexOf(":");
        const key = line.slice(0, colon).toLowerCase(), value = line.slice(colon + 1).trim();
        if (key === "status") status = Number.parseInt(value, 10);
        else headers[key] = value;
      }
      response.writeHead(status, headers);
      response.end(output.subarray(separator + 4));
    });
    request.pipe(backend.stdin);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}/remote.git`, port, failures,
    authenticatedRequests: () => authenticatedRequests,
    close: () => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}

test("macOS automatically suppresses proxy credential storage while preserving origin helpers and authenticated fetch/push", { skip: process.platform !== "darwin" }, async t => {
  const { root, home, cwd, env, git } = await fixture(t);
  await git("init", "--bare", "--template=", "--initial-branch=main", join(root, "remote.git"));
  await git("init", "--template=", "--initial-branch=main", "--separate-git-dir", join(cwd, "metadata"));
  await git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "fixture");
  await git("push", join(root, "remote.git"), "HEAD:refs/heads/main");
  const server = await serveGit(root, env);
  t.after(() => server.close());
  await git("remote", "add", "origin", server.url);
  const originHost = new URL(server.url).host;
  assert.equal((await run("git", ["credential-store", "store"], cwd, env, credential.replace("fixture.invalid", originHost))).exitCode, 0);
  const storage = join(home, ".git-credentials"), before = await readFile(storage);
  const helperPath = join(cwd, "credential-observer.cjs"), eventsPath = join(cwd, "events.jsonl");
  await writeFile(helperPath, `
    const fs = require('node:fs');
    const { spawnSync } = require('node:child_process');
    const input = fs.readFileSync(0, 'utf8');
    const host = input.split('\\n').find(line => line.startsWith('host='))?.slice(5);
    const proxy = new URL(process.env.http_proxy || process.env.HTTP_PROXY);
    const destination = host === ${JSON.stringify(originHost)} ? 'origin' : host === proxy.host ? 'proxy' : 'other';
    const action = ['get', 'store', 'erase'].includes(process.argv[2]) ? process.argv[2] : 'other';
    const event = { action, destination, lockDenied: false };
    if (action === 'get' && destination === 'origin') {
      const result = spawnSync('git', ['credential-store', 'get'], { input, encoding: 'utf8' });
      if (result.status === 0) process.stdout.write(result.stdout); // Dummy fixture credentials go only to Git.
      else process.exitCode = 1;
    }
    if (action === 'store' && destination === 'proxy') {
      const result = spawnSync('git', ['credential-store', 'store'], { input, encoding: 'utf8' });
      event.lockDenied = result.status !== 0 && /unable to get credential storage lock in 1000 ms: Operation not permitted/.test(result.stderr || '');
      // Never forward raw child output, proxy credentials, or the input payload.
      console.error(event.lockDenied ? 'fixture-proxy-store-lock-denied' : 'fixture-proxy-store-unexpected');
      process.exitCode = result.status ?? 1;
    }
    // Origin store/erase are deliberately inert; no real helper or Keychain is used.
    fs.appendFileSync(${JSON.stringify(eventsPath)}, JSON.stringify(event) + '\\n');
  `);
  const runtime = await AnthropicSandboxRuntime.initialize({ cwd, writePolicy: { allow: [cwd], deny: [home] }, allowedDomains: [`127.0.0.1:${server.port}`], allowLocalBinding: false });
  t.after(() => runtime.dispose());
  const executor = new SelectiveSandboxExecutor({ runtime, cwd, policy: new CapabilityPolicy([]),
    runner: { runSandbox: wrapped => run("/bin/bash", ["-c", wrapped], cwd, env),
      runHost: async () => { throw new Error("Proxy credential tests must not replay on host"); } },
    approvals: { request: async () => { throw new Error("Proxy credential tests must not widen the sandbox"); } }
  });
  const helper = `!${quote(process.execPath)} ${quote(helperPath)}`;
  await git("config", "credential.helper", helper); // Only the disposable repository's config.
  const gitCommand = ["git", "-c", "http.proxyAuthMethod=basic"].map(quote).join(" ");
  for (let index = 0; index < 2; index++) {
    await writeFile(eventsPath, "");
    const prefix = "NO_PROXY= no_proxy= " + gitCommand; // Force actual use of the authenticated runtime proxy.
    const fetch = await executor.execute(`${prefix} fetch origin main`, `proxy-credential-fetch-${index}`);
    assert.equal(fetch.exitCode, 0, "Proxied authenticated fetch must succeed; raw diagnostics withheld");
    assert.equal(fetch.disposition, "sandbox");
    assert.equal(await git("rev-parse", "refs/remotes/origin/main"), await git("--git-dir", join(root, "remote.git"), "rev-parse", "main"));
    await git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", `proxy-fixture-${index}`);
    const push = await executor.execute(`${prefix} push origin HEAD:refs/heads/proxy-fixture-${index}`, `proxy-credential-push-${index}`);
    assert.equal(push.exitCode, 0, "Proxied authenticated push must succeed; raw diagnostics withheld");
    assert.equal(push.disposition, "sandbox");
    assert.equal(await git("rev-parse", "HEAD"), await git("--git-dir", join(root, "remote.git"), "rev-parse", `refs/heads/proxy-fixture-${index}`));
    const events = (await readFile(eventsPath, "utf8")).trim().split("\n").filter(Boolean).map(line => JSON.parse(line)) as { action: string; destination: string; lockDenied: boolean }[];
    assert.ok(events.some(event => event.action === "get" && event.destination === "origin"), "Origin credential retrieval must be preserved");
    assert.ok(events.some(event => event.action === "store" && event.destination === "origin"), "Origin storage must not be suppressed");
    assert.ok(!events.some(event => event.destination === "proxy"), "The runtime must not invoke helpers for its proxy credentials");
    for (const result of [fetch, push]) assert.doesNotMatch(result.stderr, /fixture-proxy-store/);
    assert.deepEqual(await readFile(storage), before);
    assert.deepEqual(await readdir(home), [".git-credentials"]);
  }
  assert.ok(server.authenticatedRequests() >= 4);
  assert.deepEqual(server.failures, []);
  t.diagnostic("The runtime automatically suppresses helpers only for its proxy; origin get/store and authenticated fetch/push remain successful across fresh attempts. No proxy credentials were persisted or logged.");
});
