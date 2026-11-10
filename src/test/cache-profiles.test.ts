import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_WRITE_PROFILES, parseConfig } from "../config.js";
import { resolveWritePolicy } from "../filesystem-policy.js";
import { MutationBoundary } from "../filesystem-boundary.js";
import { createBoundaryAwareEditTool, createBoundaryAwareWriteTool } from "../mutation-tools.js";
import { buildSandboxRuntimeConfig } from "../runtime-adapter.js";
import { resolveNetworkDomains } from "../network-policy.js";
import { matchesDomainPatternWithPort } from "@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js";

const profiles = ["npm-cache", "uv-cache", "gh-cache", "go-cache"];
const nonCache = DEFAULT_WRITE_PROFILES.filter(profile => !profiles.includes(profile));
async function fixture(t: { after: (fn: () => Promise<void>) => void }) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "pi-caches-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = join(root, "home"), cwd = join(root, "project");
  await Promise.all([mkdir(home), mkdir(cwd)]);
  return { root, home, cwd };
}
const config = (disabled: string[] = [], extraWritableRoots: string[] = []) => parseConfig({ filesystem: {
  disabledDefaultProfiles: [...nonCache, ...disabled], extraWritableRoots
} });
const defaults = (home: string, platform: "darwin" | "linux") => [
  join(home, ".npm", "_cacache"), join(home, ".cache", "uv"), join(home, ".cache", "gh"),
  join(home, ...(platform === "darwin" ? ["Library", "Caches"] : [".cache"]), "go-build"),
  join(home, "go", "pkg", "mod"), join(home, "go", "pkg", "sumdb")
];

for (const platform of ["darwin", "linux"] as const) {
  test(`${platform} default cache roots are narrow and shared by bash and native boundaries`, async t => {
    const { cwd, home } = await fixture(t);
    const policy = await resolveWritePolicy({ cwd, home, platform, env: {}, config: config() });
    assert.deepEqual(policy, { allow: defaults(home, platform), deny: [join(home, ".npm", "_logs"), join(home, ".claude", "debug")] });
    const runtime = buildSandboxRuntimeConfig({ cwd, writePolicy: policy });
    assert.deepEqual(runtime.filesystem.allowWrite, policy.allow);
    assert.deepEqual(runtime.filesystem.denyWrite, policy.deny);
    const boundary = await MutationBoundary.create(cwd, policy);
    for (const cache of policy.allow) {
      assert.equal((await boundary.resolve(join(cache, "tmp", "random-uuid"))).allowed, true);
    }
    for (const excluded of [home, join(home, "Library", "Caches"), join(home, ".npm", "_npx"), join(home, ".npmrc"),
      join(home, ".config", "gh", "hosts.yml"), join(home, "go", "bin", "tool"), join(home, "go", "src"),
      join(home, ".local", "share", "uv", "tools"), join(home, ".local", "bin", "uv")]) {
      assert.equal((await boundary.resolve(excluded)).allowed, false, excluded);
    }
  });
}

test("four independently disabled profiles remove only their cache roots; explicit config may restore them", async t => {
  const { cwd, home } = await fixture(t);
  const roots = defaults(home, "darwin");
  for (const [index, profile] of profiles.entries()) {
    const policy = await resolveWritePolicy({ cwd, home, platform: "darwin", env: {}, config: config([profile]) });
    assert.deepEqual(policy.allow, roots.filter((_, i) => index === 3 ? i < 3 : i !== index));
  }
  const policy = await resolveWritePolicy({ cwd, home, env: {}, config: config(profiles, [roots[0]]) });
  assert.deepEqual(policy.allow, [roots[0]]);
});

test("startup environment precedence and Go first GOPATH/sumdb are respected", async t => {
  const { root, cwd, home } = await fixture(t);
  const xdg = join(root, "xdg"), first = join(root, "go-first"), second = join(root, "go-second");
  const env = { npm_config_cache: join(root, "npm-lower"), NPM_CONFIG_CACHE: join(root, "npm-upper"),
    XDG_CACHE_HOME: xdg, UV_CACHE_DIR: "relative-uv", GOCACHE: join(root, "build"),
    GOMODCACHE: join(root, "modules"), GOPATH: `${first}:${second}`, GH_CONFIG_DIR: join(root, "gh-config") };
  const policy = await resolveWritePolicy({ cwd, home, env, platform: "linux", config: config() });
  assert.deepEqual(policy.allow, [join(root, "npm-lower", "_cacache"), join(cwd, "relative-uv"), join(xdg, "gh"),
    env.GOCACHE, env.GOMODCACHE, join(first, "pkg", "sumdb")]);
  const withoutOverrides = await resolveWritePolicy({ cwd, home, env: { NPM_CONFIG_CACHE: env.NPM_CONFIG_CACHE, XDG_CACHE_HOME: xdg, GOPATH: env.GOPATH }, platform: "linux", config: config() });
  assert.deepEqual(withoutOverrides.allow, [join(root, "npm-upper", "_cacache"), join(xdg, "uv"), join(xdg, "gh"),
    join(xdg, "go-build"), join(first, "pkg", "mod"), join(first, "pkg", "sumdb")]);
  const mac = await resolveWritePolicy({ cwd, home, env: { XDG_CACHE_HOME: xdg }, platform: "darwin", config: config() });
  assert.ok(mac.allow.includes(join(home, "Library", "Caches", "go-build")));
  assert.ok(!mac.allow.includes(join(xdg, "go-build")));
});

test("empty overrides use defaults; invalid Go paths/off never become cwd-relative allowances", async t => {
  const { cwd, home } = await fixture(t);
  assert.deepEqual((await resolveWritePolicy({ cwd, home, platform: "linux", env: { UV_CACHE_DIR: "", GOCACHE: "", GOPATH: "", GOMODCACHE: "" }, config: config() })).allow, defaults(home, "linux"));
  for (const GOCACHE of ["off", "relative"]) {
    const policy = await resolveWritePolicy({ cwd, home, env: { GOCACHE, GOMODCACHE: "relative", GOPATH: ":/other" }, config: config() });
    assert.deepEqual(policy.allow, defaults(home, "darwin").slice(0, 3));
  }
});

test("npm expands tilde but uv/gh environment paths retain literal tilde components", async t => {
  const { cwd, home } = await fixture(t);
  const policy = await resolveWritePolicy({ cwd, home, env: { npm_config_cache: "~/npm-cache", UV_CACHE_DIR: "~/uv-cache", XDG_CACHE_HOME: "~/xdg" },
    config: config(["go-cache"]) });
  assert.deepEqual(policy.allow, [join(home, "npm-cache", "_cacache"), join(cwd, "~", "uv-cache"), join(cwd, "~", "xdg", "gh")]);
});

test("relative XDG behavior follows each tool instead of granting the cache base", async t => {
  const { cwd, home } = await fixture(t);
  const policy = await resolveWritePolicy({ cwd, home, platform: "linux", env: { XDG_CACHE_HOME: "relative-cache" }, config: config() });
  assert.deepEqual(policy.allow, [join(home, ".npm", "_cacache"), join(home, ".cache", "uv"), join(cwd, "relative-cache", "gh"),
    join(home, "go", "pkg", "mod"), join(home, "go", "pkg", "sumdb")]);
  assert.ok(!policy.allow.includes(join(cwd, "relative-cache")));
});

test("safe canonical cache aliases resolve nonexistent descendants and deduplicate explicit roots", async t => {
  const { root, cwd, home } = await fixture(t);
  const actual = join(root, "storage"); await mkdir(actual);
  const alias = join(root, "alias"); await symlink(actual, alias);
  const policy = await resolveWritePolicy({ cwd, home, env: { UV_CACHE_DIR: join(alias, "future") }, config: config(["npm-cache", "gh-cache", "go-cache"], [join(actual, "future")]) });
  assert.deepEqual(policy.allow, [join(actual, "future")]);
  const boundary = await MutationBoundary.create(cwd, policy);
  assert.equal((await boundary.resolve(join(alias, "future", "tmp", "uuid"))).allowed, true);
  await symlink(home, join(actual, "escape"));
  assert.equal((await boundary.resolve(join(actual, "escape", ".npmrc"))).allowed, false);
});

test("broad and protected env/symlink cache targets are omitted without broader default fallback", async t => {
  const { root, cwd, home } = await fixture(t);
  for (const target of ["/", home, join(home, "Library", "Caches"), join(home, ".cache"), join(home, ".config"),
    join(home, ".aws"), join(home, ".pi", "agent"), join(home, ".codex"), join(home, ".docker"),
    join(home, ".cargo", "bin"), join(home, "go", "bin"), join(home, ".local", "share", "uv", "tools"), "/usr/local/bin"]) {
    const policy = await resolveWritePolicy({ cwd, home, env: { UV_CACHE_DIR: target, GOCACHE: target, GOMODCACHE: target }, config: config(["npm-cache", "gh-cache"]) });
    assert.deepEqual(policy.allow, [join(home, "go", "pkg", "sumdb")], target);
  }
  const alias = join(root, "alias"); await symlink(home, alias);
  const policy = await resolveWritePolicy({ cwd, home, env: { UV_CACHE_DIR: alias }, config: config(["npm-cache", "gh-cache", "go-cache"]) });
  assert.deepEqual(policy.allow, []);
  const customTool = join(root, "custom-tool");
  for (const name of ["UV_TOOL_DIR", "UV_TOOL_BIN_DIR", "UV_PYTHON_INSTALL_DIR", "UV_INSTALL_DIR", "GOBIN", "GOROOT", "GH_CONFIG_DIR", "PI_CODING_AGENT_DIR", "NPM_CONFIG_PREFIX"]) {
    const custom = await resolveWritePolicy({ cwd, home, env: { [name]: customTool, UV_CACHE_DIR: customTool }, config: config(["npm-cache", "gh-cache", "go-cache"]) });
    assert.deepEqual(custom.allow, [], name);
  }
  const ghConfig = await resolveWritePolicy({ cwd, home, env: { XDG_CACHE_HOME: root, GH_CONFIG_DIR: join(root, "gh") }, config: config(["npm-cache", "uv-cache", "go-cache"]) });
  assert.deepEqual(ghConfig.allow, []);
  const npxAlias = join(root, "npx-alias");
  await mkdir(join(home, ".npm", "_npx"), { recursive: true });
  await symlink(join(home, ".npm", "_npx"), npxAlias);
  const npx = await resolveWritePolicy({ cwd, home, env: { UV_CACHE_DIR: npxAlias }, config: config(["npm-cache", "gh-cache", "go-cache"]) });
  assert.deepEqual(npx.allow, []);
});

test("a protected config symlink into a cache prevents automatically allowing its enclosing root", async t => {
  const { root, cwd, home } = await fixture(t);
  const cache = join(root, "cache"); await mkdir(cache);
  await mkdir(join(cache, "configuration"));
  await symlink(join(cache, "configuration"), join(home, ".config"));
  const policy = await resolveWritePolicy({ cwd, home, env: { UV_CACHE_DIR: cache }, config: config(["npm-cache", "gh-cache", "go-cache"]) });
  assert.deepEqual(policy.allow, []);
});

test("canonical deny wins even when an enabled cache root or explicit addition covers it", async t => {
  const { root, cwd, home } = await fixture(t);
  const cargo = join(root, "cargo"); await mkdir(cargo);
  const alias = join(root, "alias"); await symlink(cargo, alias);
  const policy = await resolveWritePolicy({ cwd, home, env: { CARGO_HOME: cargo, UV_CACHE_DIR: alias },
    config: parseConfig({ filesystem: { disabledDefaultProfiles: ["workspace", "tmp"], extraWritableRoots: [join(alias, "credentials.toml")] } }) });
  const boundary = await MutationBoundary.create(cwd, policy);
  assert.equal((await boundary.resolve(join(alias, "credentials.toml"))).denied, true);
  assert.deepEqual(buildSandboxRuntimeConfig({ cwd, writePolicy: policy }).filesystem.denyWrite, policy.deny);
});

test("native write/edit uses all four cache profiles without approval, disabled roots still ask", async t => {
  const { cwd, home } = await fixture(t);
  const policy = await resolveWritePolicy({ cwd, home, platform: "darwin", env: {}, config: config() });
  let approvals = 0;
  const provider = { request: async () => { approvals++; return "deny" as const; } };
  const options = { cwd, writePolicy: policy, approvals: provider };
  const write = await createBoundaryAwareWriteTool(options), edit = await createBoundaryAwareEditTool(options);
  const signal = new AbortController().signal;
  for (const [i, cache] of policy.allow.entries()) {
    const path = join(cache, "tmp", `random-${i}`);
    await write.execute(`cache-write-${i}`, { path, content: "before" }, signal, () => {});
    await edit.execute(`cache-edit-${i}`, { path, edits: [{ oldText: "before", newText: "after" }] }, signal, () => {});
    assert.equal(await readFile(path, "utf8"), "after");
  }
  assert.equal(approvals, 0);
  const disabled = await resolveWritePolicy({ cwd, home, env: {}, config: config(profiles) });
  const blocked = await createBoundaryAwareWriteTool({ cwd, writePolicy: disabled, approvals: provider });
  await assert.rejects(blocked.execute("disabled-cache", { path: join(policy.allow[0], "new-file"), content: "no" }, signal, () => {}));
  assert.equal(approvals, 1);
});

test("Go filesystem profile does not grant network: public endpoints need explicit HTTPS config", () => {
  const baseline = resolveNetworkDomains();
  for (const host of ["proxy.golang.org", "sum.golang.org"]) {
    assert.equal(baseline.some(pattern => matchesDomainPatternWithPort(host, 443, pattern)), false);
  }
  const domains = resolveNetworkDomains(parseConfig({ network: { extraAllowedDomains: ["proxy.golang.org:443", "sum.golang.org:443"] } }).network);
  for (const host of ["proxy.golang.org", "sum.golang.org"]) {
    assert.equal(domains.some(pattern => matchesDomainPatternWithPort(host, 443, pattern)), true);
    assert.equal(domains.some(pattern => matchesDomainPatternWithPort(host, 80, pattern)), false);
  }
  assert.equal(domains.some(pattern => matchesDomainPatternWithPort("private-registry.s3.amazonaws.com", 443, pattern)), false);
});
