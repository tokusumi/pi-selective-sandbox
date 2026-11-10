import { homedir } from "node:os";
import { realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { SelectiveSandboxConfig } from "./config.js";

export type WritePolicy = { allow: readonly string[]; deny: readonly string[] };

export function expandPath(input: string, cwd: string, home = homedir()): string {
  if (input === "~") return home;
  if (input.startsWith("~/")) return join(home, input.slice(2));
  return isAbsolute(input) ? input : resolve(cwd, input);
}

function unique(paths: readonly string[]): string[] { return [...new Set(paths)]; }

/** Canonicalizes even a not-yet-created target through its nearest existing ancestor. */
export async function canonicalPath(path: string): Promise<string> {
  const suffix: string[] = [];
  let candidate = path;
  for (;;) {
    try { return suffix.length === 0 ? await realpath(candidate) : join(await realpath(candidate), ...suffix.reverse()); }
    catch {
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`Cannot resolve path: ${path}`);
      suffix.push(candidate.slice(parent.length + (parent.endsWith("/") ? 0 : 1)));
      candidate = parent;
    }
  }
}

function contains(root: string, target: string): boolean {
  const path = relative(root, target);
  return path === "" || (path !== ".." && !path.startsWith("../") && !isAbsolute(path));
}

type PolicyOptions = { cwd: string; config: SelectiveSandboxConfig; env: NodeJS.ProcessEnv; home?: string; platform?: NodeJS.Platform };

/** No tool execution or config-file reads: only the trusted startup environment. */
async function cacheWriteRoots(options: PolicyOptions, home: string): Promise<string[]> {
  const { env, cwd } = options;
  const platform = options.platform ?? process.platform;
  // The supported filesystem sandboxes are macOS and Linux, not Windows.
  if (platform !== "darwin" && platform !== "linux") return [];
  const disabled = new Set(options.config.filesystem.disabledDefaultProfiles);
  const path = (value: string) => resolve(cwd, value);
  // npm parses its cache setting as a path (including ~/ expansion).
  const npmCache = expandPath(env.npm_config_cache || env.NPM_CONFIG_CACHE || join(home, ".npm"), cwd, home);
  const xdgCache = env.XDG_CACHE_HOME || join(home, ".cache");
  const xdgData = env.XDG_DATA_HOME || join(home, ".local", "share");
  const xdgConfig = env.XDG_CONFIG_HOME || join(home, ".config");
  // Go uses only the first GOPATH element for modcache and sumdb tree heads.
  const goPaths = (env.GOPATH || join(home, "go")).split(":");
  const goPath = goPaths[0] && isAbsolute(goPaths[0]) ? goPaths[0] : undefined;
  const candidates: string[] = [];
  if (!disabled.has("npm-cache")) {
    candidates.push(join(npmCache, "_cacache"));
  }
  if (!disabled.has("uv-cache")) {
    const uvBase = isAbsolute(xdgCache) ? xdgCache : join(home, ".cache");
    candidates.push(env.UV_CACHE_DIR ? path(env.UV_CACHE_DIR) : join(uvBase, "uv"));
  }
  if (!disabled.has("gh-cache")) candidates.push(join(path(xdgCache), "gh"));
  if (!disabled.has("go-cache")) {
    const goCacheBase = platform === "darwin" ? join(home, "Library", "Caches") : xdgCache;
    const goCache = env.GOCACHE || (isAbsolute(goCacheBase) ? join(goCacheBase, "go-build") : undefined);
    if (goCache && goCache !== "off" && isAbsolute(goCache)) candidates.push(goCache);
    if (env.GOMODCACHE) {
      if (isAbsolute(env.GOMODCACHE)) candidates.push(env.GOMODCACHE);
    } else if (goPath) candidates.push(join(goPath, "pkg", "mod"));
    if (goPath) candidates.push(join(goPath, "pkg", "sumdb"));
  }
  if (candidates.length === 0) return [];

  // A cache override/symlink is not consent to make HOME, a cache base,
  // credentials, or tool installations writable. Explicit extra roots remain
  // the user's deliberate override. These guards only filter new defaults.
  const broad = await Promise.all([
    "/", "/var", "/private", "/Users", "/home", "/tmp", home, join(home, "Library"), join(home, "Library", "Caches"),
    join(home, ".cache"), xdgCache, ...goPaths.filter(isAbsolute)
  ].map(value => canonicalPath(path(value))));
  const protectedPaths = [
    "/etc", "/bin", "/sbin", "/usr", "/opt", "/System", "/Library",
    ...[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".pi", ".claude", ".codex"].map(name => join(home, name)),
    ...[".rustup", ".nvm", ".volta", ".npm-global"].map(name => join(home, name)),
    join(home, ".cargo", "bin"), join(home, ".local", "lib", "node_modules"),
    join(home, ".npmrc"), join(home, ".netrc"), join(home, ".git-credentials"),
    join(home, ".npm", "_npx"), join(npmCache, "_npx"),
    join(path(xdgData), "gh"),
    join(home, ".config"), xdgConfig, join(home, "Library", "Keychains"),
    join(home, "Library", "Application Support"), join(home, ".local", "bin"), join(home, "bin"),
    join(home, ".local", "share", "uv"), join(path(xdgData), "uv"),
    ...goPaths.filter(isAbsolute).map(value => join(value, "bin")),
    ...[env.GOBIN, env.GOROOT, env.UV_TOOL_DIR, env.UV_TOOL_BIN_DIR, env.UV_PYTHON_INSTALL_DIR,
      env.UV_INSTALL_DIR, env.GH_CONFIG_DIR, env.PI_CODING_AGENT_DIR, env.npm_config_prefix, env.NPM_CONFIG_PREFIX].filter((value): value is string => Boolean(value))
  ];
  const protectedRoots = await Promise.all(protectedPaths.map(value => canonicalPath(path(value))));
  const canonical = await Promise.all(candidates.map(value => canonicalPath(value)));
  return unique(canonical.filter(candidate =>
    !broad.some(root => contains(candidate, root)) &&
    !protectedRoots.some(root => contains(root, candidate) || contains(candidate, root))
  ));
}

/** Resolves the immutable filesystem policy shared by every execution surface. */
export async function resolveWritePolicy(options: PolicyOptions): Promise<WritePolicy> {
  const home = options.home ?? homedir();
  const disabled = new Set(options.config.filesystem.disabledDefaultProfiles);
  const allow: string[] = [];
  const deny: string[] = [];
  if (!disabled.has("workspace")) allow.push(options.cwd);
  if (!disabled.has("tmp")) allow.push("/tmp");
  if (!disabled.has("cargo-cache")) {
    const cargoHome = expandPath(options.env.CARGO_HOME || join(home, ".cargo"), options.cwd, home);
    allow.push(cargoHome);
    deny.push(...["bin", "config", "config.toml", "credentials", "credentials.toml", "env"].map(name => join(cargoHome, name)));
  }
  const runtimeHomePaths = [join(home, ".npm", "_logs"), join(home, ".claude", "debug")];
  if (!disabled.has("runtime-home")) allow.push(...runtimeHomePaths);
  else deny.push(...runtimeHomePaths);
  allow.push(...await cacheWriteRoots(options, home));
  allow.push(...options.config.filesystem.extraWritableRoots.map(path => expandPath(path, options.cwd, home)));
  return {
    allow: unique(await Promise.all(allow.map(path => canonicalPath(expandPath(path, options.cwd, home))))),
    deny: unique(await Promise.all(deny.map(path => canonicalPath(path))))
  };
}
