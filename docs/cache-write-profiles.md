# Default package-cache write profiles

The startup filesystem policy includes four independently disableable profiles:
`npm-cache`, `uv-cache`, `gh-cache`, and `go-cache`. They apply to **any** sandboxed
bash command and native `write`/`edit`, not just the named executables. They do
not add host execution, automatic host replay, network access, or install hooks.

## Resolved paths (macOS and Linux)

| Profile | Startup environment override | Default |
| --- | --- | --- |
| `npm-cache` | `npm_config_cache`, then `NPM_CONFIG_CACHE` | `~/.npm/_cacache` |
| `uv-cache` | `UV_CACHE_DIR`, then absolute `XDG_CACHE_HOME` + `/uv` | `~/.cache/uv` on both macOS and Linux |
| `gh-cache` | `XDG_CACHE_HOME` + `/gh` | `~/.cache/gh` on both macOS and Linux |
| `go-cache`: build | absolute `GOCACHE` | macOS: `~/Library/Caches/go-build`; Linux: `${XDG_CACHE_HOME:-~/.cache}/go-build` |
| `go-cache`: modules | absolute `GOMODCACHE` | first `GOPATH` entry + `/pkg/mod`; unset `GOPATH` defaults to `~/go` |
| `go-cache`: checksum tree heads | first `GOPATH` entry + `/pkg/sumdb` | `~/go/pkg/sumdb` |

For npm, the override denotes the **parent** npm cache; only its `_cacache`
child is allowed, including `tmp/<random UUID>`, content and index files. Neither
`_npx` nor the entire npm home becomes writable. Existing per-file project grants
need not be reused for future random temporary files. Stored grants are not
migrated or deleted. The existing `runtime-home` profile still controls default
`~/.npm/_logs`, independently; custom npm log directories need explicit roots.

Empty environment values use the corresponding defaults. Go cache overrides
must be absolute: relative `GOCACHE`/`GOMODCACHE` add no allowance, and
`GOCACHE=off` adds no build-cache allowance (modern Go itself requires a cache).
Go uses only the **first** colon-separated GOPATH entry, not every entry. An
invalid relative or empty first entry adds no module/sumdb default; an explicit
absolute GOMODCACHE still works. Overriding GOMODCACHE does not relocate checksum
tree-head state: it remains under the first GOPATH. Lookup/tile caches inside
`GOMODCACHE/cache/download/sumdb` are already covered by the module cache.

On Linux, a relative XDG cache base adds no Go build-cache allowance; uv ignores
it and uses its home default. gh's implementation instead joins a nonempty XDG
value literally; relative values resolve against startup cwd. Use absolute XDG
paths for predictable behavior. npm expands `~/` in its cache setting. Relative
uv cache paths resolve against startup cwd; uv/gh paths do not shell-expand `~`.
Windows has different defaults (`LocalAppData`-based caches) but no supported
filesystem sandbox here, so these profiles add no Windows cache roots.

## Configuration, canonicalization and boundaries

To opt out of all four (or choose a subset):

```json
{
  "filesystem": {
    "disabledDefaultProfiles": ["npm-cache", "uv-cache", "gh-cache", "go-cache"],
    "extraWritableRoots": ["/mnt/dedicated-build-cache"]
  }
}
```

Opt-out removes only the profile's additions; it is not a hard deny. An explicit
extra root or another enabled profile (for example `tmp`) may still cover that
path. Explicit extra roots retain the existing tilde/relative-path semantics.
Configured policy denies, including Cargo credential/bin denies and the private
approval-transport deny, continue to take precedence on both execution surfaces
and during sandbox widening. These cache profiles never remove a deny.

Paths are resolved once at session startup through their nearest existing
ancestor, then canonicalized and deduplicated. A cache symlink to a dedicated
storage directory is supported, including not-yet-created descendants. New
automatic cache candidates that would grant HOME or an ancestor, a whole cache
base, GOPATH, or intersect known credential/configuration/install locations are
omitted, **without falling back to the tool's default cache**. Guards include
standard SSH/AWS/GPG/Kubernetes configuration, gh configuration, macOS Keychains,
standard system install roots, npm `_npx`, Go bin/GOROOT, uv data/tools/bin and
environment-selected installation/configuration locations. Guards apply after
canonicalization, including when a protected path is an alias into a cache.
They filter automatic roots; they are not a general filesystem deny list or a
classifier of arbitrary directories' contents. Trusted explicit extra roots can
still deliberately broaden access subject to existing denies.

Resolution does not execute npm, uv, gh or Go, or read their configuration or
authentication files. `.npmrc`, uv configuration, persisted `go env -w`/GOENV,
command flags, `--no-cache` temporary paths, `GOCACHEPROG`, legacy uv locations,
and environment changes made **inside a command** do not dynamically widen the
policy. Set the effective location in the startup environment, configure a
narrow extra root, or approve the observed sandbox resource. Reload after
changing startup configuration. No authentication contents are copied into policy.

## Go network access is separate

On macOS, the filesystem profile alone grants no network authority. The independent
`packages` network profile now permits `proxy.golang.org:443` and `sum.golang.org:443`
by default; see [network defaults and opt-outs](network-defaults.md). Disabling
`packages` removes these allowances even if `go-cache` remains enabled. A cold
public module download normally needs the module proxy. The proxy can serve
checksum database requests under its own endpoint, so direct sum.golang.org is
not always contacted; direct/fallback checksum access may require it. Offline
builds with complete caches need neither. To disable the broader package profile
but retain these two explicit HTTPS endpoints:

```json
{
  "network": {
    "disabledDefaultProfiles": ["packages"],
    "extraAllowedDomains": ["proxy.golang.org:443", "sum.golang.org:443"]
  }
}
```

This does not allow HTTP, arbitrary ports, AWS/S3, private module hosts, VCS
fallbacks, toolchain redirect storage, or other mirrors. Approve/configure those
separately if actually needed; do not infer authority from GOPROXY/GOSUMDB URLs.
Linux network isolation remains unsupported, independent of filesystem policy.

## Shared-cache security risk

Writable caches are **cross-project state**, not a trust boundary. A sandboxed
command or native edit can corrupt/delete entries or poison artifacts later
consumed by another project, by a host process, or by another user of the same
cache. npm integrity and Go checksum checks do not make every cached artifact
trusted. uv can link cached files into environments, increasing shared-inode
risk. Go's checksum tree-head state is security-relevant persistent state even
though it is needed for normal module downloads. The build/module cache can
also contain executable artifacts (including downloaded Go toolchains); these
allowances do not authorize Go bin or uv tool installation directories.

For untrusted projects, disable shared profiles and use isolated per-project
caches in the workspace, or dedicated explicit roots. Do not directly edit a
live uv cache; use its cache-management commands. This change reduces cache-write
prompts; it neither validates package contents nor adds host automatic execution.

## Sources and design decision

Checked against official documentation/source on 2026-11-10:

- [npm config: environment and cache](https://docs.npmjs.com/cli/v11/using-npm/config#cache),
  [npm cache: `_cacache`](https://docs.npmjs.com/cli/v11/commands/npm-cache).
- [uv cache-directory precedence](https://docs.astral.sh/uv/concepts/cache/#cache-directory),
  [uv directory implementation](https://github.com/astral-sh/uv/blob/main/crates/uv-dirs/src/lib.rs).
- [gh cache implementation](https://github.com/cli/go-gh/blob/trunk/pkg/config/config.go),
  [gh environment/config (not cache) settings](https://cli.github.com/manual/gh_help_environment).
  `GH_CONFIG_DIR` is not a cache override; no `GH_CACHE_DIR` is assumed.
- [Go cache resolution](https://github.com/golang/go/blob/master/src/cmd/go/internal/cache/default.go),
  [OS cache base](https://github.com/golang/go/blob/master/src/os/file.go),
  [first GOPATH and GOMODCACHE](https://github.com/golang/go/blob/master/src/cmd/go/internal/cfg/cfg.go),
  [separate sumdb state/cache and proxy routing](https://github.com/golang/go/blob/master/src/cmd/go/internal/modfetch/sumdb.go).

A bounded read-only council used oracle (fork context) and reviewer (runtime
default context), one independent pass, no external-CLI fallback. Both supported
independent profiles, canonical safety filtering, opt-out/explicit additions and,
at the time of that cache-only change, unchanged network defaults. A reviewer suggestion to use all GOPATH entries was
rejected based on Go's `gopathDir` implementation; first entry only is correct.
Relative-XDG gh fallback suggested in final review was rejected because gh's
`CacheDir` joins the environment value literally; a regression test records that
behavior. Unsafe automatic candidates are silently omitted rather than adding
startup notifications; explicit configuration remains available. Confidence is
high for documented default/startup-env paths, not arbitrary per-tool settings.

## Verification in the issue workspace

- `npm ci` installed the locked dependencies and applied the existing SDK patch.
- `npm run check`, `npm run build`, and `git diff --check` passed.
- Final non-OS suite: 267 passed, zero failed/skipped. This runs all test files
  except the five fixed macOS integration-group files listed by
  `scripts/run-local-macos-tests.mjs`; it is not a substitute for that group.
- The earlier full `npm test` attempt had 267 passing and 16 failing tests
  (including the three new native cache cases). The OS group could not create
  nested macOS sandboxes: `sandbox-exec: sandbox_apply: Operation not permitted`.
- The existing once-approved `macos_sandbox_test` host runner was requested but
  not approved, so no host test process started. OS integration remains
  **unverified**, including the new default/opt-out/canonical-env-deny cases.
  Run `npm run test:macos` from a normal host terminal in this workspace, or
  approve a fresh host-runner request, to supply this remaining evidence.
- Go endpoint checks cover policy matching and filesystem/network independence;
  no live cold Go download was performed. Proxy/checksum routing requirements
  above are backed by the official Go source, not an observed network trace.
