# pi-selective-sandbox

`pi-selective-sandbox` is a Pi extension that keeps command execution sandboxed by default and asks for a narrowly scoped exception only when the sandbox blocks an operation. **Sandbox by default. Escalate by exception.**

> [!WARNING]
> **This project is under early development.**
> Approval semantics, persistence formats, platform behavior, and APIs may
> change before 1.0. Review approval prompts carefully and validate the
> behavior in your environment before relying on it for security-sensitive use.

## Why

Pi can need access beyond a project's normal writable area, but an ordinary command error is not a reason to broaden its authority. This extension keeps the default boundary small while making exceptional authority visible and specific.

## How it works

Normal `bash` commands run in the OS sandbox first. Sandbox success and ordinary command failure return normally and do not prompt. Only a sandbox violation can offer an explicit exception. Native `write` and `edit` operations use equivalent preflight resource boundaries before they read or mutate a target.

The full behavioral and security contract is in [SPEC.md](SPEC.md).

## Approval model

| Approval | Authority | Execution | Once | Session | Project |
| --- | --- | --- | --- | --- | --- |
| Sandbox widening | capability + resource | sandbox | ✓ | ✓ | ✓ |
| Host replay | exact command identity | host | ✓ | ✓ | ✓ |

Approving a resource never approves leaving the sandbox.

Approving host execution never grants a resource capability.

For `bash`:

```text
sandbox
   ↓
violation
   ├─ Allow resource in sandbox
   │      → once / session / project
   │
   └─ Run exact command outside sandbox
          → once / session / project
```

Stored host-command grants do not bypass sandbox-first execution. The command is still tried in the sandbox first and only replays on host after a sandbox violation.

### Resource approval UI

For a bash filesystem-write violation, the approval screen separates **Blocked target**, **Allow access to**, **Duration**, and **Command**. Select the initial scope or any of its parent directories, then choose `Once`, `This session`, or `This project` when eligible, and confirm with `Allow and retry`. It starts with the initial scope and `Once`. Paths cannot be typed freely; candidates follow the canonical ancestor chain all the way to `/`, without special treatment for HOME.

A directory selection allows writes beneath that directory, including unrelated siblings of the blocked target. Selecting `/` displays an explicit whole-filesystem warning. Existing configured and SDK deny rules still apply, even with a broad scope. Git metadata and directory-entry operations retain their required initial scopes, which can differ from the observed leaf; the screen shows both. Selecting a parent of shared Git metadata remains once-only.

Use `Tab` / `Shift+Tab` to move between fields, arrow keys to select, and `Enter` to continue or confirm. `Esc` denies. The selected path is displayed in full below the candidate list. If several scopes are needed, each has its own ancestor selection. RPC clients use successive scope, duration, and confirmation selectors rather than a custom terminal screen. Headless execution still denies requests that have no eligible stored grant.

`Run outside sandbox…` opens a separate host-duration and exact-command confirmation. It does not approve the selected resource. Both resource retry and host replay rerun the entire command and can repeat earlier side effects. Native `write` / `edit` retain their exact-target preflight approval UI; ancestor selection is for bash sandbox widening.

## Installation

Install with Pi's normal package installer, then restart Pi:

```sh
pi install git:github.com/tokusumi/pi-selective-sandbox
```

## Behavior

The extension replaces Pi's `bash`, `write`, and `edit` tools. `bash` starts with the extension startup working directory, `/tmp`, and Cargo's cache area writable, broad reads, and, on macOS, common Git, Node, Rust, and Python network endpoints allowed by default (including GitHub API access for authenticated `gh` use). The Cargo profile permits `$CARGO_HOME` (or `~/.cargo`) but explicitly denies its `bin`, `config`, `config.toml`, `credentials`, `credentials.toml`, and `env` entries. If the sandbox cannot initialize or run, execution fails closed: it never silently falls back to the host.

When that startup directory is writable and belongs to a Git repository, a blocked Git metadata write offers the shared Git directory and, only if it is outside the shared directory, the worktree's Git directory. Git writes can span the index, objects, refs, reflogs, tags, and worktree records; this approval lets a multi-step operation retry without reaching a second Git metadata denial after it has already changed repository state. The shared directory grant can affect other worktrees and Git configuration or hooks, so the approval prompt names that scope. Configured deny paths still apply, and this access does not change the native `write` or `edit` boundaries.

For a single, literal `git worktree remove` command, a registered target outside writable roots needs its parent directory writable to remove the worktree directory itself. The approval request offers that parent once, without a session or project resource grant option, because it can be broader than the worktree path. Nested candidate paths are collapsed so sandbox bind mounts do not block directory removal.

If a later sandbox retry reaches another blocked path, the extension asks for that additional path before retrying again. This covers commands that stop at their first failed write, so their later writes were not visible in the first attempt. Every retry reruns the full shell command and may repeat earlier side effects; review each prompt for compound or destructive commands.

Approval is tied to filesystem access, not whether a Git command is destructive. For example, `git clean -fd` can delete untracked files inside an already writable worktree without an approval prompt. A command that has already made changes before reaching a blocked path cannot be resumed from that point; a retry starts it again.

For `write` and `edit`, a canonical target inside configured writable roots executes normally. A target outside those roots must receive a sandbox-capability approval before any file-content read, directory creation, or mutation. Native write/edit never offer host-command approval.

Run `/selective-sandbox off` to explicitly disable sandbox enforcement for `bash`, `write`, and `edit`. Subsequent bash commands run directly on the host, and native file mutations skip boundary approvals. Bash output redaction remains active. Run `/selective-sandbox on` to enable enforcement again. The setting stays in memory and is not saved to configuration or grants; Pi's `/reload` command (which reloads extensions) or restarting Pi also restores enforcement. Missing or unsupported arguments display usage and leave enforcement unchanged.

### Network permission (macOS)

When a proxy-aware command reaches a blocked destination, the approval prompt
shows the exact `host:port`, asks for once, session, or project duration, and
then offers **Allow and retry**. Endpoints are fixed; unlike filesystem write
scopes, they cannot be expanded to ancestors. The retry stays in the sandbox; filesystem
restrictions remain in force. A different port or hostname needs separate
approval. Unknown socket denials and DNS/private-address protection failures
cannot be widened by guessing a destination from the shell command.

Each macOS attempt has its own authenticated HTTP/SOCKS proxy. Approvals do not
leak into concurrent commands or change the SDK's global allowlist. The proxy
closes when the attempt ends, including open connections and background
children's access. This permits proxy-aware HTTP/HTTPS and TCP clients, not raw
TCP/UDP or unrestricted networking. Network isolation and network permissions
are macOS-only features. Linux network isolation is not a supported guarantee;
Linux filesystem sandboxing remains separate.

### Filesystem and network configuration

Optional user-local configuration is read at startup from `<Pi agent directory>/pi-selective-sandbox/config.json`. A missing file uses defaults. An existing malformed file, invalid field, or unknown profile name emits a diagnostic and installs a deny-by-default write policy and empty network allowlist while still replacing all three tools. Extra roots remain inside the sandbox and do not authorize host replay.

```json
{
  "filesystem": {
    "extraWritableRoots": ["~/.cache/uv", "/mnt/build-cache"],
    "disabledDefaultProfiles": []
  },
  "network": {
    "extraAllowedDomains": ["packages.example.com:443"],
    "disabledDefaultProfiles": []
  }
}
```

macOS network defaults are grouped into independently switchable profiles:

| Profile | Default destinations |
| --- | --- |
| `git` | `github.com`, `api.github.com`, `*.github.com`; HTTPS to `gitlab.com`, `bitbucket.org`, `raw.githubusercontent.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` |
| `node` | HTTPS to `registry.npmjs.org`, `registry.yarnpkg.com`, `nodejs.org`, `get.pnpm.io` |
| `rust` | HTTPS to `crates.io`, `index.crates.io`, `static.crates.io`, `static.rust-lang.org`, `sh.rustup.rs` |
| `python` | HTTPS to `pypi.org`, `files.pythonhosted.org`, `python.org`, `www.python.org`, `astral.sh` |

HTTPS means TCP port 443 only. The original GitHub host patterns retain their
existing all-port behavior. These profiles group destinations, not executables:
any sandboxed command may reach an enabled destination. They cover common
package installs and toolchain downloads, not every mirror, redirect CDN, or
self-hosted registry.

Set `network.disabledDefaultProfiles` to, for example, `["node", "python"]`
to remove those defaults, or all four names to start with an empty allowlist.
Disabling a profile removes its baseline allowances; it is not a hard deny of
explicit additions or later approvals. Filesystem profiles are independent.

`network.extraAllowedDomains` adds startup allowances to the enabled profiles.
Entries are deduplicated. Use hostnames or IP literals, optionally `:port`;
bracket IPv6 (for example, `[::1]:8080`). Without a port, all TCP ports for that
host are permitted. `*.example.com` permits strict subdomains, not the apex.
URLs, paths, bare `*`, and broad wildcards such as `*.com` are rejected. These
settings grant no host replay. For explicitly allowed local/private destinations,
override the SDK's NO_PROXY in the client (for example, curl `--noproxy ''`) so
the connection goes through the sandbox proxy. Per-attempt proxies also inherit
the SDK's upstream HTTP_PROXY / HTTPS_PROXY / NO_PROXY routing.

Paths beginning with `~/` are expanded, relative paths are resolved against the startup working directory, and paths are canonicalized. Available default profile names are `workspace`, `tmp`, `cargo-cache`, and `runtime-home`. The last profile mirrors the sandbox runtime's implicit `~/.npm/_logs` and `~/.claude/debug` allowances for native tools; disabling it adds explicit runtime denies. For example, set `disabledDefaultProfiles` to `["cargo-cache"]` to remove Cargo's default writable cache profile.

The sandbox runtime also owns a small set of operational housekeeping paths such as `/tmp/claude`; these are not user-configurable policy roots and are outside cross-surface parity. A bash violation intersecting any configured deny root is never offered sandbox widening, because `denyWrite` would make that retry ineffective. Only exact-command host replay can be offered in that case; native write/edit fail without an approval prompt.

## Platform notes

| Platform | Filesystem | Network | Unix sockets |
| --- | --- | --- | --- |
| macOS | Isolated | Isolated | Isolated |
| Other Linux | Isolated | Not supported | Isolated |
| Ubuntu | Isolated | Not supported | Unrestricted |

On macOS, SDK log monitoring is explicitly enabled. SDK stream events supply
command-correlated denials; filesystem resources are read from raw event data,
not sanitized presentation text. After a failed command, the adapter waits up
to one second for a matching supported SDK event before returning an ordinary
failure without approval.

If the SDK initialization flag `enableLogMonitor` is explicitly `false` on
macOS, enforcement is forced off for all three tools before executing an enabled
tool. A **warning** (UI notification, or stderr in headless mode) states that
bash runs on the host and native mutation approvals are bypassed. `/selective-sandbox on` cannot override this condition;
restore the SDK flag and reload. This checks only the flag, not the monitor's
process health. Initialization failures alone do not trigger automatic off.

The extension detects Ubuntu from `ID=ubuntu` in `/etc/os-release` and sets
`network.allowAllUnixSockets: true` for every Ubuntu release. Unix-socket
isolation is not provided on this execution path. Bubblewrap still enforces
filesystem isolation, and this mode is not host replay. Linux network isolation
is outside the supported feature contract.
On the tested Ubuntu 24.04 host, restrictive AppArmor policy blocks the nested
user namespace that the runtime's Unix-socket isolation would require.

Ubuntu also requires `strace` as its filesystem violation observer. The
extension checks `strace` availability and basic ptrace operation at startup.
It traces the Bubblewrap command, ignores Bubblewrap setup calls, and
attributes only failed write syscalls with `EROFS` against the existing write
policy. Trace data is carried on a parent-owned pipe; command output uses a
separate pipe. If tracing cannot start, bash fails closed and never runs the
command on the host automatically.
For creation, deletion, and rename, a sandbox-widening request names the
containing directory, because the new or removed entry cannot be made writable
by granting its leaf path alone. The observed leaf remains in the diagnostic.

The OS sandbox runtime remains the enforcement authority. On Linux, observer paths are candidate resources, not authoritative kernel-denial claims. A candidate may be canonicalized on the host and offered for sandbox widening; the widened sandbox still decides enforcement. For host replay, the candidate path is explanatory only: approval is command-scoped and is not a host resource permission. Linux and macOS do not need identical internal telemetry to retain this separation.

### Ubuntu 24.04 troubleshooting

On Ubuntu 24.04 with restrictive AppArmor, install the distribution's
`apparmor-profiles` package and enable the `bwrap-userns-restrict` profile so
the outer Bubblewrap sandbox can start. The Ubuntu execution path leaves Unix
sockets unrestricted and does not invoke the runtime's nested `apply-seccomp`
helper. The extension never changes AppArmor or sysctls for you. If Bubblewrap
itself remains unavailable, execution fails closed without automatic host
fallback.

## Persistent approvals

Sandbox grant identity is capability plus canonical resource. Host grant identity is exact command plus canonical working directory plus execution mode. Reusable grants are partitioned by session ID for session scope and project ID for project scope; once grants are not stored.

Project identity is the canonical Git base directory, shared by all linked worktrees: normally the main worktree directory, or the repository metadata directory for bare repositories and `--separate-git-dir` layouts. Outside Git, it is the canonical startup working directory. It is distinct from the startup working directory used as the default writable root. Resource paths and host-command working directories still require exact matches; a host command approved in one worktree is not automatically approved in another cwd. Moving or cloning a repository does not inherit project grants. Existing approvals keyed to a linked worktree are not migrated; approve them again for the shared project if needed. See [SPEC.md](SPEC.md) for storage invariants and exact matching rules.

## Development

```sh
npm ci
npm run check
npm test
```

The SDK is pinned to `0.0.76`. `npm ci` applies
`patches/sandbox-runtime-0.0.76.patch` through the `postinstall` script, using
Git and checking exact SDK file hashes before and after application. Do not
skip lifecycle scripts. The patch fixes record attribution, preserves raw resources, and lets the
macOS wrapper use an embedder-owned per-invocation proxy port/token. It retains
the SDK's log-stream/store execution path and sanitized presentation text. Unexpected versions or partial/local modifications
fail installation rather than silently accepting an incomplete patch. An SDK
upgrade requires reviewing the patch and rerunning the regression tests.

## Acknowledgements

This project builds on and learned from several excellent projects:

- [@anthropic-ai/sandbox-runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) — the OS sandbox runtime used for subprocess isolation.
- [pi-permission-modes](https://github.com/wynainfo/pi-permission-modes) — an important reference for permission and sandbox integration in Pi.
- [@spences10/pi-skills](https://github.com/spences10/my-pi/tree/main/packages/pi-skills) — used for Skill discovery and trust authority.
- [@spences10/pi-redact](https://github.com/spences10/my-pi/tree/main/packages/pi-redact) — used to redact likely secrets before tool output reaches model context.

Many thanks to their maintainers and contributors. These acknowledgements do not imply endorsement or affiliation.

## License

See [LICENSE](LICENSE).
