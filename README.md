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

## Installation

Install with Pi's normal package installer, then restart Pi:

```sh
pi install git:github.com/tokusumi/pi-selective-sandbox
```

## Behavior

The extension replaces Pi's `bash`, `write`, and `edit` tools. `bash` starts with the extension startup working directory, `/tmp`, and Cargo's cache area writable, broad reads, and GitHub API access for authenticated `gh` use. The Cargo profile permits `$CARGO_HOME` (or `~/.cargo`) but explicitly denies its `bin`, `config`, `config.toml`, `credentials`, `credentials.toml`, and `env` entries. If the sandbox cannot initialize or run, execution fails closed: it never silently falls back to the host.

For `write` and `edit`, a canonical target inside configured writable roots executes normally. A target outside those roots must receive a sandbox-capability approval before any file-content read, directory creation, or mutation. Native write/edit never offer host-command approval.

### Filesystem configuration

Optional user-local configuration is read at startup from `<Pi agent directory>/pi-selective-sandbox/config.json`. A missing file uses defaults. An existing malformed file, invalid field, or unknown profile name emits a diagnostic and installs a deny-by-default write policy while still replacing all three tools. Extra roots remain inside the sandbox and do not authorize host replay.

```json
{
  "filesystem": {
    "extraWritableRoots": ["~/.cache/uv", "/mnt/build-cache"],
    "disabledDefaultProfiles": []
  }
}
```

Paths beginning with `~/` are expanded, relative paths are resolved against the startup working directory, and paths are canonicalized. Available default profile names are `workspace`, `tmp`, `cargo-cache`, and `runtime-home`. The last profile mirrors the sandbox runtime's implicit `~/.npm/_logs` and `~/.claude/debug` allowances for native tools; disabling it adds explicit runtime denies. For example, set `disabledDefaultProfiles` to `["cargo-cache"]` to remove Cargo's default writable cache profile.

The sandbox runtime also owns a small set of operational housekeeping paths such as `/tmp/claude`; these are not user-configurable policy roots and are outside cross-surface parity. A bash violation intersecting any configured deny root is never offered sandbox widening, because `denyWrite` would make that retry ineffective. Only exact-command host replay can be offered in that case; native write/edit fail without an approval prompt.

## Platform notes

| Platform | Filesystem | Network | Unix sockets |
| --- | --- | --- | --- |
| macOS | Isolated | Isolated | Isolated |
| Linux | Isolated | Isolated | Isolated |
| Ubuntu 24.x | Isolated | Isolated | Unrestricted |

Ubuntu 24.x is a known platform exception. The extension detects it from
`/etc/os-release` and sets `network.allowAllUnixSockets: true`, because its
restrictive AppArmor policy can block the nested user namespace required by
the runtime's Unix-socket isolation. This does not disable Bubblewrap
filesystem or network-namespace isolation and is not host replay.

The OS sandbox runtime remains the enforcement authority. On Linux, observer paths are candidate resources, not authoritative kernel-denial claims. A candidate may be canonicalized on the host and offered for sandbox widening; the widened sandbox still decides enforcement. For host replay, the candidate path is explanatory only: approval is command-scoped and is not a host resource permission. Linux and macOS do not need identical internal telemetry to retain this separation.

### Ubuntu 24.04 troubleshooting

On Ubuntu 24.04 with restrictive AppArmor, install the distribution's
`apparmor-profiles` package and enable the `bwrap-userns-restrict` profile so
the outer Bubblewrap sandbox can start. The runtime's normal Unix-socket
isolation can still fail when `apply-seccomp` attempts the nested user namespace used for
Unix-socket isolation. The Ubuntu 24.x compatibility exception avoids that operation
by leaving Unix sockets unrestricted. The extension never changes AppArmor or
sysctls for you. If Bubblewrap itself remains unavailable, execution fails
closed without automatic host fallback.

## Persistent approvals

Sandbox grant identity is capability plus canonical resource. Host grant identity is exact command plus canonical working directory plus execution mode. Reusable grants are partitioned by session ID for session scope and project ID for project scope; once grants are not stored.

Project identity is the canonical Git worktree root, or the canonical startup working directory when there is no Git worktree. It is distinct from the startup working directory used as the default writable root. Moving or cloning a repository does not inherit project grants. See [SPEC.md](SPEC.md) for storage invariants and exact matching rules.

## Development

```sh
npm ci
npm run check
npm test
```

## Acknowledgements

This project builds on and learned from several excellent projects:

- [@anthropic-ai/sandbox-runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) — the OS sandbox runtime used for subprocess isolation.
- [pi-permission-modes](https://github.com/wynainfo/pi-permission-modes) — an important reference for permission and sandbox integration in Pi.
- [@spences10/pi-skills](https://github.com/spences10/my-pi/tree/main/packages/pi-skills) — used for Skill discovery and trust authority.
- [@spences10/pi-redact](https://github.com/spences10/my-pi/tree/main/packages/pi-redact) — used to redact likely secrets before tool output reaches model context.

Many thanks to their maintainers and contributors. These acknowledgements do not imply endorsement or affiliation.

## License

See [LICENSE](LICENSE).
