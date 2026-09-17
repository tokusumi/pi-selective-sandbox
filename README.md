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

The extension replaces Pi's `bash`, `write`, and `edit` tools. `bash` starts with the extension startup working directory and `/tmp` writable, broad reads, and GitHub API access for authenticated `gh` use. If the sandbox cannot initialize or run, execution fails closed: it never silently falls back to the host.

For `write` and `edit`, a canonical target inside configured writable roots executes normally. A target outside those roots must receive a sandbox-capability approval before any file-content read, directory creation, or mutation. Native write/edit never offer host-command approval.

## Platform notes

The OS sandbox runtime remains the enforcement authority. On Linux, observer paths are candidate resources, not authoritative kernel-denial claims. A candidate may be canonicalized on the host and offered for sandbox widening; the widened sandbox still decides enforcement. For host replay, the candidate path is explanatory only: approval is command-scoped and is not a host resource permission. Linux and macOS do not need identical internal telemetry to retain this separation.

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
