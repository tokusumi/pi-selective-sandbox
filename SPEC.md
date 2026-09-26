# pi-selective-sandbox specification

This document is the canonical behavioral and security contract for
`pi-selective-sandbox`. README.md is a concise user guide; when the two differ,
this specification governs the intended behavior.

## 1. Principles

- Sandbox by default. Escalate by exception.
- Sandbox success never requires approval.
- Ordinary command failure never implies escalation.
- Sandbox unavailability never silently falls back to host execution.
- An approval grants only the authority described by its grant type and scope.
- Platform-specific isolation properties must be documented and deterministic.

## 2. Execution surfaces

The extension replaces Pi's `bash`, `write`, and `edit` tools.

- `bash` is a subprocess execution surface. Normal commands are wrapped by the
  OS sandbox runtime before the command runner starts them.
- `write` and `edit` are native in-process Pi tools. They enforce an explicit,
  canonical filesystem boundary before invoking the native tool.
- The resolved default write policy permits the extension startup working
  directory, `/tmp`, and the Cargo home (`$CARGO_HOME`, otherwise `~/.cargo`).
  Within Cargo home, `bin`, `config`, `config.toml`, `credentials`,
  `credentials.toml`, and `env` are denied. Deny rules take precedence.
- At startup, optional user-local configuration can disable named default
  profiles or add writable roots. Tilde expansion, absolute resolution,
  canonicalization, and deduplication happen once; the resolved caller policy
  is shared by the runtime and native mutation boundary. Runtime-owned
  housekeeping paths required by `@anthropic-ai/sandbox-runtime` (for example,
  `/tmp/claude`) are explicitly outside this cross-surface parity contract.
- The `runtime-home` profile incorporates the runtime's implicit
  `~/.npm/_logs` and `~/.claude/debug` convenience paths into the shared
  policy. Disabling that profile adds explicit denies for both paths.

## 3. Approval authorities

Platform baseline isolation, sandbox widening, and host replay are separate
concepts. Sandbox widening adds a resource-specific capability inside the
platform baseline. Host replay authorizes an exact command to run outside it.

There are two deliberately separate authorities:

| Grant | Authority | Permitted execution |
| --- | --- | --- |
| `SandboxCapabilityGrant` | capability and canonical resource | widened sandbox only |
| `HostCommandGrant` | exact `CommandIdentity` | host replay only |

`SandboxCapabilityGrant` never authorizes host execution.

`HostCommandGrant` never grants a resource capability or widens a sandbox.

Resource approval means sandbox widening only. Host authority is exact operation
authority, not filesystem, executable, or policy authority.

## 4. Approval scopes

Every supported authority can be approved with one of these scopes:

- `once`: only the current operation; it is not stored.
- `session`: retained in memory for the current Pi session ID.
- `project`: retained in user-local persistent state for the current project
  identity and available to future Pi sessions in that project.

Grants are exact. A grant does not imply a parent directory, subtree, different
resource, different capability, different project, command prefix, tool name,
or executable-name match.

## 5. Bash execution flow

For ordinary bash commands:

1. Resolve stored sandbox capability grants for the current session and project.
2. Start the command in the sandbox with only the base policy plus those grants.
3. If sandbox execution succeeds, return its result without approval.
4. If it fails without a correlated sandbox violation, return that ordinary
   sandbox result without approval.
5. If it has a violation, apply the capability policy and request approval when
   policy permits asking.
6. If any filesystem-write candidate intersects a configured deny root, do not
   offer sandbox-capability approval: deny rules would make the retry
   ineffective. The approval surface may offer exact-command host replay only.
7. A sandbox-capability response retries in the sandbox with the approved,
   canonical capability resource.
8. A host-command response replays the exact command on the host.

All attempts may remain visible in the streamed execution transcript. Before
requesting approval for a detected violation, the extension streams
`<sandbox: approval-required filesystem.write>` (or the detected capability
kind). Approval then streams `<sandbox: approved widen retry>`,
`<sandbox: approved host-replay>`, or `<sandbox: approval-denied>`. An approved
attempt ends with `<sandbox: retry exit=N>` or `<sandbox: replay exit=N>`.
Only the final selected attempt determines the tool exit code; denial retains
the initial sandbox exit code. Ordinary failures and sandbox successes have no
status marker.

The command has already been attempted before a replay choice; a replay can
repeat side effects permitted before the violation. Trusted pure Skill helpers
are the explicitly limited exception described in section 13.

## 6. write/edit flow

`write` and `edit` resolve the requested target through its nearest existing
ancestor, canonicalizing paths to prevent symlink escape.

```text
canonical target
  → inside an allow root and outside every deny root → execute
  → otherwise → preflight sandbox-capability approval
```

No host-command approval is offered for native `write` or `edit`. If preflight
authorization is denied or persistent storage fails, no native tool invocation,
file-content read, directory creation, or mutation occurs.

## 7. SandboxCapabilityGrant

Conceptual identity:

```text
capability kind + canonical resource
```

Reusable grants are partitioned by session ID for session scope and project identity
for project scope. Current capability kinds
include filesystem read, filesystem write, and network; current UI widening is
limited to reported filesystem-write candidates. The grant is consumed only as
extra sandbox capability configuration.

## 8. HostCommandGrant

Conceptual identity:

```text
exact command + canonical cwd + execution mode
```

Reusable host grants are partitioned by session ID for session scope and project
identity for project scope. Host grants are persisted separately from sandbox
capability grants and contain only command identities. There are no
command-prefix matches,
executable-name-only matches, environment-wide hashes, or resource-scoped host
grants.

## 9. CommandIdentity

`CommandIdentity` has these minimum fields:

```text
shell command
canonical cwd
execution mode
```

The shell command must match exactly. The working directory must be
canonicalized. If cwd cannot be canonicalized, reusable host session/project
approval is unavailable; a one-time host replay may still be offered after a
violation.

## 10. Project identity

Project identity is resolved once at extension startup:

1. canonical Git worktree root, when Git can provide one;
2. otherwise, canonical startup cwd.

If neither path can be canonicalized, project persistence is unavailable.
Project identity is distinct from the extension startup working directory used as
the default writable root. Changing directories later does not change the
identity. Moving or cloning a
repository does not inherit its project grants.

## 11. Linux telemetry semantics

### Platform capabilities

| Platform | Filesystem | Network namespace | Unix sockets | Fail closed |
| --- | --- | --- | --- | --- |
| macOS | Isolated | Isolated | Isolated | Yes |
| Other Linux | Isolated | Isolated | Isolated | Yes |
| Ubuntu | Isolated | Isolated | Unrestricted | Yes |

Ubuntu is detected from `ID=ubuntu` in `/etc/os-release`, regardless of version,
and uses `network.allowAllUnixSockets: true`. The tested Ubuntu 24.04 host's
AppArmor policy allows the outer Bubblewrap sandbox while blocking the nested
user namespace used by the runtime's seccomp-based Unix-socket isolation.
This execution mode does not change filesystem permissions, network-namespace
isolation, violation handling, sandbox widening, or the approval model. It is
not host replay;
filesystem and network sandboxing continue inside Bubblewrap.

Because `allowAllUnixSockets` skips upstream seccomp observation, Ubuntu
uses `strace` around Bubblewrap for filesystem telemetry. The tracer's stderr
pipe belongs to the extension process; the traced command's stderr is routed
to normal command output before Bubblewrap starts. The observer ignores
Bubblewrap setup syscalls, follows the workload and descendants, and reports
only upstream write-intent syscall failures with `EROFS` whose resolved path
is outside the effective `WritePolicy`. Missing or blocked `strace` makes bash
unavailable. This telemetry only triggers the existing approval flow; it does
not grant host execution or widen the sandbox by itself.

Directory-entry operations need a writable parent directory, so their
resource candidate is that parent. An `open` with `O_CREAT` uses the parent
only when the leaf is absent; existing files and ordinary metadata writes retain
the exact file path. Metadata calls that do not follow a final symlink resolve
the symlink entry instead of its target and request the parent when the entry
is a symlink. The original denied path remains diagnostic, and a path in a
configured `denyWrite` carve-out still suppresses sandbox widening.

On Linux, an observer path is a candidate resource, not an authoritative
kernel-denied resource. The candidate can be canonicalized on the host and
proposed as a `SandboxCapabilityGrant`, because enforcement remains in the
widened sandbox.

For host replay, an observed candidate is explanatory only. Approval authority
is `CommandIdentity`; no observed path becomes a host resource permission.
This preserves the contract without claiming Linux and macOS provide identical
internal telemetry.

## 12. Credential / redaction model

Credentials may remain usable by local tools and processes, including normal
credential helpers. Model-visible bash tool output is passed through
`@spences10/pi-redact` before it reaches Pi's model context.

This is model-boundary redaction, not filesystem-level credential secrecy from a
local process. The extension does not claim to prevent a locally executing tool
from accessing credentials it is otherwise authorized to use.

## 13. Trusted Skill helpers

Skill trust comes from the Skill authority supplied by `@spences10/pi-skills`;
path naming alone does not establish trust. Only a pure, single helper
invocation can receive special trusted execution treatment. Its helper path
must resolve under the active Skill's declared canonical helper root, preventing
symlink and path escape. Compound shell expressions do not inherit helper trust.

## 14. Security invariants

- Sandbox success never prompts, and ordinary sandbox failure never replays on
  host.
- A stored host grant still follows sandbox first:

  ```text
  try sandbox → success: done
              → ordinary failure: done
              → violation + matching host grant: host replay
  ```

- Stored host grants never skip directly to host.
- Resource grants authorize sandbox widening only; host grants authorize exact
  host replay only.
- Canonical resources and canonical cwd are used for reusable grant matching.
- Native mutation authorization is complete before the native operation begins.

## 15. Fail-closed behavior

Sandbox initialization or wrapping failure returns a sandbox-unavailable result
and does not run the host command. Missing UI, missing eligible grant, malformed
persistent grant data, unavailable project identity, and persistent-store write
failure deny the relevant reusable authorization. Unknown or unapproved
violations do not receive implicit host fallback.

When available error details identify Bubblewrap, AppArmor/user-namespace
policy, or a nested-userns/seccomp restriction, the unavailable
result describes that class and the relevant operator action. Diagnostics do
not weaken or choose the security boundary.

## 16. Non-goals / current limitations

- This project is early development software; its APIs, persistence formats,
  platform behavior, and approval semantics may change before 1.0.
- It does not make Linux and macOS telemetry implementation-identical.
- It does not treat observed Linux paths as authoritative kernel-denial claims.
- It does not provide filesystem-level secrecy for credentials accessible to a
  local process.
- It does not broaden native write/edit to host execution.
- It does not implement command-prefix or executable-name allowlists for host
  execution.

## 17. Filesystem configuration

The configuration path is `<Pi agent directory>/pi-selective-sandbox/config.json`:

```json
{
  "filesystem": {
    "extraWritableRoots": ["~/.cache/uv"],
    "disabledDefaultProfiles": ["cargo-cache"]
  }
}
```

The built-in profiles are `workspace`, `tmp`, `cargo-cache`, and `runtime-home`. Extra writable
roots widen only the sandbox filesystem policy. They never grant host replay.
A missing configuration file uses defaults. An existing malformed file,
invalid field, or unknown disabled profile is reported diagnostically and
produces a deny-by-default caller write policy. Replacement tools are still
registered, so invalid configuration cannot restore Pi's unsandboxed tools.
