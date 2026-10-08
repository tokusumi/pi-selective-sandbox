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

Sandbox enforcement starts enabled. The user command `/selective-sandbox off`
explicitly disables enforcement for all three tools until extensions are reloaded
with Pi's `/reload` command, Pi restarts, or the user runs `/selective-sandbox on`.
While disabled, bash executes directly on the host with output
redaction, and native write/edit skip boundary checks and approvals. This mode
is not a grant and is not persisted. Missing or unsupported arguments display
usage without changing the mode. The sandbox-first and fail-closed contracts
below apply while enforcement is enabled.

On macOS only, an explicitly `false` SDK initialization flag
`enableLogMonitor` forces enforcement off for all three tools before an enabled
tool executes. A warning must state that bash will run on the host and native
mutation approvals will be bypassed. `/selective-sandbox on` cannot override
this condition; the SDK flag must be restored and the extension reloaded. This
condition is the flag value only: initialization errors or monitor-process
failures do not by themselves trigger automatic off.

- `bash` is a subprocess execution surface. Normal commands are wrapped by the
  OS sandbox runtime before the command runner starts them.
- `write` and `edit` are native in-process Pi tools. They enforce an explicit,
  canonical filesystem boundary before invoking the native tool.
- The resolved default write policy permits the extension startup working
  directory, `/tmp`, and the Cargo home (`$CARGO_HOME`, otherwise `~/.cargo`).
  Within Cargo home, `bin`, `config`, `config.toml`, `credentials`,
  `credentials.toml`, and `env` are denied. Deny rules take precedence.
- For bash, when the startup working directory is writable under that policy,
  a write violation within Git metadata offers the shared Git directory and
  the worktree's Git directory only if it lies outside the shared one. This covers
  index, object, ref, reflog, tag, and worktree metadata writes in linked
  worktrees. The prompt names the shared grant's impact on other worktrees,
  Git configuration, and hooks. Git paths are discovered once at startup; configured
  denies still take precedence, and this does not extend native `write` or
  `edit` permissions.
- A pure `git worktree remove` targeting a registered worktree outside writable
  roots offers the target's parent directory for one-time sandbox approval. Removing a
  directory requires parent write access, and mounting the target directory
  itself would prevent removal. Parent and child candidates are collapsed;
  session and project resource grants are not offered for this broad parent.
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

Grant identities are exact. A grant does not implicitly substitute a parent
directory, different resource, different capability, different project, command
prefix, tool name, or executable-name match. The user may explicitly choose an
ancestor directory for bash widening; that directory is the granted resource.
Inside the sandbox, a directory write grant permits writes beneath it, subject
to existing deny rules. Native write/edit approvals continue to match exact
canonical targets rather than inheriting ancestor grants.

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
   canonical capability resource. If the retry exposes another blocked write,
   request a separate approval for the newly observed resource and retry with
   the accumulated grants. Stop when the command finishes, the failure has no
   new candidate, approval is denied, or the retry limit is reached.
8. A host-command response replays the exact command on the host.

### Resource approval interaction

For supported write candidates, interactive TUI approval separates the observed
blocked targets from the initial capability scopes (including prepared Git and
directory-entry scopes), the selected write scopes, duration, and command.
The initial selection is each prepared scope and `Once`. The user can choose
that scope or any canonical ancestor up to `/`; there is no HOME-specific limit
and no free-form path input. Each scope gets its own selection when several are
required. The full selected path remains visible even when a candidate row is
truncated. Directory choices explain that descendants are writable, and `/`
requires a visible whole-filesystem warning. Existing configured and SDK deny
rules remain in force. Parents of shared Git metadata retain once-only scope.

Only final `Allow and retry` confirmation grants access. Eligible durations are
`Once`, `This session`, and `This project`; selecting a scope can remove reusable
durations. Tab/Shift+Tab change fields, arrows select, Enter continues or
confirms, and Escape denies. Cancellation or an aborted tool must not create a
new approval. RPC uses built-in sequential scope, duration, and confirmation
selectors; print/JSON modes must not acquire authority by lack of UI.

Before persistence and retry, selected scopes must be write capabilities from
the initial scopes' ancestor chains, cover every required scope, and retain
their canonical identities. Unrelated paths, omitted scopes, changed symlink
identities, and ineligible durations deny the request. Approved overlapping
write scopes can be collapsed to the expressly selected outer ancestor. Only
those selected scopes are stored and applied to the sandbox retry. A repeated
write denial already beneath an applied grant does not request the same
ineffective widening again. Storage identity matching remains exact.

Host replay is a separate `Run outside sandbox…` action with its own duration
and final exact-command confirmation, displaying command, canonical cwd and
execution mode when available. It never turns a resource choice into host
authority. Unsupported violations and configured-deny intersections offer no
resource selection, but can offer that separate host confirmation. Both retry
paths warn that the entire command runs again and can repeat earlier effects.
Native write/edit retain exact-target preflight approval, without this ancestor
selection or host action.

All attempts may remain visible in the streamed execution transcript. Before
requesting approval for a detected violation, the extension streams
`<sandbox: approval-required filesystem.write>` (or the detected capability
kind). Approval then streams `<sandbox: approved widen retry>`,
`<sandbox: approved host-replay>`, or `<sandbox: approval-denied>`. An approved
attempt ends with `<sandbox: retry exit=N>` or `<sandbox: replay exit=N>`.
Only the final selected attempt determines the tool exit code; denial retains
the latest sandbox exit code. Ordinary failures and sandbox successes have no
status marker.

The command has already been attempted before a replay choice; each retry can
repeat side effects permitted before the violation. A command with a write on
each pass may run several times, with explicit approval for each new resource
and a limit of 16 sandbox approvals. Resource approval does not classify
destructive intent: commands such as `git clean -fd` can change files entirely
inside writable roots without prompting. Trusted pure Skill helpers
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
include filesystem read, filesystem write, and network. UI widening supports
reported filesystem-write candidates and, on macOS, proxy-observed network
allowlist denials with a canonical exact `host:port` resource (bracketed IPv6).
Network grants do not imply other ports, subdomains, URLs, filesystem access,
or host replay. Raw Seatbelt socket/IP denials, malformed endpoints, and
resolved-address protection failures do not offer network widening. Network
isolation, allowlist permissions, and network widening are macOS-only features.
Linux does not consume or offer network capability grants; no Linux network
isolation guarantee is part of the supported contract. The grant is consumed
only as extra sandbox capability configuration.

Every macOS sandbox attempt uses an authenticated, per-invocation HTTP/SOCKS
proxy with immutable startup allowances plus that attempt's approved endpoints.
Seatbelt permits only that proxy's loopback port, not direct destination access.
Neither global SDK config updates nor client-supplied attribution IDs authorize
network access. Concurrent attempts cannot inherit each other's approvals. The
proxy and open connections are closed after the attempt (including failure,
cancellation, wrapping failure, and before approval); a once grant is absent on
the next operation. Background descendants lose this proxy when the attempt
finishes. SDK resolved-address guards remain enforced: a hostname approval does
not bypass DNS-rebinding/private-address protection. The proxies preserve SDK
upstream proxy resolution (explicit SDK configuration, otherwise HTTP_PROXY /
HTTPS_PROXY and NO_PROXY), with the destination allowlist checked before routing.

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

1. canonical Git base directory, when Git can provide one (the first entry from
   `git worktree list --porcelain -z`); normally this is the main worktree
   directory, shared by linked worktrees. For bare repositories and
   `--separate-git-dir` layouts, Git reports the repository metadata directory
   as the base instead;
2. otherwise, canonical startup cwd.

If neither path can be canonicalized, project persistence is unavailable.
Project identity is distinct from the extension startup working directory used as
the default writable root. Changing directories later does not change the
identity. Project grants are shared across the main and linked worktrees, but
capability resources and host command cwd remain exact canonical paths; sharing
project identity does not make a host command approved in one cwd eligible in
another. Moving or cloning a repository does not inherit its project grants.
Previously stored grants keyed to an individual linked worktree are not migrated
to the base identity; approve them again for the shared project if needed.

## 11. Linux telemetry semantics

### Platform capabilities

| Platform | Filesystem | Network isolation | Unix sockets | Fail closed |
| --- | --- | --- | --- | --- |
| macOS | Isolated | Isolated | Isolated | Yes |
| Other Linux | Isolated | Not supported | Isolated | Yes |
| Ubuntu | Isolated | Not supported | Unrestricted | Yes |

Ubuntu is detected from `ID=ubuntu` in `/etc/os-release`, regardless of version,
and uses `network.allowAllUnixSockets: true`. The tested Ubuntu 24.04 host's
AppArmor policy allows the outer Bubblewrap sandbox while blocking the nested
user namespace used by the runtime's seccomp-based Unix-socket isolation.
This execution mode does not change filesystem permissions, violation handling,
filesystem sandbox widening, or the approval model. It is not host replay;
filesystem sandboxing continues inside Bubblewrap. Network isolation is supported
only on macOS, not Linux.

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

## 17. Filesystem and network configuration

The configuration path is `<Pi agent directory>/pi-selective-sandbox/config.json`:

```json
{
  "filesystem": {
    "extraWritableRoots": ["~/.cache/uv"],
    "disabledDefaultProfiles": ["cargo-cache"]
  },
  "network": {
    "extraAllowedDomains": ["packages.example.com:443"],
    "disabledDefaultProfiles": []
  }
}
```

The built-in filesystem profiles are `workspace`, `tmp`, `cargo-cache`, and `runtime-home`. Extra writable
roots widen only the sandbox filesystem policy. They never grant host replay.
A missing configuration file uses defaults. An existing malformed file,
invalid field, or unknown disabled profile is reported diagnostically and
produces a deny-by-default caller write policy and an empty network allowlist.
Replacement tools are still registered, so invalid configuration cannot restore
Pi's unsandboxed tools.

Network defaults apply to macOS network isolation and have four profiles:

| Profile | Allowed patterns |
| --- | --- |
| `git` | `api.github.com`, `github.com`, `*.github.com`, `gitlab.com:443`, `bitbucket.org:443`, `raw.githubusercontent.com:443`, `objects.githubusercontent.com:443`, `release-assets.githubusercontent.com:443` |
| `node` | `registry.npmjs.org:443`, `registry.yarnpkg.com:443`, `nodejs.org:443`, `get.pnpm.io:443` |
| `rust` | `crates.io:443`, `index.crates.io:443`, `static.crates.io:443`, `static.rust-lang.org:443`, `sh.rustup.rs:443` |
| `python` | `pypi.org:443`, `files.pythonhosted.org:443`, `python.org:443`, `www.python.org:443`, `astral.sh:443` |

All four profiles are enabled unless named in `network.disabledDefaultProfiles`.
Filesystem and network profile disable lists are independent. Unknown names or
invalid fields fail closed. Disabling all four yields no default network
allowances; explicit additions and capability grants may still authorize their
resources. Disabling a profile removes baseline allowances, not a deny rule.
Profiles authorize destinations for all sandboxed commands, not executable-name
matches. They cover common package/toolchain routes, not arbitrary mirrors or
shared redirect CDNs. New defaults are HTTPS/443-only; the pre-existing GitHub
patterns retain their original all-port semantics.

Optional `network.extraAllowedDomains` adds to the enabled defaults. The resolved
list is deduplicated. Patterns use the SDK's domain/IP syntax: an exact host or `*.example.com`,
optionally with a port in 1–65535; IPv6 literals must be bracketed. No port means
all TCP ports for that host. URLs, paths, control characters, bare `*`, and overly
broad wildcard suffixes are rejected. Patterns are canonicalized and deduplicated.
These allowances never authorize host execution. Network widening is for clients
using the sandbox HTTP/CONNECT or authenticated SOCKS proxy, not direct TCP/UDP.
The SDK sets NO_PROXY for loopback/private networks; clients targeting an explicitly
allowed local endpoint must opt into the proxy (for example, curl `--noproxy ''`).
