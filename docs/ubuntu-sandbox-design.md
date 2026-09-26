# Ubuntu sandbox design decision

Status: Accepted  
Scope: Linux/Ubuntu execution path in `pi-selective-sandbox`

## Decision

On the target Ubuntu environment, `pi-selective-sandbox` uses Bubblewrap as the sandbox enforcement layer with:

```text
allowAllUnixSockets = true
```

Unix-domain-socket isolation is therefore not provided on this Ubuntu path. This is an accepted limitation and is not a target of the current design.

Filesystem-write violation observation must be provided independently of `apply-seccomp`. On Ubuntu, `strace` is the primary filesystem observation backend for this execution mode, not a fallback from an otherwise expected `apply-seccomp` observer.

The security and approval model remains:

```text
enforcement          = Bubblewrap
filesystem observer  = strace
policy               = WritePolicy / MutationBoundary
authorization        = explicit approval
  - sandbox widening = resource-scoped
  - host replay      = exact-command-scoped
```

Observation never authorizes execution by itself.

## Why this execution mode exists

### Bubblewrap enforcement works without `apply-seccomp`

On the target Ubuntu host, Bubblewrap successfully enforces filesystem restrictions when `allowAllUnixSockets=true`.

Observed result:

```text
touch <blocked-path>/probe
→ Read-only file system
→ exitCode 1
```

This confirms that filesystem enforcement does not depend on the filesystem observer.

Upstream architecture also separates Linux filesystem/network namespace isolation from the inner `apply-seccomp` helper. Bubblewrap creates the outer filesystem, PID, and network namespaces; `apply-seccomp` is invoked later inside that sandbox.

References:

- Anthropic Sandbox Runtime Linux architecture:
  https://github.com/anthropics/sandbox-runtime/blob/main/README.md
- Linux sandbox construction:
  https://github.com/anthropics/sandbox-runtime/blob/main/src/sandbox/linux-sandbox-utils.ts

### `apply-seccomp` is not viable on the target Ubuntu host

With `allowAllUnixSockets=false`, the target host fails before the workload starts:

```text
apply-seccomp: write /proc/self/setgroups
(nested userns is capability-restricted;
caller must provide CAP_SYS_ADMIN):
Permission denied
```

The relevant limitation is not reducible to "Ubuntu AppArmor is enabled". Upstream reports the same class of failure even when unprivileged-user-namespace restrictions are relaxed, because Bubblewrap / host policy can still leave the child unable to create the nested namespace with the capabilities required by `apply-seccomp`.

References:

- sandbox-runtime issue #428:
  https://github.com/anthropics/sandbox-runtime/issues/428
- sandbox-runtime issue #429:
  https://github.com/anthropics/sandbox-runtime/issues/429
- `apply-seccomp` explicitly creates a nested user/PID/mount namespace and fails closed if setup cannot be completed:
  https://github.com/anthropics/sandbox-runtime/blob/main/vendor/seccomp-src/apply-seccomp.c

Because this project has already accepted that Unix-domain-socket isolation is unavailable on the target Ubuntu execution path, restoring `apply-seccomp` by changing host security policy is not a design goal.

## What is lost when `allowAllUnixSockets=true`

The setting causes sandbox-runtime to skip the `apply-seccomp` path.

Two independent capabilities of `apply-seccomp` are therefore lost:

1. Unix-domain-socket creation blocking.
2. Passive filesystem write-intent observation using seccomp USER_NOTIF.

The first is an accepted Ubuntu limitation.

The second is not acceptable for `pi-selective-sandbox`, because approval depends on distinguishing an ordinary command failure from a sandbox-caused failure.

Upstream references:

- `allowAllUnixSockets` disables Unix-socket blocking:
  https://github.com/anthropics/sandbox-runtime/blob/main/src/sandbox/sandbox-config.ts
- Linux skips `apply-seccomp` when Unix-socket blocking is disabled:
  https://github.com/anthropics/sandbox-runtime/blob/main/src/sandbox/linux-sandbox-utils.ts
- Filesystem observation is implemented in `apply-seccomp` using seccomp USER_NOTIF:
  https://github.com/anthropics/sandbox-runtime/blob/main/vendor/seccomp-src/apply-seccomp.c

## Why an independent filesystem observer is required

The executor intentionally does not escalate on non-zero exit status alone.

Required invariant:

```text
sandbox command fails
  ↓
attributed sandbox violation exists?
  ├─ no  → ordinary failure
  └─ yes → approval flow
```

Without an observer, a denied write looks like:

```text
git add
→ Bubblewrap returns EROFS for .git/index.lock
→ sandbox-runtime violations = []
→ ordinary failure
→ no approval
→ no sandbox widening / host replay
```

Parsing user-visible stderr is not an acceptable substitute because arbitrary commands can emit the same strings and ordinary Unix permission failures must not become sandbox authorization prompts.

Therefore the Ubuntu execution mode requires an observer that is independent of `apply-seccomp`.

## Why `strace`

The project evaluated an independent syscall observer instead of inventing a ptrace implementation.

The production topology in PR #11 is:

```text
strace
  └─ Bubblewrap
       └─ user command and descendants
```

An earlier experiment also proved that tracing from inside Bubblewrap can observe the denied workload syscall. PR #11 deliberately uses the outer topology instead because it keeps the trace stream on a parent-owned pipe that the sandboxed workload cannot rewrite.

Tracing Bubblewrap from the outside also exposes Bubblewrap setup syscalls, so the observer must attribute only the workload process tree and ignore setup activity. This attribution rule is part of the correctness boundary of the observer; path-based exclusions such as `/newroot` are only defense in depth and must not substitute for process attribution.

On the target Ubuntu host, a blocked Git write was observed as:

```text
openat(
  ...,
  ".git/index.lock",
  O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,
  0666
) = -1 EROFS
```

The write-intent syscall model should follow sandbox-runtime's existing `observe_calls[]` table rather than define an independent semantic model.

Reference:

- Upstream write-intent syscall table:
  https://github.com/anthropics/sandbox-runtime/blob/main/vendor/seccomp-src/apply-seccomp.c

## Security boundary

`strace` is telemetry only.

It does not:

- enforce filesystem permissions,
- widen the sandbox,
- authorize host execution,
- convert a resource approval into host authority.

The decision pipeline is:

```text
strace observation
  ↓
write-intent classification
  ↓
existing WritePolicy / MutationBoundary check
  ↓
SandboxViolation
  ↓
existing approval flow
  ├─ sandbox widening
  └─ exact-command host replay
```

Bubblewrap remains the enforcement authority.

This matches upstream's treatment of Linux filesystem observation as diagnostic, attacker-controlled, best-effort telemetry rather than an enforcement boundary.

Reference:

- Linux violation monitor trust model:
  https://github.com/anthropics/sandbox-runtime/blob/main/src/sandbox/linux-violation-monitor.ts

## Network security properties on Ubuntu

`allowAllUnixSockets=true` does not remove Bubblewrap's network namespace.

The Ubuntu path still relies on Bubblewrap `--unshare-net` and the sandbox-runtime proxy architecture for ordinary network isolation and domain filtering.

What is specifically unavailable is Unix-domain-socket isolation.

Therefore the accepted Ubuntu properties are:

| Property | Ubuntu path |
| --- | --- |
| Filesystem enforcement | Bubblewrap |
| PID / outer namespace isolation | Bubblewrap |
| Network namespace isolation | Bubblewrap `--unshare-net` |
| Proxy/domain filtering | sandbox-runtime |
| Unix-domain-socket isolation | Not provided; accepted limitation |
| Filesystem violation observation | strace |
| Authorization | pi-selective-sandbox approval model |

References:

- Network isolation architecture:
  https://github.com/anthropics/sandbox-runtime/blob/main/README.md
- Linux `--unshare-net` implementation:
  https://github.com/anthropics/sandbox-runtime/blob/main/src/sandbox/linux-sandbox-utils.ts

## Approval semantics remain unchanged

The observer does not change authorization semantics.

### Sandbox widening

A resource approval only adds write capability to a subsequent Bubblewrap execution.

It never permits host execution.

### Host replay

Host replay is approved against an exact command identity:

```text
shell command
canonical cwd
execution mode
```

A path observed by `strace` is explanatory context only and never becomes a host resource permission.

### Ordinary failure

If no correlated filesystem violation is available, the failed command is returned as an ordinary sandbox failure.

No speculative escalation is allowed.

## Non-goals

This design does not attempt to:

- restore Unix-domain-socket isolation on the target Ubuntu host,
- make `apply-seccomp` work by weakening host security policy,
- treat `strace` as a policy or enforcement engine,
- parse stderr to infer sandbox violations,
- special-case Git, Cargo, Python, Node, or other applications,
- escalate every `EACCES`, `EPERM`, or non-zero exit code,
- automatically replay failed commands on the host.

## Implementation consequence

For the accepted Ubuntu path, terminology should reflect the architecture:

- `strace` is the Ubuntu filesystem observation backend.
- It should not be described as a temporary or exceptional "fallback" from an observer that this project expects to use on the same target host.
- OS/runtime selection and approval semantics should remain separate concerns.

The implementation should therefore be reviewed against these invariants rather than against a goal of eventually restoring `apply-seccomp` on Ubuntu.
