# Security risks of the default macOS Mach service allowances

Every macOS sandbox attempt permits lookup of `com.apple.sysmond` and
`com.apple.FSEvents`, in addition to the existing certificate service
`com.apple.trustd.agent`. These are exact service names, not a Mach wildcard.
The allowances apply to every command and descendant, not only to `pgrep` or
Node watchers. Disabling network destination profiles or local binding does not
remove them.

## Host information disclosure

- **sysmond:** Apple-entitled clients such as native `pgrep` can obtain host
  process information. There is no sandbox-local PID namespace. Process names,
  identities and activity can reveal information about unrelated host work.
  The daemon checks `com.apple.sysmond.client`; lookup permission does not grant
  that entitlement, but sandboxed commands can invoke entitled system tools.
- **FSEvents:** notifications expose filesystem paths and change activity,
  potentially including historical events. They are not restricted to directories
  writable by the command. The daemon's filesystem-permission, sandbox and other
  OS checks remain separate controls; lookup is not a directory-scoped grant.
  See Apple's [File System Event Security guide](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/FileSystemEventSecurity/FileSystemEventSecurity.html).

A write boundary is not an information-confidentiality boundary. These defaults
must not be represented as isolating host process metadata or filesystem activity.

## Daemon-mediated writes and root execution

FSEvents is **not an entirely read-only service**. Its public
`FSEventsPurgeEventsForDeviceUpToEventId` API removes records from the persistent
per-volume event database. Apple's `FSEvents.h` specifies that it is root-only;
the macOS 26.7 daemon also checks the kernel-supplied sender UID before entering
the purge implementation.

An ordinary non-root caller does not acquire root authority from Mach lookup.
However, **root-run Pi can reach this root-only mutation API**. The daemon's UID
check is not the caller's path-scoped Seatbelt write policy: event history outside
the allowed write roots can be removed through the daemon. Do not rely on the
filesystem sandbox alone to prohibit that operation. Run Pi as an ordinary user;
root execution requires a separate security assessment.

The daemon also maintains its own OS event logs outside the command's writable
roots. Direct file-write deny rules remain in force, but they are not a guarantee
that a trusted service performs no writes on the caller's behalf.

## Trusted OS service attack surface

Lookup enables IPC with privileged host daemons. Their request validation,
entitlement/UID checks and implementations are part of the trusted boundary.
A confused-deputy or memory-safety defect could expose authority beyond direct
sandbox syscalls. Testing ordinary writes, native process listing and event
notifications does not prove the absence of RPC vulnerabilities or all indirect
write paths. Private interfaces and access checks can also change across macOS
versions; observations from macOS 26.7 are not a permanent guarantee.

The exact service allowances do not themselves permit arbitrary Mach services,
all Unix sockets, unrestricted external networking or host-command execution.
Those restrictions reduce exposure but do not eliminate the service-specific
risks above.
