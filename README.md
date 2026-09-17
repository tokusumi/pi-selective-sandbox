# pi-selective-sandbox

Sandbox-first execution for Pi: normal commands run in an OS sandbox before
any escalation decision. A non-zero exit code is returned normally; only a
sandbox violation attributed to the specific tool call can enter escalation.

## Core guarantees

- Sandboxed success and ordinary failure never prompt for approval.
- Sandbox unavailability fails closed; there is no implicit host fallback.
- Escalation uses resource/capability policy decisions (`deny`, `ask`, or
  `auto-escalate`), not executable allowlists. Generic commands that already
  ran in the sandbox still require explicit replay approval; silent automatic
  replay is reserved for future live-widening support.
- Approval requests include the tool-call ID, command digest, requested
  capabilities, and an explicit replay warning.
- **Allow once** approves only the exact current operation. **Allow for session**
  remembers the exact capability/resource for the current Pi session, in memory.
  applies to preflight `write`/`edit` and to future bash sandbox policies; it
  never grants a parent directory or a different target.
- Trusted Skill helpers are identified through an injected `pi-skills`
  authority and canonical paths. Only a pure, single helper invocation can
  use configured automatic trusted execution, and only from that Skill's
  declared helper roots (default: `scripts/`).
- A supplied redactor processes stdout and stderr before the execution result
  is returned to the Pi integration.

`SandboxRuntime` and `CommandRunner` are interfaces so an adapter can bind
`@anthropic-ai/sandbox-runtime`'s command IDs and violation APIs to the
extension without treating its policy as a suggestion. The package does not
maintain a parallel Skill trust database or implement its own secret detector.

## Pi integration

This repository provides a Pi extension. Install it with Pi's normal package
installer, then restart Pi:

```sh
pi install git:github.com/tokusumi/pi-selective-sandbox
```

The extension replaces Pi's `bash`, `write`, and `edit` tools. `bash` initializes
`@anthropic-ai/sandbox-runtime` with project and `/tmp` write access, broad
reads, and GitHub API access for authenticated `gh` use. If initialization
fails, bash reports the unavailable sandbox and never falls back to host
execution.

`@spences10/pi-skills` supplies active trusted Skill roots at execution time.
Only pure helpers below each `scripts/` root receive automatic privileged
execution. `@spences10/pi-redact` is applied to streamed and returned bash
output before Pi makes the tool result model-visible. `write` and `edit` are in-process Pi tools, so they use an explicit canonical filesystem boundary instead: mutations in the project or configured `/tmp` root proceed normally; mutations outside those roots require one-time approval before any file-content read, directory creation, or write side effect.

For an outside-root `write` or `edit`, **Allow for session** remembers the exact
canonical `filesystem.write` target for this Pi session. The same canonical file
can then be written or edited without another prompt, even if the content or edit
replacement changes. Bash consumes stored session and project filesystem grants
before its initial sandbox attempt, so future commands run with the base policy
plus exactly those canonical resources.


## Approval authority matrix

| Approval | Authority | Execution | Once | Session | Project |
| --- | --- | --- | --- | --- | --- |
| Sandbox widening | capability + resource | sandbox | ✓ | ✓ | ✓ |
| Host replay | exact command identity | host | ✓ | ✓ | ✓ |

Approving a resource never approves leaving the sandbox. Approving host execution
never grants a resource capability.

A reusable host grant contains only the exact shell command string, canonical
working directory, and execution mode. It is never keyed by an observed
violation resource, executable prefix, environment, or command name. When cwd
cannot be canonicalized, only **Run command on host once** is offered.

A stored host-command grant still tries the sandbox first. It only suppresses
the repeated host-replay prompt when that exact command encounters a sandbox
violation again. A sandbox success or ordinary sandbox failure is returned
without host execution. `write` and `edit` remain capability-only tools and
never offer host execution.

## Current limits

- Bash execution is enforced by the OS sandbox runtime. `write` and `edit` enforce the same writable roots with a canonical, symlink-safe tool-layer boundary because they execute inside Pi rather than a sandboxed subprocess.
- Linux observer paths are candidate filesystem resources, not authoritative
  kernel-denial claims. Candidates are canonicalized on the host before an
  explicit sandbox-widening decision; the sandbox remains the enforcement
  authority.

## Development

```sh
npm install
npm test
```


## Persistent project approvals

For eligible outside-root write and edit preflight requests:

- **Allow once** permits only the current operation.
- **Allow for session** permits the exact capability/resource for the current Pi session, in memory.
- **Allow for project** persists the exact capability/resource for this canonical local project across Pi sessions.

The project identity is the canonical Git worktree root when available; otherwise it is the canonical startup directory. It is resolved once at extension startup, so later directory changes do not switch permissions. Moving or cloning a repository does not inherit grants.

Pi's exported agent-directory convention is used for user-local state:
/pi-selective-sandbox/project-grants.json, or
~/.pi/agent/pi-selective-sandbox/project-grants.json by default. The file is
versioned JSON; deleting it clears persistent approvals.

Project grants are exact canonical resource capabilities. They never imply a
directory wildcard, subtree, other capability, other project, command prefix, or
tool-name permission. Bash consumes these grants as sandbox configuration before
execution; they never authorize host execution.
