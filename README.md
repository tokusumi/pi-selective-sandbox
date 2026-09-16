# pi-selective-sandbox

Sandbox-first execution for Pi: normal commands run in an OS sandbox before
any escalation decision. A non-zero exit code is returned normally; only a
sandbox violation attributed to the specific tool call can enter escalation.

## Guarantees in this MVP

- Sandboxed success and ordinary failure never prompt for approval.
- Sandbox unavailability fails closed; there is no implicit host fallback.
- Escalation uses resource/capability policy decisions (`deny`, `ask`, or
  `auto-escalate`), not executable allowlists. Generic commands that already
  ran in the sandbox still require explicit replay approval; silent automatic
  replay is reserved for future live-widening support.
- Approval requests include the tool-call ID, command digest, requested
  capabilities, and an explicit replay warning.
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


## Current limits

- Bash execution is enforced by the OS sandbox runtime. `write` and `edit` enforce the same writable roots with a canonical, symlink-safe tool-layer boundary because they execute inside Pi rather than a sandboxed subprocess.
- macOS violation telemetry can drive filesystem approval escalation. On Linux,
  sandbox enforcement still blocks disallowed filesystem access, but the
  runtime does not yet provide automatic filesystem-violation telemetry, so
  those failures are returned normally rather than prompting speculatively.

## Development

```sh
npm install
npm test
```
