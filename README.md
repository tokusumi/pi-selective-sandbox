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

## Development

```sh
npm install
npm test
```
