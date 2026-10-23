# Follow-up draft: address the unpatched node-forge signature verification vulnerability

## Background

Dependency maintenance in ISSUE-okiiy7hhjt removed the vulnerable
`brace-expansion@5.0.9` and `undici@8.9.0` installed by Pi 0.85.1 by updating the
three development Pi packages together to 1.4.0 and requiring host Pi peers
`>=1.4.0`. The [installed-update checks](dependency-update-verification.md)
confirmed both Git dependency-install paths also remove those vulnerable
entries; updating the extension does not upgrade the host Pi itself.

A separate advisory now affects the sandbox SDK's current dependency:

- Advisory: [GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv)
- Title: node-forge RSA PKCS#1 v1.5 signature verification accepts extra nested
  DigestAlgorithm elements
- Installed chain: `@anthropic-ai/sandbox-runtime@0.0.76` → `node-forge@1.4.0`
- Affected range: `<=1.4.0`; latest published node-forge at investigation: `1.4.0`
- npm reports two high-severity entries for this single chain (node-forge and
  its direct dependent, sandbox-runtime).

The latest sandbox-runtime, 0.0.81, still declares `node-forge: ^1.4.0`.
`npm audit fix --force` instead proposes sandbox-runtime 0.0.50, which is
incompatible with this repository's pinned, hash-verified 0.0.76 telemetry patch.
Do not downgrade the SDK, suppress the audit, or disable patch verification to
make the report disappear.

## Reproduction

```sh
npm ci
npm audit
npm ls node-forge
npm view node-forge version
```

## Proposed work and acceptance criteria

1. Track a published node-forge security fix or a sandbox-runtime release that
   removes the affected dependency.
2. Update the dependency and lockfile. If changing sandbox-runtime, review and
   port the existing patch and its hash checks rather than bypassing them.
3. Verify fresh `npm ci`, `npm run check`, `npm test`, SDK patch installation,
   and native macOS sandbox tests from a supported host runner.
4. Confirm `npm audit` no longer reports this advisory; remove this draft and
   its README caveat once resolved.
