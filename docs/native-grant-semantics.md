# Native approval scope decision (ISSUE-ikmfkxxkcq)

## Decision

Retain native write/edit **exact canonical target** matching. Improve the native
prompt, bash TUI/sequential confirmation, README and SPEC rather than silently
making saved directory scopes authorize native descendants. No grant migration,
store format change, host replay change or capability expansion is introduced.

## Evidence and alternatives

At baseline `b8d0882`:

- `src/mutation-tools.ts` resolves the canonical native target, rejects configured
  denies first, and requests exactly that filesystem-write capability before the
  native tool can read content or mutate anything.
- The native branch of `createApprovalProvider` in `src/pi-extension.ts` uses
  `SessionGrantStore.covers` / `ProjectGrantStore.covers`. Both match exact
  capability keys (`src/capability-key.ts`).
- Bash obtains those same stores' `capabilities` in `src/pi-extension.ts`, applies
  them at sandbox startup, and uses `pathContains` for covered write candidates
  in `src/executor.ts`. A saved parent scope **does work for later bash writes**.
- SPEC sections 4–6 explicitly prescribe this difference. The previous prompt
  said grants were exact, but did not directly explain the cross-surface case.

Two credible alternatives were considered:

1. Add explicit, typed directory grants for native operations. This can reduce
   prompts, but needs new provenance/persistence and compatibility rules plus
   native directory-scope selection and validation. Existing grants only contain
   kind + resource; statting a stored path today cannot establish what was
   approved historically (a leaf may have become a directory).
2. Preserve exact native authority and explain the difference where users approve
   access. Chosen because it addresses the confusing re-prompt without changing
   existing authority or inferring user intent from untyped historical paths.

A blanket ancestor-based `covers` change is rejected: it would broaden existing
native approvals, not merely fix failed persistence. Old leaf grants are not
promoted to native parents, siblings or descendants. Bash's existing directory
application semantics are unchanged.

The original investigation's source/store reproduction was read from
`ISSUE-9plwyrfb7e/investigation/usage-audit/reproduce-grant-semantics.mjs`.
It corroborates exact lookup and the baseline's startup-cache behavior, not
historical UI screens. Main's subsequently merged Project-grant freshness fix
(PR #37) removes that cache: each lookup/new bash invocation reads disk. Past
real UI display history remains unverified and is not needed for this decision.

## Expected reuse

| Stored resource | Bash | Native write/edit |
| --- | --- | --- |
| Explicit bash directory | Descendants within sandbox; deny rules remain | Exact target only, not child files |
| Exact file from either surface | Applied as that sandbox capability | Same canonical file only, shared by write/edit |
| Once | Current operation only | Current operation only |
| Session | Owning session only; lost on reload | Same ownership and lifetime |
| Project | Same project identity; fresh disk read per invocation | Same project identity; fresh disk read per lookup |

Different files and changed canonical symlink targets require native approval.
Child Session approvals are not parent/sibling approvals. Project sharing is
intentional, including linked worktrees. Completed, quiescent persisted removals
are reflected in the next lookup/new bash invocation without reload, including
existing providers. This does not cancel in-flight operations or serialize
concurrent grant writers; SPEC section 10 describes those limits.
A sandbox capability does not guarantee that an OS operation will succeed (for
example, creating an entry may need its parent); it never authorizes host replay.

Configured denies still reject native targets before lookup/UI. Canonicalization,
selection revalidation, Git broad-parent once-only restrictions and the private
approvals-root deny remain unchanged.

## Review and validation

Parent-supervised council: fallback profiles `oracle` (forked, context-aware) and
`reviewer` (runtime-default context unknown). One independent pass, two completed
reports, agreement on exact-target retention, no material dispute needing a second
pass. Workflow `f40e4222-3312-4d13-b538-9ede7e80f4f1`; child runs
`6c9fac73-086f-4d9d-8c95-4294df53461b` and
`ddb76f97-44c6-44d4-97b5-a59772bcf6d7`.

Accepted: preserve exact store identities; explain both surfaces; test actual
cross-surface wiring. Rejected: the reviewer's assumption that the overall task
requested advice only; this issue also requires implementation and validation.
No unresolved owner decision remains for this conservative option. Confidence is
high based on source and the inherited contract. Mandatory directory reuse plus
an explicit versioned grant design would justify reconsidering the decision.

`src/test/cross-surface-grants.test.ts` exercises registered extension tools, real
providers, real session/project stores and real native fixture mutations. It
simulates only the OS runtime, returning fixed success/failure shell commands;
it is not an OS sandbox integration test. Coverage includes bash-directory reuse,
exact-file reuse in both directions, sibling rejection, Session isolation/reload,
Project persistence and live removal across existing/new providers, another
project, Once expiry, symlink retargeting and private-root denial. Existing store, native boundary, resource
selection, Git and runtime tests retain the other security checks.

Initial validation before incorporating main's diagnostics, cache profiles and
Project-grant freshness changes:

- Active LSP diagnostics: no errors in the four changed TypeScript files.
- `npm run check` and build: passed.
- Focused native/store/cross-surface/widening tests: 51 passed, 0 failed.
- `npm test`: 272 tests, 259 passed, 13 failed in the existing macOS OS-integration
  group. Failures include `sandbox_apply: Operation not permitted`, Unix socket
  `listen EPERM`, and a proxied Git test returning exit 71 with diagnostics
  intentionally withheld. These results do not establish OS-integration success.
  The local log is `dist/verification/npm-test.log` (ignored build artifact).
- The dedicated `macos_sandbox_test` host-test approval was not granted; host
  execution was not started. Host-side `npm run test:macos` remains necessary to
  finish OS validation; enforcement was not bypassed or weakened.
- Fresh-context final `reviewer` run
  `f1556c3a-4431-4d4b-8bc6-145661578377` reported no issues, noting the simulated
  runtime limitation. No acceptance or merge-readiness decision is inferred.

After merging main through `22c99a9` (PRs #35–37):

- Retained the native diagnostic lookup/selector instrumentation alongside the
  exact-target explanation. Updated this branch's docs and cross-surface removal
  test to match main's per-lookup Project-grant freshness contract.
- `npm run check`, build, and 105 focused tests passed, including diagnostics,
  cache profiles, Project freshness, registered tools and cross-surface reuse.
- LSP returned no findings but could not confirm clean on recheck; TypeScript
  compilation above is the confirmed type check.
- An additional reviewer could not start because host Pi dependencies were
  unavailable; that review did not run. The OS-validation limitation above remains.
