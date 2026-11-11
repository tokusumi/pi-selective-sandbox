# Network default selection and boundaries

## Decision

The Git profile adds only `results-receiver.actions.githubusercontent.com:443` for
Actions logs. Following the operator's expanded request beyond GitHub, a separate
`packages` profile adds ten exact HTTPS service hosts for Go, Maven, RubyGems,
NuGet and Composer/Packagist. These are connectivity conveniences, **not a safety
certification** of domains, packages, users, or downloaded content.

Every enabled destination is available to **any** sandboxed command, not just its
package manager. Port 443 does not enforce HTTP methods or read-only usage; an
allowed host can receive data. The existing GitHub all-port patterns are retained,
not extended to the new hosts. This changes repository defaults only: no live
runtime configuration, saved grants, host approvals, or credential files are edited.

## Primary evidence

- [GitHub runner communication requirements](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#communication-requirements-for-github-hosted-runners)
  lists `results-receiver.actions.githubusercontent.com` and
  `*.blob.core.windows.net` under uploading/downloading job summaries, logs,
  artifacts and caches. This is runner documentation, **not** a guarantee of all
  `gh` client routes. Only the exact receiver host at port 443 is adopted.
- [Workflow-run log API](https://docs.github.com/en/rest/actions/workflow-runs#download-workflow-run-logs)
  returns a 302 redirect with a download URL expiring after one minute. A permitted
  API or receiver connection does not authorize the next destination.
- [Copilot cloud agent recommended allowlist](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference#copilot-cloud-agent-recommended-allowlist)
  provides a comparable agent firewall's default connectivity precedent. All ten
  additional hosts below appear in its programming-language/package-manager lists.
  We select concrete package endpoints, **not** its entire inventory, parent-domain
  wildcards, telemetry, general vendor sites, or path-scoped storage entries.
- [Codex Common dependencies](https://developers.openai.com/codex/cloud/internet-access)
  is an optional convenience preset; agent internet is off by default and the page
  warns about exfiltration and malicious dependencies. Its apex strings are not a
  transferable safe-domain verdict or proof that this SDK should allow subdomains.
- [Anthropic sandbox-runtime](https://github.com/anthropics/sandbox-runtime)
  documents an empty default allowlist, not a maintained safety-certified host set.

| Exact HTTPS hosts in `packages` | Service evidence |
| --- | --- |
| `proxy.golang.org`, `sum.golang.org` | [Go modules reference](https://go.dev/ref/mod#module-proxy): default `GOPROXY=https://proxy.golang.org,direct`, `GOSUMDB=sum.golang.org`; Google-operated proxy/checksum services. |
| `repo.maven.apache.org`, `repo1.maven.org` | [Maven Central default](https://maven.apache.org/guides/mini/guide-mirror-settings.html) names the former; Copilot's Java list names both Central endpoints. |
| `rubygems.org`, `index.rubygems.org` | [RubyGems default source](https://github.com/rubygems/rubygems/blob/master/lib/rubygems/defaults.rb) is `https://rubygems.org/`; Copilot's Ruby list also names the index host. |
| `api.nuget.org` | [NuGet API overview](https://learn.microsoft.com/en-us/nuget/api/overview): `https://api.nuget.org/v3/index.json`. |
| `repo.packagist.org`, `packagist.org`, `getcomposer.org` | [Composer repositories](https://getcomposer.org/doc/05-repositories.md) names default Packagist metadata; Copilot's PHP list names all three service/tool hosts. |

## Exclusions and incomplete routes

No new wildcard is added. In particular, there is no default grant for
`*.blob.core.windows.net`, `storage.googleapis.com`, `*.s3.amazonaws.com`, all of
`githubusercontent.com`, arbitrary cloud tenants, private registries, or all
network access. Codex's general vendor apexes (such as `azure.com`, `google.com`,
`microsoft.com` and `oracle.com`) are not imported without a concrete service need.

A Go proxy redirect can require storage outside the permitted proxy hostname;
NuGet or Composer metadata can name other package/download hosts. Those routes
may still fail. A documented **path** such as
`storage.googleapis.com/proxy-golang-org-prod/` cannot be represented by this
host:port policy without permitting the whole multi-tenant host, so it is not
silently converted to a host grant. Additional targets require their own necessity,
ownership and scope evidence, or an explicit exact endpoint approval/configuration.

Tests use the installed SDK matcher on synthetic multi-endpoint/redirect fixtures,
including `productionresultssa2.blob.core.windows.net` from the older investigation
and a third-party account. They prove policy decisions, not a live redirect trace,
service availability, or full log/package download success. These fixtures do not
download live logs or package payloads. Denied storage remains denied even after
receiver access succeeds.

## Opt-outs and compatibility

- `network.disabledDefaultProfiles: ["packages"]` removes only these ten hosts.
  No host is duplicated into another profile to defeat an existing profile opt-out.
- Disabling all five profiles empties the default proxy allowlist.
- **Legacy full opt-out is preserved:** naming all four original profiles (`git`,
  `node`, `rust`, `python`) also suppresses `packages`. Adding a default profile
  must not silently reopen a previously empty allowlist. Consequently, to request
  only selected package hosts with all original profiles disabled, use explicit
  `network.extraAllowedDomains` entries.
- A profile disable is not a hard deny: explicit startup additions and exact
  approved capabilities can still authorize their resources. Local binding and
  filesystem profiles remain independent; Linux network isolation is unsupported.

Exact host:port grants, SDK resolved-address protection, existing deny behavior,
filesystem boundaries and explicit exact-command host replay are unchanged.
Canonicalization follows existing rules: the proxy normalizes host case/trailing
DNS dots; the stricter approval endpoint schema still rejects trailing-dot grant
spellings. No new canonicalization exception is introduced for the receiver.

## Design review

A bounded council used `oracle` (fork context, run
`9b6ccd2a-886a-4dbd-ac31-ca8ca3797bd4`) and `reviewer` (runtime-default context,
run `758474d0-f822-49ab-82e6-f6253f0aceeb`), one independent pass of a two-pass cap.
Both advised concrete package endpoints instead of wholesale copying a purported
safe list. No recommendation-affecting disagreement remained, so no cross-exam
was needed. The parent's decision accepts that recommendation, the ownership/
profile-overlap warning and legacy-opt-out warning. It rejects wholesale Codex
apex import because the safety premise and equivalent subdomain/method semantics
are unproven. No external CLI critique was run; the oracle's additional default
critique was explicitly waived for this advisory-only two-agent council.

The operator authorized broader defaults; the parent owns the endpoint selection
and the compatibility rule above. Confidence is high in the exact matcher scope
and documented service purpose, not in intrinsic host safety or complete redirect
coverage. New primary evidence for a necessary, appropriately scoped endpoint can
change the list; general upstream popularity alone cannot establish safety.

## Verification

- `npm ci` installed the locked test/build dependencies and applied the existing
  SDK patch; no dependency versions were changed.
- TypeScript check/build and focused SDK matcher/redirect/guard/opt-out tests pass.
- Full `npm test`: 340 tests, 324 passed, 16 failed, zero skipped. The failures
  require OS sandbox execution and report `sandbox_apply: Operation not permitted`
  in this enclosing sandbox; this is not an all-green test result.
- The existing approval-gated `macos_sandbox_test` was requested but not approved;
  no host test process started. OS integration remains unverified. To supply that
  evidence, run `npm run test:macos` in this workspace from a normal host terminal,
  or approve a fresh dedicated host-runner request. No protection was disabled.
- Fresh-context read-only implementation review (`reviewer`, run
  `77246b47-3a38-4ec3-9970-eb79810cd671`) reported no issues. Its advice is not an
  acceptance/merge decision and does not replace the missing OS verification.
