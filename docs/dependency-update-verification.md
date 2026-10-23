# Installed-extension dependency update verification

## Supported host

This extension requires Pi **1.4.0 or newer**, including the host-provided
pi-ai and pi-tui APIs. Pi 0.85.1 is no longer supported. The three
`peerDependencies` declare `>=1.4.0`; development dependencies start at 1.4.0.

Users must upgrade their **host Pi** with `pi update` (or its owning package
manager), then update extensions and restart Pi. Updating this repository's
manifest or running `pi update --extensions` does not upgrade the host.
Managed installs can suppress peer resolution, so a peer minimum is not a
runtime version check and is not a substitute for upgrading the host.

## Isolated checks

These checks exercised the npm dependency-install phase used by Pi's Git
package manager, not just development `npm ci`. All fixtures were created
under this checkout's ignored `node_modules/.install-path-verification`.
No personal Pi settings, installed extensions, or global packages were changed.

The commands were selected by inspecting the released Pi package manager's
`getGitDependencyInstallArgs()` implementation:

| Pi version | Default npm Git dependency command |
| --- | --- |
| 0.85.1 | `npm install --omit=dev` |
| 1.4.0 | `npm install --omit=dev --legacy-peer-deps` |

### Existing installation update

1. Installed a private Pi 0.85.1 host fixture.
2. Created a separate Git-extension directory beneath that fixture, containing
   this repository's baseline `package.json` and `package-lock.json` from
   commit `8f3e905`, plus the postinstall script and SDK patch.
3. Ran `npm install --omit=dev` in the extension directory. It installed
   Pi 0.85.1, `brace-expansion@5.0.9`, and `undici@8.9.0`; audit reported five
   package entries (one moderate, four high).
4. Replaced the extension's manifest and lockfile with this change, preserving
   its existing `node_modules`, then ran the same install command.
5. Confirmed the extension tree now contains Pi 1.4.0,
   `brace-expansion@5.0.12`, and `undici@8.10.2`. The SDK patch remained applied.
6. Repeated the install without `npm audit fix`: the install was up to date,
   and neither brace-expansion nor undici appeared in the audit report.

The private host remained at 0.85.1, demonstrating that updating the extension
does **not** upgrade it. That host is deliberately outside the supported range;
this check does not claim extension execution on 0.85.1 is supported.

### Supported-host install behavior

In another isolated directory containing the new manifest, lockfile, script,
and patch, ran Pi 1.4.0's command:

```sh
npm install --omit=dev --legacy-peer-deps
```

It installed 11 dependencies, applied the SDK patch, and did not install a
physical copy of pi-coding-agent in the extension directory. The development
host used for this check was Pi 1.4.0. This matches the supported host providing
Pi APIs rather than relying on an extension-local Pi copy.

Both install paths still report only the sandbox-runtime/node-forge advisory
chain (two high-severity package entries). That advisory has no published
node-forge fix at investigation; see [the follow-up draft](node-forge-audit-follow-up.md).
Install-script warnings are independent of the audit and were not blanket-approved.

## Coverage limits

The dependency phase and existing-node_modules update were tested locally;
a real user's `pi update --extensions` against a published Git revision was
not run. These fixtures do not verify the user's other installed packages,
custom package-manager commands, or host upgrade.

Type checking and all 14 focused Pi-entrypoint/SDK-patch tests pass. The full
suite previously reported 234 passes and nine native macOS failures because
this runner cannot create a nested macOS sandbox. The host-test tool could not
start because its configured Node executable was missing. Native macOS
integration therefore still needs a supported host runner.
