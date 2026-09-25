import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_WRITE_PROFILES, loadConfig, parseConfig } from "../config.js";
import { expandPath, resolveWritePolicy } from "../filesystem-policy.js";
import { MutationBoundary } from "../filesystem-boundary.js";
import { buildSandboxRuntimeConfig } from "../runtime-adapter.js";

async function fixture() {
  const base = await mkdtemp(join(tmpdir(), "pi-policy-"));
  const cwd = join(base, "project");
  const home = join(base, "home");
  await Promise.all([mkdir(cwd), mkdir(home)]);
  return { base, cwd, home };
}

test("default Cargo profile uses ~/.cargo and protects sensitive entries", async () => {
  const { cwd, home } = await fixture();
  const policy = await resolveWritePolicy({ cwd, home, env: {}, config: parseConfig({}) });
  const cargo = join(home, ".cargo");
  assert.deepEqual(policy.allow, [cwd, "/tmp", cargo, join(home, ".npm", "_logs"), join(home, ".claude", "debug")]);
  const boundary = await MutationBoundary.create(cwd, policy);
  assert.equal((await boundary.resolve(join(cargo, "registry", "index"))).allowed, true);
  assert.equal((await boundary.resolve(join(cargo, ".package-cache"))).allowed, true);
  for (const name of ["bin", "config", "config.toml", "credentials", "credentials.toml", "env"]) {
    assert.equal((await boundary.resolve(join(cargo, name))).allowed, false, name);
  }
});

test("CARGO_HOME, extra roots, tilde expansion, disabling, and runtime equality", async () => {
  const { base, cwd, home } = await fixture();
  const cargo = join(base, "custom-cargo");
  const policy = await resolveWritePolicy({
    cwd, home, env: { CARGO_HOME: cargo },
    config: parseConfig({ filesystem: { extraWritableRoots: ["~/build-cache", "relative-cache"], disabledDefaultProfiles: ["tmp"] } })
  });
  assert.deepEqual(policy.allow, [cwd, cargo, join(home, ".npm", "_logs"), join(home, ".claude", "debug"), join(home, "build-cache"), join(cwd, "relative-cache")]);
  assert.deepEqual(buildSandboxRuntimeConfig({ cwd, writePolicy: policy }).filesystem, {
    allowRead: [], denyRead: [], allowWrite: [...policy.allow], denyWrite: [...policy.deny]
  });
  assert.equal(expandPath("~", cwd, home), home);
});

test("cargo profile can be disabled", async () => {
  const { cwd, home } = await fixture();
  const policy = await resolveWritePolicy({ cwd, home, env: {}, config: parseConfig({ filesystem: { disabledDefaultProfiles: ["cargo-cache"] } }) });
  assert.deepEqual(policy, { allow: [cwd, "/tmp", join(home, ".npm", "_logs"), join(home, ".claude", "debug")], deny: [] });
});

test("resolved policy canonicalizes symlink roots", async () => {
  const { base, cwd, home } = await fixture();
  const actual = join(base, "actual"); await mkdir(actual);
  const alias = join(base, "alias"); await symlink(actual, alias);
  const policy = await resolveWritePolicy({ cwd, home, env: {}, config: parseConfig({ filesystem: { extraWritableRoots: [alias] } }) });
  assert.equal(policy.allow.at(-1), actual);
});

test("missing config uses defaults while malformed and unknown profiles are invalid", async () => {
  const { base } = await fixture();
  const messages: string[] = [];
  assert.deepEqual(await loadConfig(join(base, "missing.json"), message => messages.push(message)), { valid: true, config: parseConfig({}) });
  assert.equal(messages.length, 0);
  const malformed = join(base, "config.json"); await writeFile(malformed, "{nope");
  assert.deepEqual(await loadConfig(malformed, message => messages.push(message)), { valid: false });
  assert.equal(messages.length, 1);
  assert.throws(() => parseConfig({ filesystem: { disabledDefaultProfiles: ["cargo-cahce"] } }), /unknown default write profile/);
  assert.throws(() => parseConfig({ filesystem: { disabledDefaultProfile: ["cargo-cache"] } }), /unknown filesystem field/);
  assert.throws(() => parseConfig({ filesystem: { extraWritableRoots: [""] } }), /non-empty strings/);
});

test("disabling runtime-home counters the runtime's implicit home allowances", async () => {
  const { cwd, home } = await fixture();
  const policy = await resolveWritePolicy({ cwd, home, env: {}, config: parseConfig({ filesystem: { disabledDefaultProfiles: ["runtime-home"] } }) });
  assert.ok(policy.deny.includes(join(home, ".npm", "_logs")));
  assert.ok(policy.deny.includes(join(home, ".claude", "debug")));
  const boundary = await MutationBoundary.create(cwd, policy);
  assert.equal((await boundary.resolve(join(home, ".npm", "_logs", "x.log"))).denied, true);
});

test("disabling every profile yields a restrictive policy for invalid-config fallback", async () => {
  const { cwd, home } = await fixture();
  const policy = await resolveWritePolicy({
    cwd, home, env: {},
    config: { filesystem: { extraWritableRoots: [], disabledDefaultProfiles: [...DEFAULT_WRITE_PROFILES] } }
  });
  assert.deepEqual(policy.allow, []);
  assert.deepEqual(policy.deny, [join(home, ".npm", "_logs"), join(home, ".claude", "debug")]);
});
