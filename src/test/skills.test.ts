import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import test from "node:test";
import { findTrustedHelper, splitPureInvocation } from "../skills.js";

async function fixture(t: test.TestContext) {
  const base = await mkdtemp(join(tmpdir(), "skill-helper-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, "demo skill"), scripts = join(root, "scripts");
  await mkdir(scripts, { recursive: true });
  const helper = join(scripts, "finish-worktree.sh");
  await writeFile(helper, "#!/bin/sh\nprintf '%s' \"$*\"\n");
  const skill = { id: "demo", root, active: true, trusted: true };
  return { base, root, scripts, helper, skill, authority: { getActiveSkills: async () => [skill] } };
}

test("literal helpers accept arguments, quotes and the command cwd", async t => {
  const f = await fixture(t);
  for (const command of [
    `'${f.helper}' --message "変更内容"`,
    `bash '${f.helper}' --message='変更 内容'`,
    `sh '${f.helper}' --message ""`,
    `python3 '${f.helper}' --arg x`,
    `node '${f.helper}' --arg x`,
    `uv run '${f.helper}' --arg x`,
    `'./${relative(f.base, f.helper)}' --message "変更 内容"`
  ]) assert.equal(await findTrustedHelper(command, f.authority, f.base), f.skill, command);
  assert.deepEqual(splitPureInvocation(`bash 'some path' --message="変更 内容" ''`), ["bash", "some path", "--message=変更 内容", ""]);
  assert.equal(await findTrustedHelper(`'./${relative(f.base, f.helper)}'`, f.authority, f.root), undefined);
});

test("only unquoted home shorthand expands, never a quoted tilde or a bare PATH command", async t => {
  const f = await fixture(t);
  const home = process.env.HOME;
  process.env.HOME = f.base;
  t.after(() => { if (home === undefined) delete process.env.HOME; else process.env.HOME = home; });
  await mkdir(join(f.base, "skill", "scripts"), { recursive: true });
  await symlink(f.helper, join(f.base, "skill", "scripts", "finish.sh"));
  assert.equal(await findTrustedHelper('~/skill/scripts/finish.sh --message "変更内容"', f.authority, f.base), f.skill);
  assert.equal(await findTrustedHelper('bash ~/skill/scripts/finish.sh --message "変更内容"', f.authority, f.base), f.skill);
  assert.equal(await findTrustedHelper('"~/skill/scripts/finish.sh"', f.authority, f.base), undefined);
  assert.equal(await findTrustedHelper('~"/skill/scripts/finish.sh"', f.authority, f.base), undefined);
  await symlink(f.scripts, join(f.base, "~+"));
  assert.equal(await findTrustedHelper("~+/finish-worktree.sh", f.authority, f.base), undefined);
  assert.equal(await findTrustedHelper(`'${f.helper}' ~`, f.authority, f.base), undefined);
  assert.equal(await findTrustedHelper("finish-worktree.sh", f.authority, f.scripts), undefined);
});

test("shell compounds, expansions, comments, escapes and malformed quotes never get helper trust", async t => {
  const f = await fixture(t);
  const command = `'${f.helper}'`;
  for (const suffix of ["; echo bad", " && echo bad", " | cat", " &", " > /tmp/out", "\necho bad", "\r echo bad", " $(whoami)", " `whoami`", " $HOME", " *", " \\x", " 'unterminated", ' "unterminated', " # comment", "\0"]) {
    assert.equal(await findTrustedHelper(command + suffix, f.authority), undefined, suffix);
  }
  assert.equal(await findTrustedHelper(`bash #${f.helper}`, f.authority), undefined);
  assert.equal(splitPureInvocation(""), undefined);
});

test("shell assignment and interpreter option operands cannot disguise an unrelated command", async t => {
  const f = await fixture(t);
  await symlink("/", join(f.base, "A="));
  await symlink("/", join(f.base, "A+="));
  await symlink("/", join(f.base, "--require="));
  await symlink("/", join(f.base, "--script="));
  const module = join(f.scripts, "helper.js");
  await writeFile(module, "// harmless preload fixture\n");
  for (const command of [
    `A=''"${f.helper}" /bin/echo bypass`,
    `A+=''"${f.helper}" /bin/echo bypass`,
    `node --require=''"${module}" ./evil.js`,
    `uv run --script=''"${f.helper}" ./evil.sh`
  ]) assert.equal(await findTrustedHelper(command, f.authority, f.base), undefined, command);
});

test("symlink followed by dot-dot is resolved like the executed path, not lexically", async t => {
  const f = await fixture(t);
  await mkdir(join(f.base, "evil", "subdir"), { recursive: true });
  const evil = join(f.base, "evil", "alias");
  await writeFile(evil, "#!/bin/sh\necho untrusted\n");
  await symlink(f.helper, join(f.base, "alias"));
  await symlink(join(f.base, "evil", "subdir"), join(f.base, "jump"));
  assert.equal(await realpath(`${f.base}/jump/../alias`), await realpath(evil));
  assert.equal(await findTrustedHelper("./jump/../alias", f.authority, f.base), undefined);
  assert.equal(await findTrustedHelper(`bash ./jump/../alias`, f.authority, f.base), undefined);
  assert.equal(await findTrustedHelper(`'${f.scripts}/../scripts/finish-worktree.sh'`, f.authority, f.base), f.skill);
});

test("canonical helper containment permits aliases but rejects escapes and directories", async t => {
  const f = await fixture(t);
  const outside = join(f.base, "outside.sh");
  await writeFile(outside, "echo outside");
  await symlink(outside, join(f.scripts, "escape.sh"));
  await symlink(f.helper, join(f.base, "alias.sh"));
  assert.equal(await findTrustedHelper(`'${join(f.base, "alias.sh")}'`, f.authority), f.skill);
  for (const path of [join(f.scripts, "escape.sh"), f.root, f.scripts, join(f.scripts, "missing.sh"), outside]) {
    assert.equal(await findTrustedHelper(`'${path}'`, f.authority), undefined, path);
  }
  await symlink(f.base, join(f.root, "external-scripts"));
  assert.equal(await findTrustedHelper(`'${outside}'`, { getActiveSkills: async () => [{ ...f.skill, helperRoots: ["external-scripts"] }] }), undefined);
  for (const state of [{ active: false }, { trusted: false }]) {
    assert.equal(await findTrustedHelper(`'${f.helper}'`, { getActiveSkills: async () => [{ ...f.skill, ...state }] }), undefined);
  }
});
