import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const runtime = join(root, "node_modules", "@anthropic-ai", "sandbox-runtime");
const patch = join(root, "patches", "sandbox-runtime-0.0.76.patch");
// Exact input/output hashes reject version drift, partial patches, and local
// modifications rather than silently installing incomplete telemetry repairs.
const files = {
  "macos-sandbox-utils.js": [
    "5e7672b216ac850e28c9ea90688d705a068ad6f8d1f2ece7e8399c7db92319dd",
    "7d36d8254d378bdccdd91c66aee9ea41d987672c3903c2679cd3ad22223bdc7d"
  ],
  "macos-sandbox-utils.d.ts": [
    "2b4727a648b59bbe41d6ac0dc492b9b7adc39d6e7dc05c10285cc9670d6244ac",
    "8c251de694089d2ab7b88fbddc6eb6512f6f2222251b27925fd87aae34a63478"
  ],
  "sandbox-violation-store.js": [
    "e7524fb72e0d483ebc572bb3e37d1baf472db59714c3f3935824e9d3b82b2142",
    "67716e596b38bb7d00435d3f1ff2d261bc320397f2c560ca672fb543f0b8833e"
  ]
};
const hashes = async () => Promise.all(Object.keys(files).map(async name =>
  createHash("sha256").update(await readFile(join(runtime, "dist", "sandbox", name))).digest("hex")));
const matches = (actual, column) => Object.values(files).every((expected, index) => expected[column] === actual[index]);

try {
  const { version } = JSON.parse(await readFile(join(runtime, "package.json"), "utf8"));
  if (version !== "0.0.76") throw new Error(`Expected sandbox-runtime 0.0.76, found ${version}; review the SDK patch before upgrading.`);
  const before = await hashes();
  if (matches(before, 1)) {
    console.log("sandbox-runtime 0.0.76 telemetry patch already applied.");
  } else {
    if (!matches(before, 0)) throw new Error("SDK files differ from both pristine and patched 0.0.76; refusing to apply a partial patch. Reinstall dependencies.");
    // Do not discover a consumer's parent repository: that changes Git's
    // path prefix and can skip dependency patches installed under node_modules.
    const env = { ...process.env, GIT_CEILING_DIRECTORIES: dirname(root) };
    for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"]) delete env[key];
    const options = { cwd: root, stdio: "inherit", env };
    execFileSync("git", ["apply", "--check", "--", patch], options);
    execFileSync("git", ["apply", "--", patch], options);
    if (!matches(await hashes(), 1)) throw new Error("SDK patch verification failed. Reinstall dependencies; do not use this installation.");
    console.log("Applied sandbox-runtime 0.0.76 telemetry patch.");
  }
} catch (error) {
  console.error(`Sandbox runtime patch installation failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
