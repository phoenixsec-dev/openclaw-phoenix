import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(new URL("../scripts/generate-manifest.mjs", import.meta.url));

test("openclaw.plugin.json is up to date with src/config.ts", () => {
  assert.doesNotThrow(() => {
    execFileSync(process.execPath, [scriptPath, "--check"], { stdio: "pipe" });
  }, "manifest drift detected; run: npm run generate:manifest");
});
