import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(new URL("../scripts/generate-manifest.mjs", import.meta.url));
const manifestPath = fileURLToPath(new URL("../openclaw.plugin.json", import.meta.url));

test("openclaw.plugin.json is up to date with src/config.ts", () => {
  assert.doesNotThrow(() => {
    execFileSync(process.execPath, [scriptPath, "--check"], { stdio: "pipe" });
  }, "manifest drift detected; run: npm run generate:manifest");
});

test("manifest opts into gateway startup so registered services actually run", () => {
  // Since OpenClaw 2026.6.x a tool-only plugin is excluded from the gateway
  // startup plugin set unless activation.onStartup === true, which means
  // api.registerService() output is never started and `openclaw plugins
  // inspect phoenix-secrets` reports services: []. index.ts registers the
  // phoenix-startup-check service, so the manifest must keep this opt-in.
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    activation?: { onStartup?: unknown; onCapabilities?: unknown };
  };
  assert.equal(manifest.activation?.onStartup, true);
  assert.deepEqual(manifest.activation?.onCapabilities, ["tool"]);
});
