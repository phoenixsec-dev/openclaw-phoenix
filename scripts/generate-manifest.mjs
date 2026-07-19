// Generates openclaw.plugin.json from the runtime config schema so the
// manifest can never drift from src/config.ts. Run: npm run generate:manifest
// Verify without writing: npm run generate:manifest -- --check
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  phoenixPluginConfigJsonSchema,
  phoenixPluginConfigUiHints,
} from "../src/config.ts";

const manifestPath = fileURLToPath(new URL("../openclaw.plugin.json", import.meta.url));

const manifest = {
  id: "phoenix-secrets",
  contracts: {
    tools: ["phoenix_resolve", "phoenix_list", "phoenix_status"],
  },
  activation: {
    onCapabilities: ["tool"],
  },
  uiHints: phoenixPluginConfigUiHints,
  configSchema: phoenixPluginConfigJsonSchema,
};

const rendered = `${JSON.stringify(manifest, null, 2)}\n`;

if (process.argv.includes("--check")) {
  const existing = readFileSync(manifestPath, "utf8");
  if (existing !== rendered) {
    console.error(
      "openclaw.plugin.json is out of date with src/config.ts; run: npm run generate:manifest",
    );
    process.exit(1);
  }
  console.log("openclaw.plugin.json matches src/config.ts");
} else {
  writeFileSync(manifestPath, rendered);
  console.log(`wrote ${manifestPath}`);
}
