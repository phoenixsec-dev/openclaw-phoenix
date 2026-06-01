import type { PhoenixPluginConfig } from "./config.ts";
import { PhoenixClient, formatPhoenixError } from "./client.ts";

export async function runPhoenixStartupCheck(config: PhoenixPluginConfig): Promise<void> {
  const client = new PhoenixClient(config);
  try {
    await client.validateSealConfiguration();
    await client.health({ toolName: "phoenix_status" });
  } catch (error) {
    throw new Error(
      `Phoenix startup preflight failed for ${config.server}: ${formatPhoenixError(error)}. ` +
        "Check the server URL, network reachability, and any configured token, certificate, or seal key paths.",
    );
  }
}
