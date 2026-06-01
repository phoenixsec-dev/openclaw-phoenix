import type { PhoenixPluginConfig, PhoenixClientConfig } from "./config.ts";
import { PhoenixClient, formatPhoenixError } from "./client.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import { validatePhoenixAgentIdentityMaterialUniqueness } from "./identity-validation.ts";

async function runSinglePhoenixStartupCheck(params: {
  config: PhoenixClientConfig;
  agentId?: string;
}): Promise<void> {
  const client = new PhoenixClient(params.config);
  await client.validateSealConfiguration();
  await client.health({
    toolName: "phoenix_status",
    ...(params.agentId ? { caller: { agentId: params.agentId } } : {}),
  });
}

export async function runPhoenixStartupCheck(config: PhoenixPluginConfig): Promise<void> {
  try {
    await validatePhoenixAgentIdentityMaterialUniqueness(config);
  } catch (error) {
    throw new Error(
      `Phoenix startup preflight failed for per-agent identity mapping: ${formatPhoenixError(error)}. ` +
        "Check that each mapped agent uses distinct token and seal key material.",
    );
  }

  const agentConfigs = getPhoenixAgentClientConfigs(config);
  const checks = agentConfigs.length > 0 ? agentConfigs : [{ config }];

  for (const check of checks) {
    try {
      await runSinglePhoenixStartupCheck(check);
    } catch (error) {
      const target = "agentId" in check ? ` agent ${check.agentId}` : "";
      throw new Error(
        `Phoenix startup preflight failed for${target} ${check.config.server}: ${formatPhoenixError(error)}. ` +
          "Check the server URL, network reachability, and any configured token, certificate, or seal key paths.",
      );
    }
  }
}
