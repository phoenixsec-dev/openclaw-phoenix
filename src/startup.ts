import type { PhoenixPluginConfig, PhoenixClientConfig } from "./config.ts";
import { PhoenixClient, formatPhoenixError } from "./client.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import {
  PhoenixDuplicateIdentityMaterialError,
  validatePhoenixAgentIdentityMaterialUniqueness,
} from "./identity-validation.ts";

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
    if (error instanceof PhoenixDuplicateIdentityMaterialError) {
      throw new Error(
        `Phoenix startup preflight failed for per-agent identity mapping: ${formatPhoenixError(error)}. ` +
          "Check that each mapped agent uses distinct token and seal key material.",
      );
    }
    throw new Error(
      `Phoenix startup preflight failed for per-agent identity mapping: ${formatPhoenixError(error)}. ` +
        "Check the configured per-agent token and seal key file paths and permissions.",
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

export type PhoenixStartupPreflightLogger = {
  warn?: (message: string) => void;
};

export type PhoenixStartupPreflightResult =
  | { ok: true }
  | { ok: false; warning: string; error: unknown };

export async function runPhoenixStartupPreflightWarningOnly(
  config: PhoenixPluginConfig,
  logger: PhoenixStartupPreflightLogger = {},
): Promise<PhoenixStartupPreflightResult> {
  try {
    await runPhoenixStartupCheck(config);
    return { ok: true };
  } catch (error) {
    const warning =
      `Phoenix startup preflight warning (non-fatal): ${formatPhoenixError(error)}; ` +
      "OpenClaw gateway will continue. Use phoenix_status (or openclaw phoenix verify with a diagnostic identity) to diagnose Phoenix connectivity, auth, TLS, and seal-key configuration. " +
      "Active OpenClaw SecretRefs still fail through OpenClaw's configured secret providers.";
    logger.warn?.(warning);
    return { ok: false, warning, error };
  }
}
