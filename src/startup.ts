import {
  collectPhoenixTransportWarnings,
  type PhoenixPluginConfig,
  type PhoenixClientConfig,
} from "./config.ts";
import { PhoenixApiError, PhoenixClient, formatPhoenixError } from "./client.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import {
  PhoenixDuplicateIdentityMaterialError,
  PhoenixIdentityMaterialError,
  validatePhoenixAgentIdentityMaterialUniqueness,
} from "./identity-validation.ts";

async function runSinglePhoenixStartupCheck(params: {
  config: PhoenixClientConfig;
  agentId?: string;
}): Promise<void> {
  const client = new PhoenixClient(params.config);
  await client.validateSealConfiguration();
  // Authenticated probe (GET /v1/policy/check), not the unauthenticated
  // /v1/health endpoint: this validates the configured token / client
  // certificate against the server, so invalid credentials no longer pass
  // preflight silently. See PhoenixClient.checkAuth for endpoint rationale.
  await client.checkAuth({
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
    // The tool-visible payload omits the underlying filesystem error; this log
    // line is operator-facing, so include it here.
    const cause =
      error instanceof PhoenixIdentityMaterialError && error.cause instanceof Error
        ? ` Underlying error: ${error.cause.message}.`
        : "";
    throw new Error(
      `Phoenix startup preflight failed for per-agent identity mapping: ${formatPhoenixError(error)}.${cause} ` +
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
      // Only classify genuine Phoenix API/transport errors; local
      // configuration errors (unreadable seal key files, etc.) fall through
      // to the generic message below.
      const payload = error instanceof PhoenixApiError ? error.toJSON() : undefined;
      if (payload?.type === "network_error") {
        throw new Error(
          `Phoenix startup preflight failed for${target} ${check.config.server}: Phoenix is unreachable: ${formatPhoenixError(error)}. ` +
            "Check the server URL, network reachability, that phoenix-server is running, and any configured CA/client certificate paths.",
        );
      }
      if (payload?.type === "access_denied") {
        throw new Error(
          `Phoenix startup preflight failed for${target} ${check.config.server}: Phoenix is reachable but rejected the configured credentials (HTTP ${payload.status}): ${formatPhoenixError(error)}. ` +
            "Check that the configured token/tokenFile contents (or mTLS client certificate) match a registered Phoenix agent for this identity. No token material is included in this message.",
        );
      }
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
  // Transport posture check: warn loudly (never refuse) when any configured
  // Phoenix server URL -- top-level or per-agent override -- is plain http://
  // to a non-loopback address, since that sends bearer tokens and secret
  // values across the wire in cleartext. phoenix_status and `openclaw
  // phoenix verify` surface the same warning in their structured output.
  for (const transportWarning of collectPhoenixTransportWarnings(config)) {
    logger.warn?.(transportWarning);
  }
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
