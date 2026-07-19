import type {
  PhoenixAgentIdentityConfig,
  PhoenixClientConfig,
  PhoenixPluginConfig,
} from "./config.ts";
import type { PhoenixCallerContext } from "./tool-helpers.ts";
import { PhoenixAccessDeniedError } from "./errors.ts";

const PER_AGENT_REMEDIATION =
  "Configure plugins.entries[\"phoenix-secrets\"].config.agents.<agentId> with tokenFile, sealKeyFile, and defaultNamespace for each OpenClaw agent that may use Phoenix tools, or remove Phoenix tools from that agent's allowlist.";

export class PhoenixIdentityError extends PhoenixAccessDeniedError {
  constructor(params: {
    code: "OPENCLAW_AGENT_IDENTITY_MISSING" | "OPENCLAW_AGENT_IDENTITY_UNMAPPED";
    message: string;
    detail: string;
    remediation?: string;
  }) {
    super({
      code: params.code,
      message: params.message,
      detail: params.detail,
      remediation: params.remediation ?? PER_AGENT_REMEDIATION,
    });
  }
}

export function hasPhoenixAgentMappings(config: PhoenixPluginConfig): boolean {
  return Boolean(config.agents && Object.keys(config.agents).length > 0);
}

export function getConfiguredPhoenixAgentIds(config: PhoenixPluginConfig): string[] {
  if (!config.agents) {
    return [];
  }
  return Object.keys(config.agents).sort((left, right) => left.localeCompare(right));
}

function getMappedIdentity(
  config: PhoenixPluginConfig,
  agentId: string,
): PhoenixAgentIdentityConfig | undefined {
  if (!config.agents || !Object.hasOwn(config.agents, agentId)) {
    return undefined;
  }
  return config.agents[agentId];
}

function effectiveClientConfig(
  config: PhoenixPluginConfig,
  identity: PhoenixAgentIdentityConfig,
): PhoenixClientConfig {
  const caCert = identity.caCert ?? config.caCert;
  const clientCert = identity.clientCert ?? config.clientCert;
  const clientKey = identity.clientKey ?? config.clientKey;

  return {
    server: identity.server ?? config.server,
    tokenFile: identity.tokenFile,
    ...(identity.sealKeyFile ? { sealKeyFile: identity.sealKeyFile } : {}),
    ...(caCert ? { caCert } : {}),
    ...(clientCert ? { clientCert } : {}),
    ...(clientKey ? { clientKey } : {}),
    defaultNamespace: identity.defaultNamespace,
    sealMode: identity.sealMode ?? config.sealMode,
  };
}

export function selectPhoenixClientConfigForCaller(
  config: PhoenixPluginConfig,
  caller?: PhoenixCallerContext,
): PhoenixClientConfig {
  if (!hasPhoenixAgentMappings(config)) {
    return config;
  }

  const agentId = caller?.agentId?.trim();
  if (!agentId) {
    throw new PhoenixIdentityError({
      code: "OPENCLAW_AGENT_IDENTITY_MISSING",
      message: "Phoenix per-agent identity is unavailable for this OpenClaw tool call",
      detail:
        "Per-agent Phoenix identity mapping is enabled, but OpenClaw did not provide a trusted runtime ctx.agentId to the plugin tool context.",
    });
  }

  const identity = getMappedIdentity(config, agentId);
  if (!identity) {
    throw new PhoenixIdentityError({
      code: "OPENCLAW_AGENT_IDENTITY_UNMAPPED",
      message: `Phoenix identity is not configured for OpenClaw agent "${agentId}"`,
      detail:
        `The phoenix-secrets plugin refuses to use a shared fallback identity while per-agent mappings are enabled. No mapping exists at config.agents.${agentId}.`,
    });
  }

  return effectiveClientConfig(config, identity);
}

export function getPhoenixAgentClientConfigs(
  config: PhoenixPluginConfig,
): Array<{ agentId: string; config: PhoenixClientConfig }> {
  return getConfiguredPhoenixAgentIds(config).map((agentId) => ({
    agentId,
    config: effectiveClientConfig(config, getMappedIdentity(config, agentId)!),
  }));
}
