import type {
  PhoenixAgentIdentityConfig,
  PhoenixClientConfig,
  PhoenixPluginConfig,
} from "./config.ts";
import type { PhoenixCallerContext } from "./tool-helpers.ts";

const PER_AGENT_REMEDIATION =
  "Configure plugins.entries[\"phoenix-secrets\"].config.agents.<agentId> with tokenFile, sealKeyFile, and defaultNamespace for each OpenClaw agent that may use Phoenix tools, or remove Phoenix tools from that agent's allowlist.";

export class PhoenixIdentityError extends Error {
  readonly status = 403;
  readonly type = "access_denied" as const;
  readonly code: "OPENCLAW_AGENT_IDENTITY_MISSING" | "OPENCLAW_AGENT_IDENTITY_UNMAPPED";
  readonly detail: string;
  readonly remediation: string;

  constructor(params: {
    code: PhoenixIdentityError["code"];
    message: string;
    detail: string;
    remediation?: string;
  }) {
    super(params.message);
    this.name = "PhoenixIdentityError";
    this.code = params.code;
    this.detail = params.detail;
    this.remediation = params.remediation ?? PER_AGENT_REMEDIATION;
  }

  toJSON() {
    return {
      type: this.type,
      status: this.status,
      error: this.message,
      code: this.code,
      detail: this.detail,
      remediation: this.remediation,
    };
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
  return (config.agents as Record<string, PhoenixAgentIdentityConfig> | undefined)?.[agentId];
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
