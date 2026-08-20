import { PHOENIX_NAMESPACE_PATTERN, isValidPhoenixNamespace } from "./refs.ts";

// Mirrors OpenClaw's VALID_ID_RE (src/routing/session-key.ts) after its
// normalizeAgentId lowercasing.
export const PHOENIX_OPENCLAW_AGENT_ID_PATTERN = "^[a-z0-9][a-z0-9_-]{0,63}$";
const PHOENIX_OPENCLAW_AGENT_ID_RE = new RegExp(PHOENIX_OPENCLAW_AGENT_ID_PATTERN);

export type PhoenixClientConfig = {
  server: string;
  token?: string;
  tokenFile?: string;
  sealKeyFile?: string;
  caCert?: string;
  clientCert?: string;
  clientKey?: string;
  defaultNamespace?: string;
  sealMode: boolean;
};

export type PhoenixAgentIdentityConfig = {
  server?: string;
  tokenFile: string;
  sealKeyFile?: string;
  caCert?: string;
  clientCert?: string;
  clientKey?: string;
  defaultNamespace: string;
  sealMode?: boolean;
};

export type PhoenixPluginConfig = PhoenixClientConfig & {
  agents?: Record<string, PhoenixAgentIdentityConfig>;
};

type ResolvePhoenixPluginConfigOptions = {
  env?: NodeJS.ProcessEnv;
  resolvePath?: (input: string) => string;
};

type PluginConfigValidation =
  | { ok: true; value?: unknown }
  | { ok: false; errors: string[] };

const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);

const phoenixAgentIdentityConfigJsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["tokenFile", "defaultNamespace"],
  properties: {
    server: { type: "string" },
    tokenFile: { type: "string" },
    sealKeyFile: { type: "string" },
    caCert: { type: "string" },
    clientCert: { type: "string" },
    clientKey: { type: "string" },
    defaultNamespace: { type: "string", pattern: PHOENIX_NAMESPACE_PATTERN },
    sealMode: { type: "boolean" },
  },
};

export const phoenixPluginConfigJsonSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    server: { type: "string" },
    token: { type: "string" },
    tokenFile: { type: "string" },
    sealKeyFile: { type: "string" },
    caCert: { type: "string" },
    clientCert: { type: "string" },
    clientKey: { type: "string" },
    defaultNamespace: { type: "string", pattern: PHOENIX_NAMESPACE_PATTERN },
    sealMode: { type: "boolean" },
    agents: {
      type: "object",
      additionalProperties: false,
      minProperties: 1,
      propertyNames: { pattern: PHOENIX_OPENCLAW_AGENT_ID_PATTERN },
      patternProperties: {
        [PHOENIX_OPENCLAW_AGENT_ID_PATTERN]: phoenixAgentIdentityConfigJsonSchema,
      },
    },
  },
};

export const phoenixPluginConfigUiHints = {
  server: {
    label: "Phoenix Server URL",
    help: "Phoenix base URL (fallback: PHOENIX_SERVER). Shared by per-agent identities unless an agent overrides it. Use https:// whenever the address is not loopback; non-loopback http:// sends the bearer token and secret values in cleartext and triggers a security warning.",
    placeholder: "https://phoenix:9090",
  },
  token: {
    label: "Phoenix Token",
    help: "Diagnostic/dev shared bearer token (fallback: PHOENIX_TOKEN). Not a per-agent trust boundary.",
    sensitive: true,
    placeholder: "phoenix_...",
  },
  tokenFile: {
    label: "Phoenix Token File",
    help: "Diagnostic/dev shared bearer token file (fallback: PHOENIX_TOKEN_FILE). Prefer agents.<id>.tokenFile for trusted per-agent use.",
    sensitive: true,
  },
  sealKeyFile: {
    label: "Phoenix Seal Key File",
    help: "Diagnostic/dev shared seal private key file (fallback: PHOENIX_SEAL_KEY). Prefer agents.<id>.sealKeyFile for trusted per-agent use.",
    sensitive: true,
  },
  caCert: {
    label: "CA Certificate Path",
    help: "Optional CA certificate path for custom TLS trust (fallback: PHOENIX_CA_CERT). Shared by per-agent identities unless overridden.",
  },
  clientCert: {
    label: "Client Certificate Path",
    help: "Optional client certificate path for mTLS (fallback: PHOENIX_CLIENT_CERT). Shared by per-agent identities unless overridden.",
  },
  clientKey: {
    label: "Client Key Path",
    help: "Optional client key path for mTLS (fallback: PHOENIX_CLIENT_KEY). Shared by per-agent identities unless overridden.",
    sensitive: true,
  },
  defaultNamespace: {
    label: "Default Namespace",
    help: "Diagnostic/dev namespace for single-identity mode. In per-agent mode use agents.<id>.defaultNamespace.",
  },
  sealMode: {
    label: "Sealed Mode",
    help: "Return opaque PHOENIX_SEALED tokens instead of plaintext values. Per-agent identities inherit this unless they override sealMode.",
  },
  agents: {
    label: "Per-Agent Phoenix Identities",
    help: "Map trusted OpenClaw ctx.agentId values (lowercase ids, e.g. main or example-agent) to tokenFile, sealKeyFile, and defaultNamespace. Tool args cannot select identity.",
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function resolveMaybePath(
  value: string | undefined,
  resolvePath: (input: string) => string,
): string | undefined {
  return value ? resolvePath(value) : undefined;
}

function normalizePhoenixServer(server: string, label: string): string {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(server);
  } catch {
    throw new Error(`${label} must be a valid URL: ${server}`);
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(`${label} must use http:// or https://: ${server}`);
  }
  return parsedUrl.toString().replace(/\/$/, "");
}

// --- Transport posture ----------------------------------------------------
//
// Phoenix is LAN-scoped by design: internet/WAN exposure is out of scope and
// unsupported. Plaintext HTTP over loopback is the supported default because
// loopback traffic never reaches a network interface. A LAN, however, is not
// a trust boundary (containers on shared bridges, IoT, guest WiFi, any
// compromised host), so the plugin warns loudly whenever a configured server
// URL would send the bearer token across a wire in cleartext. It warns only
// and never refuses: this package is published, and hard-failing would break
// existing deployments with no migration path. phoenix-server and the Hermes
// plugin apply the same warn-never-refuse posture.

function isLoopbackHostname(rawHostname: string): boolean {
  let hostname = rawHostname.toLowerCase();
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    return true;
  }
  if (hostname === "::1") {
    return true;
  }
  if (hostname.startsWith("::ffff:")) {
    hostname = hostname.slice("::ffff:".length);
  }
  const ipv4 = /^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.exec(hostname);
  if (ipv4) {
    return Number(ipv4[1]) === 127;
  }
  // IPv4-mapped IPv6 loopback after WHATWG URL normalization to hex groups
  // (http://[::ffff:127.0.0.1] parses to hostname "[::ffff:7f00:1]").
  return /^7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(hostname);
}

export function getPhoenixTransportWarning(server: string): string | undefined {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(server);
  } catch {
    return undefined;
  }
  if (parsedUrl.protocol !== "http:" || isLoopbackHostname(parsedUrl.hostname)) {
    return undefined;
  }
  return (
    `SECURITY WARNING: Phoenix server ${server} uses plain http:// to a non-loopback address. ` +
    "The Phoenix bearer token and resolved secret values cross the network in cleartext, readable by " +
    "anything on that network segment (containers on shared bridges, other LAN hosts, guest WiFi), and " +
    "one captured token yields everything its ACL permits. Phoenix is LAN-scoped by design and a LAN is " +
    "not a trust boundary; WAN/internet exposure is unsupported. Fix: enable TLS on phoenix-server, change " +
    "this URL to https://, and point caCert (or PHOENIX_CA_CERT) at the Phoenix CA certificate -- or keep " +
    "Phoenix on loopback (e.g. http://127.0.0.1:9090). The plugin continues with this warning; it does not " +
    "refuse plaintext."
  );
}

export function collectPhoenixTransportWarnings(config: PhoenixPluginConfig): string[] {
  const servers = new Set<string>([config.server]);
  for (const identity of Object.values(config.agents ?? {})) {
    servers.add(identity.server ?? config.server);
  }
  const warnings: string[] = [];
  for (const server of servers) {
    const warning = getPhoenixTransportWarning(server);
    if (warning) {
      warnings.push(warning);
    }
  }
  return warnings;
}

function validateDefaultNamespace(defaultNamespace: string, label: string): void {
  if (defaultNamespace.includes(":")) {
    throw new Error(`${label} must be a namespace name, not a URI`);
  }
  if (!isValidPhoenixNamespace(defaultNamespace)) {
    throw new Error(
      `${label} must be a single namespace segment (letters, digits, '._-', no '/' or '.'/'..')`,
    );
  }
}

function readAgentIdentityMappings(
  value: unknown,
  options: { inheritedSealMode: boolean; resolvePath: (input: string) => string },
): PhoenixPluginConfig["agents"] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new Error("phoenix-secrets agents must be an object mapping OpenClaw agent ids to Phoenix identities");
  }

  const entries = Object.entries(value);
  if (entries.length === 0) {
    throw new Error("phoenix-secrets agents must configure at least one OpenClaw agent identity");
  }

  // Null prototype so runtime agentId lookups can never resolve to inherited
  // Object.prototype members (e.g. an agent named "constructor").
  const agents: Record<string, PhoenixAgentIdentityConfig> = Object.create(null);
  const tokenFileOwners = new Map<string, string>();
  const sealKeyFileOwners = new Map<string, string>();
  for (const [agentId, rawAgent] of entries) {
    if (!PHOENIX_OPENCLAW_AGENT_ID_RE.test(agentId)) {
      throw new Error(
        `phoenix-secrets agents.${agentId} is not a valid OpenClaw agent id; ids must match ${PHOENIX_OPENCLAW_AGENT_ID_PATTERN}`,
      );
    }
    if (!isRecord(rawAgent)) {
      throw new Error(`phoenix-secrets agents.${agentId} must be an object`);
    }

    const tokenFile = resolveMaybePath(readString(rawAgent.tokenFile), options.resolvePath);
    if (!tokenFile) {
      throw new Error(`phoenix-secrets agents.${agentId}.tokenFile is required`);
    }
    const existingTokenFileOwner = tokenFileOwners.get(tokenFile);
    if (existingTokenFileOwner) {
      throw new Error(
        `phoenix-secrets agents.${agentId}.tokenFile must be unique; already used by agents.${existingTokenFileOwner}`,
      );
    }
    tokenFileOwners.set(tokenFile, agentId);

    const defaultNamespace = readString(rawAgent.defaultNamespace);
    if (!defaultNamespace) {
      throw new Error(`phoenix-secrets agents.${agentId}.defaultNamespace is required`);
    }
    validateDefaultNamespace(defaultNamespace, `phoenix-secrets agents.${agentId}.defaultNamespace`);

    const explicitSealMode = readBoolean(rawAgent.sealMode);
    const effectiveSealMode = explicitSealMode ?? options.inheritedSealMode;
    const sealKeyFile = resolveMaybePath(readString(rawAgent.sealKeyFile), options.resolvePath);
    if (effectiveSealMode && !sealKeyFile) {
      throw new Error(
        `phoenix-secrets agents.${agentId}.sealKeyFile is required when effective sealMode is true`,
      );
    }
    if (sealKeyFile) {
      const existingSealKeyFileOwner = sealKeyFileOwners.get(sealKeyFile);
      if (existingSealKeyFileOwner) {
        throw new Error(
          `phoenix-secrets agents.${agentId}.sealKeyFile must be unique; already used by agents.${existingSealKeyFileOwner}`,
        );
      }
      sealKeyFileOwners.set(sealKeyFile, agentId);
    }

    const rawServer = readString(rawAgent.server);
    const server = rawServer
      ? normalizePhoenixServer(rawServer, `phoenix-secrets agents.${agentId}.server`)
      : undefined;
    const caCert = resolveMaybePath(readString(rawAgent.caCert), options.resolvePath);
    const clientCert = resolveMaybePath(readString(rawAgent.clientCert), options.resolvePath);
    const clientKey = resolveMaybePath(readString(rawAgent.clientKey), options.resolvePath);
    if ((clientCert && !clientKey) || (!clientCert && clientKey)) {
      throw new Error(`phoenix-secrets agents.${agentId} mTLS override requires both clientCert and clientKey`);
    }

    agents[agentId] = {
      tokenFile,
      defaultNamespace,
      ...(sealKeyFile ? { sealKeyFile } : {}),
      ...(server ? { server } : {}),
      ...(caCert ? { caCert } : {}),
      ...(clientCert ? { clientCert } : {}),
      ...(clientKey ? { clientKey } : {}),
      ...(explicitSealMode !== undefined ? { sealMode: explicitSealMode } : {}),
    };
  }

  return agents;
}

export function resolvePhoenixPluginConfig(
  value: unknown,
  options: ResolvePhoenixPluginConfigOptions = {},
): PhoenixPluginConfig {
  const env = options.env ?? process.env;
  const resolvePath = options.resolvePath ?? ((input: string) => input);
  const raw = isRecord(value) ? value : {};

  const rawServer = readString(raw.server) ?? readString(env.PHOENIX_SERVER);
  if (!rawServer) {
    throw new Error("phoenix-secrets config requires server (or PHOENIX_SERVER)");
  }
  const server = normalizePhoenixServer(rawServer, "phoenix-secrets server");

  const token = readString(raw.token) ?? readString(env.PHOENIX_TOKEN);
  const tokenFile = resolveMaybePath(
    readString(raw.tokenFile) ?? readString(env.PHOENIX_TOKEN_FILE),
    resolvePath,
  );
  const sealKeyFile = resolveMaybePath(
    readString(raw.sealKeyFile) ?? readString(env.PHOENIX_SEAL_KEY),
    resolvePath,
  );
  const caCert = resolveMaybePath(readString(raw.caCert) ?? readString(env.PHOENIX_CA_CERT), resolvePath);
  const clientCert = resolveMaybePath(
    readString(raw.clientCert) ?? readString(env.PHOENIX_CLIENT_CERT),
    resolvePath,
  );
  const clientKey = resolveMaybePath(
    readString(raw.clientKey) ?? readString(env.PHOENIX_CLIENT_KEY),
    resolvePath,
  );
  const defaultNamespace =
    readString(raw.defaultNamespace) ?? readString(env.PHOENIX_DEFAULT_NAMESPACE);

  const explicitSealMode = readBoolean(raw.sealMode);
  const sealMode =
    explicitSealMode ?? TRUE_VALUES.has((env.PHOENIX_SEAL_MODE ?? "").trim().toLowerCase());
  const agents = readAgentIdentityMappings(raw.agents, { inheritedSealMode: sealMode, resolvePath });
  const hasAgentMappings = Boolean(agents && Object.keys(agents).length > 0);

  if (!hasAgentMappings && !token && !tokenFile && !(clientCert && clientKey)) {
    throw new Error(
      "phoenix-secrets config requires token auth, tokenFile auth, per-agent agents config, or both clientCert and clientKey for mTLS",
    );
  }

  if ((clientCert && !clientKey) || (!clientCert && clientKey)) {
    throw new Error("phoenix-secrets mTLS requires both clientCert and clientKey");
  }

  if (!hasAgentMappings && sealMode && !sealKeyFile) {
    throw new Error("phoenix-secrets sealMode requires sealKeyFile (or PHOENIX_SEAL_KEY)");
  }

  if (defaultNamespace) {
    validateDefaultNamespace(defaultNamespace, "phoenix-secrets defaultNamespace");
  }

  return {
    server,
    ...(token ? { token } : {}),
    ...(tokenFile ? { tokenFile } : {}),
    ...(sealKeyFile ? { sealKeyFile } : {}),
    ...(caCert ? { caCert } : {}),
    ...(clientCert ? { clientCert } : {}),
    ...(clientKey ? { clientKey } : {}),
    ...(defaultNamespace ? { defaultNamespace } : {}),
    sealMode,
    ...(agents ? { agents } : {}),
  };
}

export const phoenixPluginConfigSchema = {
  jsonSchema: phoenixPluginConfigJsonSchema,
  uiHints: phoenixPluginConfigUiHints,
  parse(value: unknown) {
    return resolvePhoenixPluginConfig(value);
  },
  validate(value: unknown): PluginConfigValidation {
    try {
      return {
        ok: true,
        value: resolvePhoenixPluginConfig(value),
      };
    } catch (error) {
      return {
        ok: false,
        errors: [error instanceof Error ? error.message : String(error)],
      };
    }
  },
};
