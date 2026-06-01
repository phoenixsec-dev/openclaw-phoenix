export type PhoenixPluginConfig = {
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

type ResolvePhoenixPluginConfigOptions = {
  env?: NodeJS.ProcessEnv;
  resolvePath?: (input: string) => string;
};

type PluginConfigValidation =
  | { ok: true; value?: unknown }
  | { ok: false; errors: string[] };

const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);

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
    defaultNamespace: { type: "string" },
    sealMode: { type: "boolean" },
  },
};

export const phoenixPluginConfigUiHints = {
  server: {
    label: "Phoenix Server URL",
    help: "Phoenix base URL (fallback: PHOENIX_SERVER).",
    placeholder: "https://phoenix:9090",
  },
  token: {
    label: "Phoenix Token",
    help: "Bearer token for Phoenix (fallback: PHOENIX_TOKEN).",
    sensitive: true,
    placeholder: "phoenix_...",
  },
  tokenFile: {
    label: "Phoenix Token File",
    help: "Path to a bearer token file (fallback: PHOENIX_TOKEN_FILE). Prefer this over embedding token values in config.",
    sensitive: true,
  },
  sealKeyFile: {
    label: "Phoenix Seal Key File",
    help: "Path to the agent's persistent X25519 seal private key file (fallback: PHOENIX_SEAL_KEY). Required when sealMode is enabled.",
    sensitive: true,
  },
  caCert: {
    label: "CA Certificate Path",
    help: "Optional CA certificate path for custom TLS trust (fallback: PHOENIX_CA_CERT).",
  },
  clientCert: {
    label: "Client Certificate Path",
    help: "Optional client certificate path for mTLS (fallback: PHOENIX_CLIENT_CERT).",
  },
  clientKey: {
    label: "Client Key Path",
    help: "Optional client key path for mTLS (fallback: PHOENIX_CLIENT_KEY).",
    sensitive: true,
  },
  defaultNamespace: {
    label: "Default Namespace",
    help: "Namespace used when callers pass bare secret ids instead of full phoenix:// refs.",
  },
  sealMode: {
    label: "Sealed Mode",
    help: "Return opaque PHOENIX_SEALED tokens instead of plaintext values.",
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

export function resolvePhoenixPluginConfig(
  value: unknown,
  options: ResolvePhoenixPluginConfigOptions = {},
): PhoenixPluginConfig {
  const env = options.env ?? process.env;
  const resolvePath = options.resolvePath ?? ((input: string) => input);
  const raw = isRecord(value) ? value : {};

  const server = readString(raw.server) ?? readString(env.PHOENIX_SERVER);
  if (!server) {
    throw new Error("phoenix-secrets config requires server (or PHOENIX_SERVER)");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(server);
  } catch {
    throw new Error(`phoenix-secrets server must be a valid URL: ${server}`);
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(`phoenix-secrets server must use http:// or https://: ${server}`);
  }

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

  if (!token && !tokenFile && !(clientCert && clientKey)) {
    throw new Error(
      "phoenix-secrets config requires token auth, tokenFile auth, or both clientCert and clientKey for mTLS",
    );
  }

  if ((clientCert && !clientKey) || (!clientCert && clientKey)) {
    throw new Error("phoenix-secrets mTLS requires both clientCert and clientKey");
  }

  if (sealMode && !sealKeyFile) {
    throw new Error("phoenix-secrets sealMode requires sealKeyFile (or PHOENIX_SEAL_KEY)");
  }

  if (defaultNamespace?.includes(":")) {
    throw new Error("phoenix-secrets defaultNamespace must be a namespace name, not a URI");
  }

  return {
    server: parsedUrl.toString().replace(/\/$/, ""),
    ...(token ? { token } : {}),
    ...(tokenFile ? { tokenFile } : {}),
    ...(sealKeyFile ? { sealKeyFile } : {}),
    ...(caCert ? { caCert } : {}),
    ...(clientCert ? { clientCert } : {}),
    ...(clientKey ? { clientKey } : {}),
    ...(defaultNamespace ? { defaultNamespace } : {}),
    sealMode,
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
