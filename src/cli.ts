import type { PhoenixPluginConfig } from "./config.ts";
import { PhoenixClient, formatPhoenixError } from "./client.ts";
import { hasPhoenixAgentMappings } from "./identity.ts";
import { extractPhoenixRefs } from "./refs.ts";

export type PhoenixVerifyResult = {
  refs: string[];
  okCount: number;
  failCount: number;
  values: Record<string, string>;
  errors: Record<string, string>;
};

type PhoenixCliCommand = {
  command: (name: string) => PhoenixCliCommand;
  description: (text: string) => PhoenixCliCommand;
  action: (handler: () => Promise<void> | void) => PhoenixCliCommand;
};

export async function verifyPhoenixRefsInConfig(
  configSnapshot: unknown,
  pluginConfig: PhoenixPluginConfig,
): Promise<PhoenixVerifyResult> {
  const refs = [...extractPhoenixRefs(configSnapshot)].sort((left, right) => left.localeCompare(right));
  if (hasPhoenixAgentMappings(pluginConfig)) {
    if (
      !pluginConfig.token &&
      !pluginConfig.tokenFile &&
      !(pluginConfig.clientCert && pluginConfig.clientKey)
    ) {
      throw new Error(
        "openclaw phoenix verify requires a top-level diagnostic Phoenix identity when per-agent mappings are enabled (token/tokenFile or clientCert/clientKey, plus sealKeyFile or PHOENIX_SEAL_KEY when top-level sealMode is enabled); runtime agent identity comes from ctx.agentId and is not available to this CLI command",
      );
    }
    if (pluginConfig.sealMode && !pluginConfig.sealKeyFile) {
      throw new Error(
        "openclaw phoenix verify requires a top-level diagnostic sealKeyFile (or PHOENIX_SEAL_KEY) when top-level sealMode is enabled; agents.<id>.sealKeyFile entries belong to runtime identities and are not used by this CLI command",
      );
    }
  }

  const client = new PhoenixClient(pluginConfig);
  await client.validateSealConfiguration();

  if (refs.length === 0) {
    return {
      refs,
      okCount: 0,
      failCount: 0,
      values: {},
      errors: {},
    };
  }

  const result = await client.resolve(refs, { dryRun: true });
  const okCount = Object.keys(result.values).length;
  const failCount = Object.keys(result.errors).length;

  return {
    refs,
    okCount,
    failCount,
    values: result.values,
    errors: result.errors,
  };
}

export function registerPhoenixCli(params: {
  program: {
    command: (name: string) => PhoenixCliCommand;
  };
  openClawConfig: unknown;
  pluginConfig: PhoenixPluginConfig;
  logger: {
    info?: (message: string) => void;
    warn?: (message: string) => void;
  };
}) {
  const phoenix = params.program.command("phoenix");
  phoenix.description("Phoenix Secrets Manager helper commands");

  phoenix
    .command("verify")
    .description("Dry-run validate all phoenix:// refs currently present in the gateway config")
    .action(async () => {
      const result = await verifyPhoenixRefsInConfig(params.openClawConfig, params.pluginConfig);
      if (result.refs.length === 0) {
        params.logger.info?.("No phoenix:// refs found in the active OpenClaw config.");
        return;
      }

      params.logger.info?.(
        `Verifying ${result.refs.length} phoenix:// ref(s) against ${params.pluginConfig.server}...`,
      );
      for (const ref of result.refs) {
        if (result.errors[ref]) {
          params.logger.warn?.(`${ref} FAIL (${result.errors[ref]})`);
        } else {
          params.logger.info?.(`${ref} OK`);
        }
      }
      params.logger.info?.(
        `Phoenix verify complete: ${result.okCount} OK, ${result.failCount} FAIL, ${result.refs.length} total.`,
      );
      if (result.failCount > 0) {
        throw new Error(`${result.failCount} Phoenix ref(s) failed verification`);
      }
    });
}

export function formatPhoenixVerifyFailure(error: unknown): string {
  return `Phoenix verify failed: ${formatPhoenixError(error)}`;
}
