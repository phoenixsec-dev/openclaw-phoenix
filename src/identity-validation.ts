import type { PhoenixPluginConfig } from "./config.ts";
import { PhoenixAccessDeniedError } from "./errors.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import { fingerprintSealPublicKey } from "./seal.ts";
import { fingerprintPhoenixTokenFile } from "./token.ts";

export class PhoenixDuplicateIdentityMaterialError extends PhoenixAccessDeniedError {
  readonly agentId: string;
  readonly existingAgentId: string;
  readonly material: "token" | "seal key";

  constructor(params: {
    agentId: string;
    existingAgentId: string;
    material: "token" | "seal key";
  }) {
    super({
      code: "PHOENIX_DUPLICATE_IDENTITY_MATERIAL",
      message:
        `phoenix-secrets agents.${params.agentId} ${params.material} material must be unique; it matches agents.${params.existingAgentId}`,
      remediation:
        "Configure every mapped OpenClaw agent with distinct Phoenix token and seal key material before using Phoenix tools.",
    });
    this.agentId = params.agentId;
    this.existingAgentId = params.existingAgentId;
    this.material = params.material;
  }
}

export class PhoenixIdentityMaterialError extends PhoenixAccessDeniedError {
  readonly agentId: string;

  constructor(params: { agentId: string; material: "token" | "seal key"; cause: unknown }) {
    super({
      code: "PHOENIX_IDENTITY_MATERIAL_UNREADABLE",
      message: `phoenix-secrets agents.${params.agentId} ${params.material} material could not be validated`,
      // Deliberately omits the underlying path/filesystem error: this detail is
      // model/tool-visible and must not leak another agent's credential paths.
      detail:
        `Cross-agent identity validation could not read agents.${params.agentId} ${params.material} material (missing, unreadable, insecure permissions, or invalid contents).`,
      remediation:
        "Fix the file path, permissions, and contents for that mapped agent (specifics are in the gateway startup preflight warning); every mapped Phoenix identity must be readable before Phoenix tools can run for any agent.",
    });
    this.agentId = params.agentId;
    this.cause = params.cause;
  }
}

export async function validatePhoenixAgentIdentityMaterialUniqueness(
  config: PhoenixPluginConfig,
): Promise<void> {
  const agentConfigs = getPhoenixAgentClientConfigs(config);
  if (agentConfigs.length === 0) {
    return;
  }

  const tokenOwners = new Map<string, string>();
  const sealKeyOwners = new Map<string, string>();

  const fingerprint = async (
    agentId: string,
    material: "token" | "seal key",
    read: () => Promise<string>,
  ): Promise<string> => {
    try {
      return await read();
    } catch (error) {
      throw new PhoenixIdentityMaterialError({ agentId, material, cause: error });
    }
  };

  for (const { agentId, config: agentConfig } of agentConfigs) {
    if (agentConfig.tokenFile) {
      const tokenFile = agentConfig.tokenFile;
      const tokenFingerprint = await fingerprint(agentId, "token", () =>
        fingerprintPhoenixTokenFile(tokenFile),
      );
      const existingAgentId = tokenOwners.get(tokenFingerprint);
      if (existingAgentId) {
        throw new PhoenixDuplicateIdentityMaterialError({
          agentId,
          existingAgentId,
          material: "token",
        });
      }
      tokenOwners.set(tokenFingerprint, agentId);
    }

    if (agentConfig.sealMode && agentConfig.sealKeyFile) {
      const sealKeyFile = agentConfig.sealKeyFile;
      const sealKeyFingerprint = await fingerprint(agentId, "seal key", () =>
        fingerprintSealPublicKey(sealKeyFile),
      );
      const existingAgentId = sealKeyOwners.get(sealKeyFingerprint);
      if (existingAgentId) {
        throw new PhoenixDuplicateIdentityMaterialError({
          agentId,
          existingAgentId,
          material: "seal key",
        });
      }
      sealKeyOwners.set(sealKeyFingerprint, agentId);
    }
  }
}
