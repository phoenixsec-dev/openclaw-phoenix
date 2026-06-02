import type { PhoenixPluginConfig } from "./config.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import { fingerprintSealPublicKey } from "./seal.ts";
import { fingerprintPhoenixTokenFile } from "./token.ts";

export class PhoenixDuplicateIdentityMaterialError extends Error {
  readonly agentId: string;
  readonly existingAgentId: string;
  readonly material: "token" | "seal key";

  constructor(params: {
    agentId: string;
    existingAgentId: string;
    material: "token" | "seal key";
  }) {
    super(
      `phoenix-secrets agents.${params.agentId} ${params.material} material must be unique; it matches agents.${params.existingAgentId}`,
    );
    this.name = "PhoenixDuplicateIdentityMaterialError";
    this.agentId = params.agentId;
    this.existingAgentId = params.existingAgentId;
    this.material = params.material;
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

  for (const { agentId, config: agentConfig } of agentConfigs) {
    if (agentConfig.tokenFile) {
      const tokenFingerprint = await fingerprintPhoenixTokenFile(agentConfig.tokenFile);
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
      const sealKeyFingerprint = await fingerprintSealPublicKey(agentConfig.sealKeyFile);
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
