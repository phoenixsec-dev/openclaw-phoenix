import fs from "node:fs/promises";
import { createHash } from "node:crypto";
import type { PhoenixPluginConfig } from "./config.ts";
import { getPhoenixAgentClientConfigs } from "./identity.ts";
import { fingerprintSealPublicKey } from "./seal.ts";

function fingerprintToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("base64url");
}

async function fingerprintTokenFile(tokenFile: string): Promise<string> {
  const raw = await fs.readFile(tokenFile, "utf8");
  const token = raw.trim();
  if (!token) {
    throw new Error(`Phoenix token file is empty: ${tokenFile}`);
  }
  return fingerprintToken(token);
}

function duplicateIdentityMaterialError(params: {
  agentId: string;
  existingAgentId: string;
  material: "token" | "seal key";
}): Error {
  return new Error(
    `phoenix-secrets agents.${params.agentId} ${params.material} material must be unique; it matches agents.${params.existingAgentId}`,
  );
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
      const tokenFingerprint = await fingerprintTokenFile(agentConfig.tokenFile);
      const existingAgentId = tokenOwners.get(tokenFingerprint);
      if (existingAgentId) {
        throw duplicateIdentityMaterialError({
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
        throw duplicateIdentityMaterialError({
          agentId,
          existingAgentId,
          material: "seal key",
        });
      }
      sealKeyOwners.set(sealKeyFingerprint, agentId);
    }
  }
}
