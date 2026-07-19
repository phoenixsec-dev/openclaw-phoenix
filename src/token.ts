import { createHash } from "node:crypto";
import { readCredentialFile } from "./secure-file.ts";

export async function readPhoenixTokenFile(tokenFile: string): Promise<string> {
  const raw = await readCredentialFile(tokenFile, "Phoenix token");
  const token = raw.trim();
  if (!token) {
    throw new Error(`Phoenix token file is empty: ${tokenFile}`);
  }
  return token;
}

export async function fingerprintPhoenixTokenFile(tokenFile: string): Promise<string> {
  const token = await readPhoenixTokenFile(tokenFile);
  return createHash("sha256").update(token, "utf8").digest("base64url");
}
