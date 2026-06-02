import fs from "node:fs/promises";
import { createHash } from "node:crypto";

export async function readPhoenixTokenFile(tokenFile: string): Promise<string> {
  const stat = await fs.stat(tokenFile);
  if (!stat.isFile()) {
    throw new Error(`Phoenix token path must be a file: ${tokenFile}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `Phoenix token file has insecure permissions: ${tokenFile} must not be readable, writable, or executable by group or others`,
    );
  }

  const raw = await fs.readFile(tokenFile, "utf8");
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
