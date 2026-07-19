import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readCredentialFile } from "./secure-file.ts";

const SEAL_KEY_SIZE_BYTES = 32;
const X25519_PRIVATE_KEY_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_PUBLIC_KEY_DER_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function decodeSealPrivateKey(raw: string, source: string): Buffer {
  const encoded = raw.trim();
  if (!encoded) {
    throw new Error(`Phoenix seal key file is empty: ${source}`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error(`Phoenix seal key file contains invalid base64: ${source}`);
  }
  const privateKey = Buffer.from(encoded, "base64");
  if (privateKey.length !== SEAL_KEY_SIZE_BYTES) {
    throw new Error(
      `Phoenix seal key file must contain a base64-encoded ${SEAL_KEY_SIZE_BYTES}-byte private key: ${source}`,
    );
  }
  return privateKey;
}

function deriveSealPublicKey(privateKey: Buffer, source: string): Buffer {
  try {
    const keyObject = createPrivateKey({
      key: Buffer.concat([X25519_PRIVATE_KEY_DER_PREFIX, privateKey]),
      format: "der",
      type: "pkcs8",
    });
    const publicDer = createPublicKey(keyObject).export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(publicDer) || publicDer.length !== X25519_PUBLIC_KEY_DER_PREFIX.length + SEAL_KEY_SIZE_BYTES) {
      throw new Error("unexpected X25519 public key export format");
    }
    if (!publicDer.subarray(0, X25519_PUBLIC_KEY_DER_PREFIX.length).equals(X25519_PUBLIC_KEY_DER_PREFIX)) {
      throw new Error("unexpected X25519 public key DER prefix");
    }
    return Buffer.from(publicDer.subarray(X25519_PUBLIC_KEY_DER_PREFIX.length));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not derive Phoenix seal public key from ${source}: ${detail}`);
  }
}

async function loadSealPrivateKey(sealKeyFile: string): Promise<Buffer> {
  const rawPrivateKey = await readCredentialFile(sealKeyFile, "Phoenix seal key");
  return decodeSealPrivateKey(rawPrivateKey, sealKeyFile);
}

export async function buildSealHeader(sealKeyFile: string): Promise<string> {
  const privateKey = await loadSealPrivateKey(sealKeyFile);
  const publicKey = deriveSealPublicKey(privateKey, sealKeyFile);
  return publicKey.toString("base64");
}

export async function fingerprintSealPublicKey(sealKeyFile: string): Promise<string> {
  const sealHeader = await buildSealHeader(sealKeyFile);
  return createHash("sha256").update(sealHeader, "utf8").digest("base64url");
}
