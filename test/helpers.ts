import http from "node:http";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const TEST_SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
export const TEST_SEAL_PUBLIC_KEY = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
export const TEST_SEAL_PRIVATE_KEY_B = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
export const TEST_SEAL_PUBLIC_KEY_B = "zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=";

export async function withServer(
  handler: Parameters<typeof http.createServer>[0],
  run: (baseUrl: string) => Promise<void>,
) {
  const server = http.createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to resolve test server address");
  }
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    server.close();
    await once(server, "close");
  }
}

export async function withSealKeyFile(run: (sealKeyFile: string) => Promise<void>) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-seal-test-"));
  const sealKeyFile = path.join(dir, "agent.seal.key");
  await fs.writeFile(sealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await run(sealKeyFile);
  } finally {
    await fs.unlink(sealKeyFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
}

export async function withAgentIdentityFiles(
  run: (files: {
    mainTokenFile: string;
    mainSealKeyFile: string;
    exampleAgentTokenFile: string;
    exampleAgentSealKeyFile: string;
  }) => Promise<void>,
) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-agent-identity-test-"));
  const files = {
    mainTokenFile: path.join(dir, "main.token"),
    mainSealKeyFile: path.join(dir, "main.seal.key"),
    exampleAgentTokenFile: path.join(dir, "example-agent.token"),
    exampleAgentSealKeyFile: path.join(dir, "example-agent.seal.key"),
  };
  await fs.writeFile(files.mainTokenFile, "main-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.exampleAgentTokenFile, "example-agent-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.mainSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.exampleAgentSealKeyFile, `${TEST_SEAL_PRIVATE_KEY_B}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await run(files);
  } finally {
    await fs.unlink(files.mainTokenFile).catch(() => undefined);
    await fs.unlink(files.exampleAgentTokenFile).catch(() => undefined);
    await fs.unlink(files.mainSealKeyFile).catch(() => undefined);
    await fs.unlink(files.exampleAgentSealKeyFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
}

export async function readRequestJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
}
