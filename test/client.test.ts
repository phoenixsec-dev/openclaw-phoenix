import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PhoenixClient, PhoenixApiError } from "../src/client.ts";

const TEST_SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
const TEST_SEAL_PUBLIC_KEY = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

async function withServer(
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

async function withSealKeyFile(run: (sealKeyFile: string) => Promise<void>) {
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

test("PhoenixClient resolve sends tool headers and returns plaintext values", async () => {
  await withServer(async (req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/resolve");
    assert.equal(req.headers["x-phoenix-tool"], "phoenix_resolve");
    assert.equal(req.headers["x-openclaw-agent"], "main-agent");

    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        values: {
          "phoenix://openclaw/api-key": "secret-value",
        },
      }),
    );
  }, async (baseUrl) => {
    const client = new PhoenixClient({
      server: baseUrl,
      token: "token",
      defaultNamespace: "openclaw",
      sealMode: false,
    });

    const result = await client.resolve(["api-key"], {
      caller: { agentId: "main-agent" },
    });

    assert.equal(result.mode, "plaintext");
    assert.deepEqual(result.values, {
      "phoenix://openclaw/api-key": "secret-value",
    });
    assert.deepEqual(result.errors, {});
  });
});

test("PhoenixClient reads bearer auth from tokenFile", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-test-"));
  const tokenFile = path.join(dir, "token");
  await fs.writeFile(tokenFile, "file-token\n", { encoding: "utf8", mode: 0o600 });
  try {
    await withServer(async (req, res) => {
      assert.equal(req.headers.authorization, "Bearer file-token");
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ status: "ok" }));
    }, async (baseUrl) => {
      const client = new PhoenixClient({
        server: baseUrl,
        tokenFile,
        sealMode: false,
      });

      const { health } = await client.health();
      assert.equal(health.status, "ok");
    });
  } finally {
    await fs.unlink(tokenFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
});

test("PhoenixClient rejects overly permissive token file permissions", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-token-test-"));
  const tokenFile = path.join(dir, "token");
  await fs.writeFile(tokenFile, "file-token\n", "utf8");
  await fs.chmod(tokenFile, 0o644);
  try {
    const client = new PhoenixClient({
      server: "http://127.0.0.1:1",
      tokenFile,
      sealMode: false,
    });

    await assert.rejects(
      () => client.health(),
      /token file has insecure permissions/,
    );
  } finally {
    await fs.unlink(tokenFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
});

test("PhoenixClient derives a stable seal key header from sealKeyFile", async () => {
  const seenHeaders: string[] = [];
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      seenHeaders.push(String(req.headers["x-phoenix-seal-key"] ?? ""));
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ sealed_values: {} }));
    }, async (baseUrl) => {
      const client = new PhoenixClient({
        server: baseUrl,
        token: "token",
        sealKeyFile,
        sealMode: true,
      });

      await client.resolve(["phoenix://openclaw/api-key"]);
      await client.resolve(["phoenix://openclaw/other-key"]);
    });
  });

  assert.deepEqual(seenHeaders, [TEST_SEAL_PUBLIC_KEY, TEST_SEAL_PUBLIC_KEY]);
});

test("PhoenixClient rejects overly permissive seal key file permissions", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-seal-test-"));
  const sealKeyFile = path.join(dir, "agent.seal.key");
  await fs.writeFile(sealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, "utf8");
  await fs.chmod(sealKeyFile, 0o644);
  try {
    const client = new PhoenixClient({
      server: "http://phoenix:9090",
      token: "token",
      sealKeyFile,
      sealMode: true,
    });

    await assert.rejects(
      () => client.validateSealConfiguration(),
      /seal key file has insecure permissions/,
    );
  } finally {
    await fs.unlink(sealKeyFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
});

test("PhoenixClient resolve returns opaque sealed tokens in sealMode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      assert.equal(req.headers["x-phoenix-seal-key"], TEST_SEAL_PUBLIC_KEY);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          sealed_values: {
            "phoenix://openclaw/api-key": {
              version: 1,
              algorithm: "x25519-xsalsa20-poly1305",
              path: "openclaw/api-key",
              ref: "phoenix://openclaw/api-key",
              ephemeral_key: "abc",
              nonce: "def",
              ciphertext: "ghi",
            },
          },
        }),
      );
    }, async (baseUrl) => {
      const client = new PhoenixClient({
        server: baseUrl,
        token: "token",
        sealKeyFile,
        defaultNamespace: "openclaw",
        sealMode: true,
      });

      const result = await client.resolve(["api-key"]);
      assert.equal(result.mode, "sealed");
      assert.match(result.values["phoenix://openclaw/api-key"], /^PHOENIX_SEALED:/);
    });
  });
});

test("PhoenixClient surfaces structured denial payloads", async () => {
  await withServer(async (_req, res) => {
    res.statusCode = 403;
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        error: "access_denied",
        code: "SCOPE_EXCEEDED",
        detail: 'path "infra/db" is outside session scope',
        remediation: "request a session with the right namespace",
      }),
    );
  }, async (baseUrl) => {
    const client = new PhoenixClient({
      server: baseUrl,
      token: "token",
      sealMode: false,
    });

    await assert.rejects(
      () => client.list("infra/"),
      (error: unknown) => {
        assert.ok(error instanceof PhoenixApiError);
        assert.equal(error.code, "SCOPE_EXCEEDED");
        assert.equal(error.type, "access_denied");
        assert.match(error.message, /outside session scope/);
        return true;
      },
    );
  });
});

test("PhoenixClient status falls back cleanly when /v1/status is forbidden", async () => {
  await withServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/v1/health") {
      res.end(JSON.stringify({ status: "ok", secrets: 3 }));
      return;
    }
    if (req.url === "/v1/status") {
      res.statusCode = 403;
      res.end(JSON.stringify({ error: "access_denied", detail: "admin required" }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  }, async (baseUrl) => {
    const client = new PhoenixClient({
      server: baseUrl,
      token: "token",
      sealMode: false,
    });

    const status = await client.status();
    assert.equal(status.ok, true);
    assert.equal(status.serverVersion, null);
    assert.equal(status.versionSource, "unavailable");
    assert.equal(status.health.status, "ok");
    assert.equal(status.adminStatus, undefined);
    assert.equal(status.adminStatusError?.type, "access_denied");
    assert.ok(status.notes.some((note) => note.includes("does not currently expose the server version")));
  });
});
