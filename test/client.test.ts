import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { PhoenixClient, PhoenixApiError } from "../src/client.ts";

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

test("PhoenixClient resolve returns opaque sealed tokens in sealMode", async () => {
  await withServer(async (req, res) => {
    assert.equal(typeof req.headers["x-phoenix-seal-key"], "string");
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
      defaultNamespace: "openclaw",
      sealMode: true,
    });

    const result = await client.resolve(["api-key"]);
    assert.equal(result.mode, "sealed");
    assert.match(result.values["phoenix://openclaw/api-key"], /^PHOENIX_SEALED:/);
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
