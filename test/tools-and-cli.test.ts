import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createPhoenixResolveTool, createPhoenixListTool, createPhoenixStatusTool } from "../src/tools.ts";
import { runPhoenixStartupCheck } from "../src/startup.ts";
import { verifyPhoenixRefsInConfig } from "../src/cli.ts";

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

test("tool handlers return structured success payloads", async () => {
  await withServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/v1/resolve") {
      res.end(JSON.stringify({ values: { "phoenix://openclaw/key": "value" } }));
      return;
    }
    if (req.url === "/v1/secrets/openclaw/") {
      res.end(JSON.stringify({ paths: ["openclaw/key"] }));
      return;
    }
    if (req.url === "/v1/health") {
      res.end(JSON.stringify({ status: "ok" }));
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
    const config = {
      server: baseUrl,
      token: "token",
      defaultNamespace: "openclaw",
      sealMode: false,
    };

    const resolveTool = createPhoenixResolveTool(config, { agentId: "main" });
    const resolveResult = await resolveTool.execute("tool-1", { refs: ["key"] });
    assert.equal((resolveResult.details as { ok: boolean }).ok, true);

    const listTool = createPhoenixListTool(config);
    const listResult = await listTool.execute("tool-2", {});
    assert.equal((listResult.details as { count: number }).count, 1);

    const statusTool = createPhoenixStatusTool(config);
    const statusResult = await statusTool.execute("tool-3", {});
    assert.equal((statusResult.details as { ok: boolean }).ok, true);
  });
});

test("resolve tool keeps sealed output opaque and excludes plaintext values", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      assert.equal(req.headers["x-phoenix-seal-key"], TEST_SEAL_PUBLIC_KEY);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          values: {
            "phoenix://openclaw/key": "plain-secret-that-must-not-appear",
          },
          sealed_values: {
            "phoenix://openclaw/key": {
              version: 1,
              algorithm: "x25519-xsalsa20-poly1305",
              path: "openclaw/key",
              ref: "phoenix://openclaw/key",
              ephemeral_key: "abc",
              nonce: "def",
              ciphertext: "ghi",
            },
          },
        }),
      );
    }, async (baseUrl) => {
      const resolveTool = createPhoenixResolveTool({
        server: baseUrl,
        token: "token",
        sealKeyFile,
        defaultNamespace: "openclaw",
        sealMode: true,
      });
      const result = await resolveTool.execute("tool-1", { refs: ["key"] });
      const text = result.content.map((entry) => entry.text).join("\n");
      const serializedDetails = JSON.stringify(result.details);

      assert.match(text, /PHOENIX_SEALED:/);
      assert.doesNotMatch(text, /plain-secret-that-must-not-appear/);
      assert.doesNotMatch(serializedDetails, /plain-secret-that-must-not-appear/);
    });
  });
});

test("tool handlers return structured remediation errors", async () => {
  await withServer(async (_req, res) => {
    res.statusCode = 403;
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        error: "access_denied",
        code: "ATTESTATION_FAILED",
        detail: "attestation requirements not met",
        remediation: "retry from an attested runtime",
      }),
    );
  }, async (baseUrl) => {
    const config = {
      server: baseUrl,
      token: "token",
      sealMode: false,
    };
    const resolveTool = createPhoenixResolveTool(config);
    const result = await resolveTool.execute("tool-1", { refs: ["phoenix://secure/key"] });
    const details = result.details as {
      ok: boolean;
      error: { code?: string; remediation?: string };
    };
    assert.equal(details.ok, false);
    assert.equal(details.error.code, "ATTESTATION_FAILED");
    assert.equal(details.error.remediation, "retry from an attested runtime");
  });
});

test("verifyPhoenixRefsInConfig scans config and dry-runs all refs", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      assert.equal(req.url, "/v1/resolve?dry_run=true");
      assert.equal(req.headers["x-phoenix-seal-key"], TEST_SEAL_PUBLIC_KEY);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          values: { "phoenix://openclaw/good": "ok" },
          errors: { "phoenix://openclaw/missing": "secret not found" },
        }),
      );
    }, async (baseUrl) => {
      const report = await verifyPhoenixRefsInConfig(
        {
          agents: {
            defaults: {
              env: {
                GOOD: "phoenix://openclaw/good",
                MISSING: "phoenix://openclaw/missing",
              },
            },
          },
        },
        {
          server: baseUrl,
          token: "token",
          sealKeyFile,
          sealMode: true,
        },
      );

      assert.deepEqual(report.refs, ["phoenix://openclaw/good", "phoenix://openclaw/missing"]);
      assert.equal(report.okCount, 1);
      assert.equal(report.failCount, 1);
    });
  });
});

test("runPhoenixStartupCheck validates seal key config before health", async () => {
  await assert.rejects(
    () =>
      runPhoenixStartupCheck({
        server: "http://127.0.0.1:1",
        token: "token",
        sealKeyFile: "/nonexistent/openclaw-phoenix-test.seal.key",
        sealMode: true,
      }),
    /seal key/,
  );
});

test("runPhoenixStartupCheck throws actionable connectivity errors", async () => {
  await assert.rejects(
    () =>
      runPhoenixStartupCheck({
        server: "http://127.0.0.1:1",
        token: "token",
        sealMode: false,
      }),
    /Phoenix startup preflight failed/,
  );
});
