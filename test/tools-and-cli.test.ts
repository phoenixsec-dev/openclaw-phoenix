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
const TEST_SEAL_PRIVATE_KEY_B = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const TEST_SEAL_PUBLIC_KEY_B = "zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=";

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

async function withAgentIdentityFiles(
  run: (files: {
    mainTokenFile: string;
    mainSealKeyFile: string;
    kitTokenFile: string;
    kitSealKeyFile: string;
  }) => Promise<void>,
) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-agent-identity-test-"));
  const files = {
    mainTokenFile: path.join(dir, "main.token"),
    mainSealKeyFile: path.join(dir, "main.seal.key"),
    kitTokenFile: path.join(dir, "kit.token"),
    kitSealKeyFile: path.join(dir, "kit.seal.key"),
  };
  await fs.writeFile(files.mainTokenFile, "main-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.kitTokenFile, "kit-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.mainSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.kitSealKeyFile, `${TEST_SEAL_PRIVATE_KEY_B}\n`, { encoding: "utf8", mode: 0o600 });
  try {
    await run(files);
  } finally {
    await fs.unlink(files.mainTokenFile).catch(() => undefined);
    await fs.unlink(files.kitTokenFile).catch(() => undefined);
    await fs.unlink(files.mainSealKeyFile).catch(() => undefined);
    await fs.unlink(files.kitSealKeyFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
}

async function readRequestJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
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

test("per-agent identity is selected from runtime context only and keeps sealed output opaque", async () => {
  await withAgentIdentityFiles(async (files) => {
    const seenRequests: Array<{
      authorization?: string;
      sealKey?: string;
      agent?: string;
      refs: unknown;
    }> = [];

    await withServer(async (req, res) => {
      const body = await readRequestJson(req);
      const refs = Array.isArray(body.refs) ? body.refs : [];
      const ref = typeof refs[0] === "string" ? refs[0] : "phoenix://unknown/key";
      seenRequests.push({
        authorization: typeof req.headers.authorization === "string" ? req.headers.authorization : undefined,
        sealKey: typeof req.headers["x-phoenix-seal-key"] === "string" ? req.headers["x-phoenix-seal-key"] : undefined,
        agent: typeof req.headers["x-openclaw-agent"] === "string" ? req.headers["x-openclaw-agent"] : undefined,
        refs,
      });

      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          values: {
            [ref]: "plain-secret-that-must-not-appear",
          },
          sealed_values: {
            [ref]: {
              version: 1,
              algorithm: "x25519-xsalsa20-poly1305",
              path: ref.replace(/^phoenix:\/\//, ""),
              ref,
              ephemeral_key: "abc",
              nonce: "def",
              ciphertext: "ghi",
            },
          },
        }),
      );
    }, async (baseUrl) => {
      const config = {
        server: baseUrl,
        token: "root-token-that-must-not-be-used",
        defaultNamespace: "root-ns-that-must-not-be-used",
        sealMode: true,
        agents: {
          main: {
            tokenFile: files.mainTokenFile,
            sealKeyFile: files.mainSealKeyFile,
            defaultNamespace: "main-ns",
          },
          kit: {
            tokenFile: files.kitTokenFile,
            sealKeyFile: files.kitSealKeyFile,
            defaultNamespace: "kit-ns",
          },
        },
      };

      const mainTool = createPhoenixResolveTool(config, { agentId: "main" });
      const mainResult = await mainTool.execute("tool-main", {
        refs: ["key"],
        agentId: "kit",
        identity: "kit",
        tokenFile: files.kitTokenFile,
      });
      const kitTool = createPhoenixResolveTool(config, { agentId: "kit" });
      const kitResult = await kitTool.execute("tool-kit", {
        refs: ["key"],
        agentId: "main",
        identity: "main",
        tokenFile: files.mainTokenFile,
      });

      for (const result of [mainResult, kitResult]) {
        const text = result.content.map((entry) => entry.text).join("\n");
        const serializedDetails = JSON.stringify(result.details);
        assert.match(text, /PHOENIX_SEALED:/);
        assert.doesNotMatch(text, /plain-secret-that-must-not-appear|main-token|kit-token|root-token-that-must-not-be-used/);
        assert.doesNotMatch(serializedDetails, /plain-secret-that-must-not-appear|main-token|kit-token|root-token-that-must-not-be-used/);
      }
    });

    assert.equal(seenRequests.length, 2);
    assert.deepEqual(seenRequests.map((request) => request.authorization), [
      "Bearer main-token",
      "Bearer kit-token",
    ]);
    assert.deepEqual(seenRequests.map((request) => request.sealKey), [
      TEST_SEAL_PUBLIC_KEY,
      TEST_SEAL_PUBLIC_KEY_B,
    ]);
    assert.deepEqual(seenRequests.map((request) => request.agent), ["main", "kit"]);
    assert.deepEqual(seenRequests.map((request) => request.refs), [
      ["phoenix://main-ns/key"],
      ["phoenix://kit-ns/key"],
    ]);
  });
});

test("per-agent mapping fails closed for unknown or unmapped runtime agents", async () => {
  const resolveTool = createPhoenixResolveTool(
    {
      server: "http://127.0.0.1:1",
      sealMode: false,
      agents: {
        main: {
          tokenFile: "/tmp/openclaw-phoenix-main-token-not-read",
          defaultNamespace: "main-ns",
        },
      },
    },
    { agentId: "unknown" },
  );

  const result = await resolveTool.execute("tool-unknown", { refs: ["key"], agentId: "main" });
  const details = result.details as {
    ok: boolean;
    error: { type?: string; code?: string; remediation?: string; detail?: string };
  };
  const text = result.content.map((entry) => entry.text).join("\n");

  assert.equal(details.ok, false);
  assert.equal(details.error.type, "access_denied");
  assert.equal(details.error.code, "OPENCLAW_AGENT_IDENTITY_UNMAPPED");
  assert.match(details.error.remediation ?? "", /config\.agents\.<agentId>/);
  assert.match(details.error.detail ?? "", /No mapping exists/);
  assert.doesNotMatch(text, /openclaw-phoenix-main-token-not-read/);
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

test("verifyPhoenixRefsInConfig rejects agents-only config without diagnostic identity", async () => {
  await assert.rejects(
    () =>
      verifyPhoenixRefsInConfig(
        {
          env: {
            SECRET: "phoenix://openclaw/key",
          },
        },
        {
          server: "http://127.0.0.1:1",
          sealMode: true,
          agents: {
            main: {
              tokenFile: "/tmp/openclaw-phoenix-main-token-not-read",
              sealKeyFile: "/tmp/openclaw-phoenix-main-seal-key-not-read",
              defaultNamespace: "main-ns",
            },
          },
        },
      ),
    /top-level diagnostic Phoenix identity/,
  );
});

test("runPhoenixStartupCheck reports per-agent token file path and permission errors clearly", async () => {
  await assert.rejects(
    () =>
      runPhoenixStartupCheck({
        server: "http://127.0.0.1:1",
        sealMode: false,
        agents: {
          main: {
            tokenFile: "/tmp/openclaw-phoenix-missing-token-for-startup-test",
            defaultNamespace: "main-ns",
          },
        },
      }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /per-agent token and seal key file paths and permissions/);
      assert.doesNotMatch(error.message, /distinct token and seal key material/);
      return true;
    },
  );
});

test("runPhoenixStartupCheck rejects duplicate per-agent token or seal key material", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-duplicate-identity-test-"));
  const files = {
    mainTokenFile: path.join(dir, "main.token"),
    kitTokenFile: path.join(dir, "kit.token"),
    mainSealKeyFile: path.join(dir, "main.seal.key"),
    kitSealKeyFile: path.join(dir, "kit.seal.key"),
  };
  await fs.writeFile(files.mainTokenFile, "same-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.kitTokenFile, "same-token\n", { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.mainSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
  await fs.writeFile(files.kitSealKeyFile, `${TEST_SEAL_PRIVATE_KEY_B}\n`, { encoding: "utf8", mode: 0o600 });

  const config = {
    server: "http://127.0.0.1:1",
    sealMode: true,
    agents: {
      main: {
        tokenFile: files.mainTokenFile,
        sealKeyFile: files.mainSealKeyFile,
        defaultNamespace: "main-ns",
      },
      kit: {
        tokenFile: files.kitTokenFile,
        sealKeyFile: files.kitSealKeyFile,
        defaultNamespace: "kit-ns",
      },
    },
  };

  try {
    await assert.rejects(
      () => runPhoenixStartupCheck(config),
      /token material must be unique/,
    );

    await fs.writeFile(files.kitTokenFile, "kit-token\n", { encoding: "utf8", mode: 0o600 });
    await fs.writeFile(files.kitSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
    await assert.rejects(
      () => runPhoenixStartupCheck(config),
      /seal key material must be unique/,
    );
  } finally {
    await fs.unlink(files.mainTokenFile).catch(() => undefined);
    await fs.unlink(files.kitTokenFile).catch(() => undefined);
    await fs.unlink(files.mainSealKeyFile).catch(() => undefined);
    await fs.unlink(files.kitSealKeyFile).catch(() => undefined);
    await fs.rmdir(dir).catch(() => undefined);
  }
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
