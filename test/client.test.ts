import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { PhoenixClient, PhoenixApiError } from "../src/client.ts";
import {
  TEST_SEAL_PRIVATE_KEY,
  TEST_SEAL_PUBLIC_KEY,
  readRequestJson,
  withSealKeyFile,
  withServer,
} from "./helpers.ts";

function testSealedEnvelope(ref: string) {
  return {
    version: 1,
    algorithm: "x25519-xsalsa20-poly1305",
    path: ref.replace(/^phoenix:\/\//, ""),
    ref,
    ephemeral_key: "abc",
    nonce: "def",
    ciphertext: "ghi",
  };
}

async function withTempDir(run: (dir: string) => Promise<void>) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-phoenix-credential-test-"));
  try {
    await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
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
      const body = await readRequestJson(req);
      const refs = Array.isArray(body.refs) ? body.refs.filter((entry): entry is string => typeof entry === "string") : [];
      const ref = refs[0] ?? "phoenix://openclaw/api-key";
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ sealed_values: { [ref]: testSealedEnvelope(ref) } }));
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
      server: "http://127.0.0.1:1",
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
            "phoenix://openclaw/api-key": testSealedEnvelope("phoenix://openclaw/api-key"),
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

test("PhoenixClient resolve rejects malformed sealed envelopes in sealMode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (_req, res) => {
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

      await assert.rejects(
        () => client.resolve(["api-key"]),
        (error: unknown) => {
          assert.ok(error instanceof PhoenixApiError);
          assert.equal(error.type, "sealed_response_error");
          assert.equal(error.code, "PHOENIX_SEALED_VALUES_INVALID");
          assert.match(error.detail ?? "", /malformed or did not match the requested ref/);
          assert.match(error.detail ?? "", /phoenix:\/\/openclaw\/api-key/);
          return true;
        },
      );
    });
  });
});

test("PhoenixClient resolve rejects wrong-ref sealed envelopes in sealMode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          sealed_values: {
            "phoenix://openclaw/api-key": testSealedEnvelope("phoenix://openclaw/other-key"),
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

      await assert.rejects(
        () => client.resolve(["api-key"]),
        (error: unknown) => {
          assert.ok(error instanceof PhoenixApiError);
          assert.equal(error.type, "sealed_response_error");
          assert.equal(error.code, "PHOENIX_SEALED_VALUES_INVALID");
          assert.match(error.detail ?? "", /phoenix:\/\/openclaw\/api-key/);
          assert.doesNotMatch(error.detail ?? "", /other-key/);
          return true;
        },
      );
    });
  });
});

test("PhoenixClient resolve ignores unrequested sealed_values in sealMode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          sealed_values: {
            "phoenix://openclaw/requested": testSealedEnvelope("phoenix://openclaw/requested"),
            "phoenix://openclaw/extra": testSealedEnvelope("phoenix://openclaw/extra"),
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

      const result = await client.resolve(["requested"]);
      assert.deepEqual(Object.keys(result.values), ["phoenix://openclaw/requested"]);
      assert.equal(result.values["phoenix://openclaw/extra"], undefined);
    });
  });
});

test("PhoenixClient resolve fails closed and refuses plaintext when sealed_values is missing in sealMode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          values: {
            "phoenix://openclaw/api-key": "plain-secret-that-must-not-appear",
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

      await assert.rejects(
        () => client.resolve(["api-key"]),
        (error: unknown) => {
          assert.ok(error instanceof PhoenixApiError);
          assert.equal(error.type, "sealed_response_error");
          assert.equal(error.code, "PHOENIX_SEALED_VALUES_MISSING");
          assert.equal(error.status, 200);
          assert.match(error.detail ?? "", /omitted sealed_values envelope/);
          assert.doesNotMatch(JSON.stringify(error.toJSON()), /plain-secret-that-must-not-appear/);
          return true;
        },
      );
    });
  });
});

test("PhoenixClient resolve allows partial sealed success with per-ref errors", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (_req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          sealed_values: {
            "phoenix://openclaw/good": testSealedEnvelope("phoenix://openclaw/good"),
          },
          errors: {
            "phoenix://openclaw/missing": "secret not found",
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

      const result = await client.resolve(["good", "missing"]);
      assert.equal(result.mode, "sealed");
      assert.match(result.values["phoenix://openclaw/good"], /^PHOENIX_SEALED:/);
      assert.deepEqual(result.errors, {
        "phoenix://openclaw/missing": "secret not found",
      });
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

test("PhoenixClient rejects seal key files with invalid content", async () => {
  await withTempDir(async (dir) => {
    const cases: Array<{ name: string; content: string | null; expected: RegExp }> = [
      { name: "empty", content: "", expected: /empty/ },
      { name: "invalid-base64", content: "not-base64!!", expected: /invalid base64/ },
      { name: "wrong-length", content: Buffer.alloc(16, 7).toString("base64"), expected: /32-byte/ },
      { name: "directory", content: null, expected: /must be a file/ },
    ];

    for (const testCase of cases) {
      let sealKeyFile: string;
      if (testCase.content === null) {
        sealKeyFile = path.join(dir, testCase.name);
        await fs.mkdir(sealKeyFile, { mode: 0o700 });
      } else {
        sealKeyFile = path.join(dir, testCase.name);
        await fs.writeFile(sealKeyFile, testCase.content, { encoding: "utf8", mode: 0o600 });
      }

      const client = new PhoenixClient({
        server: "http://127.0.0.1:1",
        token: "token",
        sealKeyFile,
        sealMode: true,
      });

      await assert.rejects(
        () => client.validateSealConfiguration(),
        testCase.expected,
        `expected seal key case ${testCase.name} to be rejected`,
      );
    }
  });
});

test("PhoenixClient rejects token files with invalid content", async () => {
  await withTempDir(async (dir) => {
    const emptyTokenFile = path.join(dir, "empty-token");
    await fs.writeFile(emptyTokenFile, "", { encoding: "utf8", mode: 0o600 });
    const emptyClient = new PhoenixClient({
      server: "http://127.0.0.1:1",
      tokenFile: emptyTokenFile,
      sealMode: false,
    });
    await assert.rejects(() => emptyClient.health(), /empty/);

    const directoryTokenFile = path.join(dir, "token-dir");
    await fs.mkdir(directoryTokenFile, { mode: 0o700 });
    const directoryClient = new PhoenixClient({
      server: "http://127.0.0.1:1",
      tokenFile: directoryTokenFile,
      sealMode: false,
    });
    await assert.rejects(() => directoryClient.health(), /must be a file/);
  });
});

test("PhoenixClient rejects non-JSON responses in plaintext mode", async () => {
  await withServer(async (_req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("not json");
  }, async (baseUrl) => {
    const client = new PhoenixClient({
      server: baseUrl,
      token: "token",
      defaultNamespace: "openclaw",
      sealMode: false,
    });

    await assert.rejects(
      () => client.resolve(["api-key"]),
      (error: unknown) => {
        assert.ok(error instanceof PhoenixApiError);
        assert.equal(error.type, "http_error");
        assert.equal(error.code, "PHOENIX_NON_JSON_RESPONSE");
        return true;
      },
    );
  });
});

test("PhoenixClient surfaces approval_required on HTTP 202", async () => {
  await withServer(async (_req, res) => {
    res.statusCode = 202;
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        status: "approval_required",
        approval_id: "ap_1",
        expires_at: "2026-01-01T00:00:00Z",
        error: "approval required",
      }),
    );
  }, async (baseUrl) => {
    const client = new PhoenixClient({
      server: baseUrl,
      token: "token",
      defaultNamespace: "openclaw",
      sealMode: false,
    });

    await assert.rejects(
      () => client.resolve(["api-key"]),
      (error: unknown) => {
        assert.ok(error instanceof PhoenixApiError);
        assert.equal(error.type, "approval_required");
        assert.equal(error.approvalId, "ap_1");
        assert.equal(error.expiresAt, "2026-01-01T00:00:00Z");
        return true;
      },
    );
  });
});
