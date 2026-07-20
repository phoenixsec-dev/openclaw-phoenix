import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createPhoenixResolveTool, createPhoenixListTool, createPhoenixStatusTool } from "../src/tools.ts";
import {
  runPhoenixStartupCheck,
  runPhoenixStartupPreflightWarningOnly,
} from "../src/startup.ts";
import { verifyPhoenixRefsInConfig } from "../src/cli.ts";
import {
  TEST_SEAL_PRIVATE_KEY,
  TEST_SEAL_PRIVATE_KEY_B,
  TEST_SEAL_PUBLIC_KEY,
  TEST_SEAL_PUBLIC_KEY_B,
  readRequestJson,
  withAgentIdentityFiles,
  withSealKeyFile,
  withServer,
} from "./helpers.ts";

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

test("resolve tool fails closed when sealed mode response only contains plaintext", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      assert.equal(req.headers["x-phoenix-seal-key"], TEST_SEAL_PUBLIC_KEY);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          values: {
            "phoenix://openclaw/key": "plain-secret-that-must-not-appear",
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
      const details = result.details as {
        ok: boolean;
        resolved?: number;
        error?: { type?: string; code?: string; remediation?: string };
      };
      const text = result.content.map((entry) => entry.text).join("\n");
      const serializedDetails = JSON.stringify(result.details);

      assert.equal(details.ok, false);
      assert.equal(details.resolved, undefined);
      assert.equal(details.error?.type, "sealed_response_error");
      assert.equal(details.error?.code, "PHOENIX_SEALED_VALUES_MISSING");
      assert.match(details.error?.remediation ?? "", /sealed response contract/);
      assert.doesNotMatch(text, /plain-secret-that-must-not-appear/);
      assert.doesNotMatch(serializedDetails, /plain-secret-that-must-not-appear/);
    });
  });
});

test("resolve tool sanitizes HTTP 200 non-JSON bodies in sealed mode", async () => {
  await withSealKeyFile(async (sealKeyFile) => {
    await withServer(async (req, res) => {
      assert.equal(req.headers["x-phoenix-seal-key"], TEST_SEAL_PUBLIC_KEY);
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain");
      res.end("text-plain-fake-secret-body");
    }, async (baseUrl) => {
      const resolveTool = createPhoenixResolveTool({
        server: baseUrl,
        token: "token",
        sealKeyFile,
        defaultNamespace: "openclaw",
        sealMode: true,
      });
      const result = await resolveTool.execute("tool-1", { refs: ["key"] });
      const details = result.details as {
        ok: boolean;
        error?: { type?: string; code?: string; detail?: string; remediation?: string };
      };
      const text = result.content.map((entry) => entry.text).join("\n");
      const serializedDetails = JSON.stringify(result.details);

      assert.equal(details.ok, false);
      assert.equal(details.error?.type, "sealed_response_error");
      assert.equal(details.error?.code, "PHOENIX_NON_JSON_RESPONSE");
      assert.match(details.error?.detail ?? "", /body was omitted/);
      assert.match(details.error?.remediation ?? "", /JSON API responses/);
      assert.doesNotMatch(text, /text-plain-fake-secret-body/);
      assert.doesNotMatch(serializedDetails, /text-plain-fake-secret-body/);
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

test("runtime tools fail closed when mapped agents share token or seal key material", async () => {
  await withAgentIdentityFiles(async (files) => {
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

    await fs.writeFile(files.kitTokenFile, "main-token\n", { encoding: "utf8", mode: 0o600 });
    const duplicateTokenResults = [
      await createPhoenixResolveTool(config, { agentId: "main" }).execute("tool-resolve", {
        refs: ["key"],
      }),
      await createPhoenixListTool(config, { agentId: "main" }).execute("tool-list", {}),
      await createPhoenixStatusTool(config, { agentId: "main" }).execute(),
    ];

    for (const result of duplicateTokenResults) {
      const details = result.details as {
        ok: boolean;
        error?: { type?: string; code?: string; detail?: string; remediation?: string };
      };
      assert.equal(details.ok, false);
      assert.equal(details.error?.type, "access_denied");
      assert.equal(details.error?.code, "PHOENIX_DUPLICATE_IDENTITY_MATERIAL");
      assert.match(details.error?.detail ?? "", /token material must be unique/);
    }

    await fs.writeFile(files.kitTokenFile, "kit-token\n", { encoding: "utf8", mode: 0o600 });
    await fs.writeFile(files.kitSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    const duplicateSealResult = await createPhoenixResolveTool(config, {
      agentId: "main",
    }).execute("tool-resolve", { refs: ["key"] });
    const duplicateSealDetails = duplicateSealResult.details as {
      ok: boolean;
      error?: { type?: string; code?: string; detail?: string };
    };
    assert.equal(duplicateSealDetails.ok, false);
    assert.equal(duplicateSealDetails.error?.type, "access_denied");
    assert.equal(duplicateSealDetails.error?.code, "PHOENIX_DUPLICATE_IDENTITY_MATERIAL");
    assert.match(duplicateSealDetails.error?.detail ?? "", /seal key material must be unique/);
  });
});

test("runtime tools report which agent's identity material is unreadable", async () => {
  await withAgentIdentityFiles(async (files) => {
    const config = {
      server: "http://127.0.0.1:1",
      sealMode: false,
      agents: {
        main: {
          tokenFile: files.mainTokenFile,
          defaultNamespace: "main-ns",
        },
        kit: {
          tokenFile: files.kitTokenFile,
          defaultNamespace: "kit-ns",
        },
      },
    };

    await fs.unlink(files.kitTokenFile);
    const result = await createPhoenixResolveTool(config, { agentId: "main" }).execute(
      "tool-resolve",
      { refs: ["key"] },
    );
    const details = result.details as {
      ok: boolean;
      error?: { type?: string; code?: string; detail?: string };
    };
    assert.equal(details.ok, false);
    assert.equal(details.error?.type, "access_denied");
    assert.equal(details.error?.code, "PHOENIX_IDENTITY_MATERIAL_UNREADABLE");
    assert.match(details.error?.detail ?? "", /agents\.kit token material/);
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

test("per-agent mapping fails closed for agent ids that name Object.prototype members", async () => {
  const config = {
    server: "http://127.0.0.1:1",
    sealMode: false,
    agents: {
      main: {
        tokenFile: "/tmp/openclaw-phoenix-main-token-not-read",
        defaultNamespace: "main-ns",
      },
    },
  };

  for (const agentId of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
    const result = await createPhoenixResolveTool(config, { agentId }).execute("tool-proto", {
      refs: ["key"],
    });
    const details = result.details as { ok: boolean; error?: { code?: string } };
    assert.equal(details.ok, false, `expected fail-closed for agentId ${agentId}`);
    assert.equal(details.error?.code, "OPENCLAW_AGENT_IDENTITY_UNMAPPED", `agentId ${agentId}`);
  }
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

test("verifyPhoenixRefsInConfig requires a top-level diagnostic seal key in sealed agents mode", async () => {
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
          token: "diagnostic-token",
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
    /top-level diagnostic sealKeyFile.*PHOENIX_SEAL_KEY/,
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
      assert.match(error.message, /PHOENIX_IDENTITY_MATERIAL_UNREADABLE/);
      assert.match(error.message, /per-agent token and seal key file paths and permissions/);
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
    (error: Error) => {
      assert.match(error.message, /Phoenix startup preflight failed/);
      assert.match(error.message, /Phoenix is unreachable/);
      assert.match(error.message, /phoenix-server is running/);
      assert.doesNotMatch(error.message, /rejected the configured credentials/);
      return true;
    },
  );
});

test("runPhoenixStartupCheck distinguishes rejected credentials from unreachable", async () => {
  const probeRequests: Array<{ url: string; authorization: string | undefined }> = [];
  await withServer(async (req, res) => {
    probeRequests.push({
      url: req.url ?? "",
      authorization: typeof req.headers.authorization === "string" ? req.headers.authorization : undefined,
    });
    res.statusCode = 401;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: "unauthorized" }));
  }, async (baseUrl) => {
    await assert.rejects(
      () =>
        runPhoenixStartupCheck({
          server: baseUrl,
          token: "synthetic-invalid-token-value",
          sealMode: false,
        }),
      (error: Error) => {
        assert.match(error.message, /Phoenix startup preflight failed/);
        assert.match(error.message, /reachable but rejected the configured credentials \(HTTP 401\)/);
        assert.doesNotMatch(error.message, /Phoenix is unreachable/);
        assert.doesNotMatch(
          error.message,
          /synthetic-invalid-token-value/,
          "the token value must never appear in preflight messages",
        );
        return true;
      },
    );
  });

  // The probe must be an authenticated read-only endpoint carrying the bearer token.
  assert.equal(probeRequests.length, 1);
  assert.match(probeRequests[0].url, /^\/v1\/policy\/check\?/);
  assert.equal(probeRequests[0].authorization, "Bearer synthetic-invalid-token-value");
});

test("runPhoenixStartupPreflightWarningOnly emits a distinct unauthorized warning", async () => {
  await withServer(async (_req, res) => {
    res.statusCode = 403;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ error: "access denied" }));
  }, async (baseUrl) => {
    const warnings: string[] = [];
    const result = await runPhoenixStartupPreflightWarningOnly(
      {
        server: baseUrl,
        token: "synthetic-denied-token-value",
        sealMode: false,
      },
      { warn: (message) => warnings.push(message) },
    );

    assert.equal(result.ok, false);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /Phoenix startup preflight warning \(non-fatal\)/);
    assert.match(warnings[0], /reachable but rejected the configured credentials \(HTTP 403\)/);
    assert.doesNotMatch(warnings[0], /Phoenix is unreachable/);
    assert.doesNotMatch(warnings[0], /synthetic-denied-token-value/);
  });
});

test("runPhoenixStartupPreflightWarningOnly logs and resolves on connectivity errors", async () => {
  const warnings: string[] = [];
  const result = await runPhoenixStartupPreflightWarningOnly(
    {
      server: "http://127.0.0.1:1",
      token: "token",
      sealMode: false,
    },
    {
      warn: (message) => warnings.push(message),
    },
  );

  assert.equal(result.ok, false);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /non-fatal/);
  assert.match(warnings[0], /Phoenix is unreachable/);
  assert.doesNotMatch(warnings[0], /rejected the configured credentials/);
});

test("runPhoenixStartupPreflightWarningOnly logs and resolves on duplicate per-agent material", async () => {
  await withAgentIdentityFiles(async (files) => {
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

    await fs.writeFile(files.kitTokenFile, "main-token\n", { encoding: "utf8", mode: 0o600 });
    const tokenWarnings: string[] = [];
    const tokenResult = await runPhoenixStartupPreflightWarningOnly(config, {
      warn: (message) => tokenWarnings.push(message),
    });

    assert.equal(tokenResult.ok, false);
    assert.equal(tokenWarnings.length, 1);
    assert.match(tokenWarnings[0], /PHOENIX_DUPLICATE_IDENTITY_MATERIAL/);
    assert.match(tokenWarnings[0], /token material must be unique/);

    await fs.writeFile(files.kitTokenFile, "kit-token\n", { encoding: "utf8", mode: 0o600 });
    await fs.writeFile(files.kitSealKeyFile, `${TEST_SEAL_PRIVATE_KEY}\n`, { encoding: "utf8", mode: 0o600 });
    const sealKeyWarnings: string[] = [];
    const sealKeyResult = await runPhoenixStartupPreflightWarningOnly(config, {
      warn: (message) => sealKeyWarnings.push(message),
    });

    assert.equal(sealKeyResult.ok, false);
    assert.equal(sealKeyWarnings.length, 1);
    assert.match(sealKeyWarnings[0], /PHOENIX_DUPLICATE_IDENTITY_MATERIAL/);
    assert.match(sealKeyWarnings[0], /seal key material must be unique/);
  });
});

test("per-agent mapping fails closed when no runtime agent identity is provided", async () => {
  const config = {
    server: "http://127.0.0.1:1",
    sealMode: false,
    agents: {
      main: {
        tokenFile: "/tmp/openclaw-phoenix-main-token-not-read",
        defaultNamespace: "main-ns",
      },
    },
  };

  for (const caller of [undefined, { agentId: "   " }]) {
    const resolveTool = createPhoenixResolveTool(config, caller);
    const result = await resolveTool.execute("tool-missing-identity", { refs: ["key"] });
    const details = result.details as {
      ok: boolean;
      error?: { type?: string; code?: string };
    };
    assert.equal(details.ok, false);
    assert.equal(details.error?.type, "access_denied");
    assert.equal(details.error?.code, "OPENCLAW_AGENT_IDENTITY_MISSING");
  }
});

test("per-agent sealMode:false overrides top-level sealed mode and resolves plaintext", async () => {
  await withAgentIdentityFiles(async (files) => {
    const seenSealKeyHeaders: Array<string | undefined> = [];
    await withServer(async (req, res) => {
      seenSealKeyHeaders.push(
        typeof req.headers["x-phoenix-seal-key"] === "string"
          ? req.headers["x-phoenix-seal-key"]
          : undefined,
      );
      await readRequestJson(req);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ values: { "phoenix://main-ns/key": "value" } }));
    }, async (baseUrl) => {
      const config = {
        server: baseUrl,
        sealMode: true,
        agents: {
          main: {
            tokenFile: files.mainTokenFile,
            defaultNamespace: "main-ns",
            sealMode: false,
          },
        },
      };

      const resolveTool = createPhoenixResolveTool(config, { agentId: "main" });
      const result = await resolveTool.execute("tool-plain", { refs: ["key"] });
      const details = result.details as { ok: boolean; mode?: string };
      assert.equal(details.ok, true);
      assert.equal(details.mode, "plaintext");
    });

    assert.deepEqual(seenSealKeyHeaders, [undefined]);
  });
});

test("per-agent server override routes requests to the agent's own server", async () => {
  await withAgentIdentityFiles(async (files) => {
    let topLevelRequests = 0;
    let kitRequests = 0;
    await withServer(async (_topReq, topRes) => {
      topLevelRequests += 1;
      topRes.setHeader("content-type", "application/json");
      topRes.end(JSON.stringify({ values: {} }));
    }, async (topLevelUrl) => {
      await withServer(async (req, res) => {
        kitRequests += 1;
        await readRequestJson(req);
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ values: { "phoenix://kit-ns/key": "value" } }));
      }, async (kitUrl) => {
        const config = {
          server: topLevelUrl,
          sealMode: false,
          agents: {
            kit: {
              server: kitUrl,
              tokenFile: files.kitTokenFile,
              defaultNamespace: "kit-ns",
            },
          },
        };

        const resolveTool = createPhoenixResolveTool(config, { agentId: "kit" });
        const result = await resolveTool.execute("tool-kit-server", { refs: ["key"] });
        assert.equal((result.details as { ok: boolean }).ok, true);
      });
    });

    assert.equal(topLevelRequests, 0);
    assert.equal(kitRequests, 1);
  });
});

test("runPhoenixStartupCheck runs an authenticated probe for every mapped agent", async () => {
  await withAgentIdentityFiles(async (files) => {
    const healthAgents: Array<string | undefined> = [];
    const probeTokens: Array<string | undefined> = [];
    await withServer(async (req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/v1/policy/check")) {
        healthAgents.push(
          typeof req.headers["x-openclaw-agent"] === "string"
            ? req.headers["x-openclaw-agent"]
            : undefined,
        );
        probeTokens.push(
          typeof req.headers.authorization === "string" ? req.headers.authorization : undefined,
        );
        res.end(JSON.stringify({ path: "openclaw/startup-preflight-auth-probe", check: "allow_unseal", allowed: false }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not found" }));
    }, async (baseUrl) => {
      const config = {
        server: baseUrl,
        sealMode: false,
        agents: {
          main: {
            tokenFile: files.mainTokenFile,
            defaultNamespace: "main-ns",
          },
          kit: {
            tokenFile: files.kitTokenFile,
            defaultNamespace: "kit-ns",
          },
        },
      };

      await runPhoenixStartupCheck(config);
      assert.deepEqual(healthAgents, ["kit", "main"]);
      assert.deepEqual(probeTokens, ["Bearer kit-token", "Bearer main-token"]);

      healthAgents.length = 0;
      const warnings: string[] = [];
      const preflight = await runPhoenixStartupPreflightWarningOnly(config, {
        warn: (message) => warnings.push(message),
      });
      assert.deepEqual(preflight, { ok: true });
      assert.deepEqual(warnings, []);
    });
  });
});
