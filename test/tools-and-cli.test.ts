import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { createPhoenixResolveTool, createPhoenixListTool, createPhoenixStatusTool } from "../src/tools.ts";
import { runPhoenixStartupCheck } from "../src/startup.ts";
import { verifyPhoenixRefsInConfig } from "../src/cli.ts";

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
  await withServer(async (req, res) => {
    assert.equal(req.url, "/v1/resolve?dry_run=true");
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
        sealMode: false,
      },
    );

    assert.deepEqual(report.refs, ["phoenix://openclaw/good", "phoenix://openclaw/missing"]);
    assert.equal(report.okCount, 1);
    assert.equal(report.failCount, 1);
  });
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
