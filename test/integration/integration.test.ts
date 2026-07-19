import test from "node:test";
import assert from "node:assert/strict";
import fsp from "node:fs/promises";
import path from "node:path";
import {
  detectPhoenixAvailability,
  ensurePhoenixBinaries,
  getFreePort,
  phoenixServerVersion,
  writeCredentialFile,
  PhoenixServer,
} from "./harness.ts";
import { createPhoenixListTool, createPhoenixResolveTool, createPhoenixStatusTool } from "../../src/tools.ts";
import { runPhoenixStartupCheck, runPhoenixStartupPreflightWarningOnly } from "../../src/startup.ts";
import { verifyPhoenixRefsInConfig } from "../../src/cli.ts";
import type { PhoenixPluginConfig } from "../../src/config.ts";
import type { ToolResult } from "../../src/tool-helpers.ts";

const SEALED_TOKEN_PREFIX = "PHOENIX_SEALED:";

type AuditEntry = {
  agent?: string;
  action?: string;
  path?: string;
  status?: string;
  reason?: string;
  metadata?: Record<string, string>;
};

function toolDetails(result: ToolResult): Record<string, unknown> {
  return result.details as Record<string, unknown>;
}

function decodeSealedToken(token: string): Record<string, unknown> {
  assert.ok(token.startsWith(SEALED_TOKEN_PREFIX), `sealed value must start with ${SEALED_TOKEN_PREFIX}`);
  const decoded = Buffer.from(token.slice(SEALED_TOKEN_PREFIX.length), "base64").toString("utf8");
  return JSON.parse(decoded) as Record<string, unknown>;
}

const availability = detectPhoenixAvailability();

if (!availability.ok) {
  test("Phoenix server integration", { skip: availability.reason }, () => {});
} else {
  test("Phoenix server integration", async (t) => {
    const binaries = await ensurePhoenixBinaries(availability);
    t.diagnostic(`phoenix-server version: ${phoenixServerVersion(binaries)}`);
    t.diagnostic(
      availability.mode === "prebuilt"
        ? `using prebuilt binaries: ${binaries.serverBin}`
        : `built from Phoenix checkout: ${availability.srcDir}`,
    );

    const server = new PhoenixServer(binaries);
    t.after(async () => {
      await server.dispose();
    });
    await server.init();
    await server.start();

    // Seed synthetic secrets and two agents: one with read access to the
    // openclaw-int namespaces, one scoped to an unrelated namespace.
    server.cliOk(["set", "openclaw-int/api-key", "-v", "synthetic-value-1"]);
    server.cliOk(["set", "openclaw-int/db-pass", "-v", "synthetic-value-2"]);
    server.cliOk(["set", "openclaw-int/verify-only", "-v", "synthetic-verify-value"]);
    server.cliOk(["set", "openclaw-sealedonly/key", "-v", "synthetic-sealed-value"]);
    server.cliOk(["set", "other-ns/secret", "-v", "synthetic-other-value"]);
    server.cliOk([
      "agent",
      "create",
      "int-main",
      "-t",
      "synthetic-int-main-token",
      "--acl",
      "openclaw-int/*:read;openclaw-sealedonly/*:read",
    ]);
    server.cliOk([
      "agent",
      "create",
      "int-outsider",
      "-t",
      "synthetic-int-outsider-token",
      "--acl",
      "other-ns/*:read",
    ]);

    const mainSealKeyFile = path.join(server.runDir, "int-main.seal.key");
    server.cliOk(["keypair", "generate", "int-main", "-o", mainSealKeyFile]);
    const sealKeyStat = await fsp.stat(mainSealKeyFile);
    assert.equal(sealKeyStat.mode & 0o777, 0o600, "phoenix keypair generate writes a 0600 private key file");

    const mainTokenFile = path.join(server.runDir, "int-main.token");
    const outsiderTokenFile = path.join(server.runDir, "int-outsider.token");
    await writeCredentialFile(mainTokenFile, "synthetic-int-main-token");
    await writeCredentialFile(outsiderTokenFile, "synthetic-int-outsider-token");

    const mainConfig: PhoenixPluginConfig = {
      server: server.url,
      tokenFile: mainTokenFile,
      defaultNamespace: "openclaw-int",
      sealMode: false,
    };
    const outsiderConfig: PhoenixPluginConfig = {
      server: server.url,
      tokenFile: outsiderTokenFile,
      defaultNamespace: "openclaw-int",
      sealMode: false,
    };
    const sealedConfig: PhoenixPluginConfig = {
      ...mainConfig,
      sealMode: true,
      sealKeyFile: mainSealKeyFile,
    };

    await t.test("phoenix_resolve round-trips real values", async () => {
      const tool = createPhoenixResolveTool(mainConfig, { agentId: "main" });
      const result = toolDetails(
        await tool.execute("call-resolve-ok", { refs: ["phoenix://openclaw-int/api-key", "db-pass"] }),
      );
      assert.equal(result.ok, true);
      assert.equal(result.partial, false);
      assert.equal(result.mode, "plaintext");
      assert.equal(result.requested, 2);
      assert.equal(result.resolved, 2);
      assert.deepEqual(result.values, {
        "phoenix://openclaw-int/api-key": "synthetic-value-1",
        "phoenix://openclaw-int/db-pass": "synthetic-value-2",
      });
      assert.deepEqual(result.errors, {});
    });

    await t.test("phoenix_resolve reports missing refs per id and flags partial results", async () => {
      const tool = createPhoenixResolveTool(mainConfig, { agentId: "main" });
      const result = toolDetails(
        await tool.execute("call-resolve-missing", {
          refs: ["phoenix://openclaw-int/api-key", "phoenix://openclaw-int/does-not-exist"],
        }),
      );
      assert.equal(result.ok, false);
      assert.equal(result.partial, true);
      assert.equal(result.resolved, 1);
      const errors = result.errors as Record<string, string>;
      assert.equal(errors["phoenix://openclaw-int/does-not-exist"], "secret not found");
      assert.equal(
        (result.values as Record<string, string>)["phoenix://openclaw-int/api-key"],
        "synthetic-value-1",
      );
    });

    await t.test("phoenix_resolve denied ACL surfaces per-ref access errors", async (st) => {
      // Observed Phoenix behavior: /v1/resolve answers HTTP 200 with a per-ref
      // "access denied: read_value permission required" error (not an HTTP 403),
      // so the tool reports ok:false with a per-ref error rather than a
      // top-level access_denied payload.
      const tool = createPhoenixResolveTool(outsiderConfig, { agentId: "outsider" });
      const result = toolDetails(
        await tool.execute("call-resolve-denied", { refs: ["phoenix://openclaw-int/api-key"] }),
      );
      assert.equal(result.ok, false);
      assert.equal(result.partial, false);
      assert.equal(result.resolved, 0);
      assert.equal(result.error, undefined, "denied ACL is per-ref, not a top-level error");
      const errors = result.errors as Record<string, string>;
      assert.match(errors["phoenix://openclaw-int/api-key"], /access denied/);
      st.diagnostic(`denied-ACL per-ref error: ${errors["phoenix://openclaw-int/api-key"]}`);
    });

    await t.test("phoenix_list lists seeded paths and returns empty for unauthorized prefixes", async (st) => {
      // No explicit prefix: the tool lists under the configured defaultNamespace.
      const tool = createPhoenixListTool(mainConfig, { agentId: "main" });
      const result = toolDetails(await tool.execute("call-list-ok", {}));
      assert.equal(result.ok, true);
      assert.equal(result.prefix, "openclaw-int/");
      assert.deepEqual(result.paths, [
        "openclaw-int/api-key",
        "openclaw-int/db-pass",
        "openclaw-int/verify-only",
      ]);
      assert.equal(result.count, 3);

      // Observed Phoenix behavior: listing a prefix the agent cannot read is
      // not an error; the server answers HTTP 200 with "paths": null, so the
      // tool reports ok:true with an empty listing.
      const outsiderTool = createPhoenixListTool(outsiderConfig, { agentId: "outsider" });
      const denied = toolDetails(await outsiderTool.execute("call-list-denied", {}));
      assert.equal(denied.ok, true);
      assert.equal(denied.count, 0);
      assert.deepEqual(denied.paths, []);
      st.diagnostic("unauthorized phoenix_list is an empty listing (HTTP 200, paths:null), not an error");
    });

    await t.test("phoenix_status reports health and bearer auth mode", async () => {
      const tool = createPhoenixStatusTool(mainConfig, { agentId: "main" });
      const result = toolDetails(await tool.execute("call-status", {}));
      assert.equal(result.ok, true);
      assert.equal(result.authMode, "bearer");
      assert.equal(result.server, server.url);
      const health = result.health as Record<string, unknown>;
      assert.equal(health.status, "ok");
      // Non-admin bearer tokens cannot read /v1/status; the tool degrades to a note.
      const adminStatusError = result.adminStatusError as Record<string, unknown>;
      assert.equal(adminStatusError.type, "access_denied");
    });

    await t.test("sealed mode returns opaque envelopes and never the plaintext", async () => {
      const tool = createPhoenixResolveTool(sealedConfig, { agentId: "main" });
      const rawResult = await tool.execute("call-resolve-sealed", {
        refs: ["phoenix://openclaw-int/api-key"],
      });
      const serialized = JSON.stringify(rawResult);
      assert.ok(!serialized.includes("synthetic-value-1"), "plaintext must not appear in the sealed tool result");

      const result = toolDetails(rawResult);
      assert.equal(result.ok, true);
      assert.equal(result.mode, "sealed");
      const sealedToken = (result.values as Record<string, string>)["phoenix://openclaw-int/api-key"];
      const envelope = decodeSealedToken(sealedToken);
      assert.equal(envelope.ref, "phoenix://openclaw-int/api-key");
      assert.equal(envelope.path, "openclaw-int/api-key");
      assert.equal(typeof envelope.algorithm, "string");
      assert.equal(typeof envelope.ciphertext, "string");
      assert.ok(!JSON.stringify(envelope).includes("synthetic-value-1"));
    });

    await t.test("startup preflight succeeds against the live server with per-agent mappings", async () => {
      const config: PhoenixPluginConfig = {
        server: server.url,
        sealMode: false,
        agents: {
          main: { tokenFile: mainTokenFile, defaultNamespace: "openclaw-int" },
          kit: { tokenFile: outsiderTokenFile, defaultNamespace: "other-ns" },
        },
      };
      await runPhoenixStartupCheck(config);
      const preflight = await runPhoenixStartupPreflightWarningOnly(config);
      assert.deepEqual(preflight, { ok: true });
    });

    await t.test("startup preflight fails with an actionable error when the server is down", async () => {
      const unusedPort = await getFreePort();
      const config: PhoenixPluginConfig = {
        server: `http://127.0.0.1:${unusedPort}`,
        token: "synthetic-unused-token",
        sealMode: false,
      };
      await assert.rejects(runPhoenixStartupCheck(config), (error: Error) => {
        assert.match(error.message, /Phoenix startup preflight failed/);
        assert.match(error.message, /Could not reach Phoenix at http:\/\/127\.0\.0\.1:\d+/);
        assert.match(error.message, /Check the server URL/);
        return true;
      });
      const warnings: string[] = [];
      const preflight = await runPhoenixStartupPreflightWarningOnly(config, {
        warn: (message) => warnings.push(message),
      });
      assert.equal(preflight.ok, false);
      assert.equal(warnings.length, 1);
      assert.match(warnings[0], /Phoenix startup preflight warning \(non-fatal\)/);
    });

    await t.test("startup preflight does not validate bearer tokens (health is unauthenticated)", async (st) => {
      // Observed Phoenix behavior: GET /v1/health answers HTTP 200 regardless of
      // the Authorization header, so a preflight configured with a bad token
      // still succeeds. Token validity is only checked on first real use
      // (resolve/list). If this assertion ever fails, Phoenix started
      // authenticating /v1/health and the preflight gained token validation.
      const config: PhoenixPluginConfig = {
        server: server.url,
        token: "synthetic-bogus-token-that-is-not-registered",
        sealMode: false,
      };
      await runPhoenixStartupCheck(config);
      st.diagnostic("GET /v1/health is unauthenticated: preflight passes even with an invalid token");
    });

    await t.test("verifyPhoenixRefsInConfig dry-runs refs without reading values", async (st) => {
      const configSnapshot = {
        channels: { alpha: { apiKey: "phoenix://openclaw-int/verify-only" } },
        notes: ["inline mention of phoenix://openclaw-int/api-key here"],
        broken: "phoenix://openclaw-int/bogus-ref",
      };
      const result = await verifyPhoenixRefsInConfig(configSnapshot, mainConfig);
      assert.deepEqual(result.refs, [
        "phoenix://openclaw-int/api-key",
        "phoenix://openclaw-int/bogus-ref",
        "phoenix://openclaw-int/verify-only",
      ]);
      assert.equal(result.okCount, 2);
      assert.equal(result.failCount, 1);
      assert.equal(result.errors["phoenix://openclaw-int/bogus-ref"], "secret not found");
      // Observed Phoenix behavior: dry_run=true answers with the literal
      // placeholder "ok" per resolvable ref, never the secret value.
      assert.equal(result.values["phoenix://openclaw-int/verify-only"], "ok");
      st.diagnostic("dry-run resolve returns placeholder \"ok\" values, not plaintext");

      // Observed Phoenix behavior: the dry run IS audited, but as a dedicated
      // "dry-resolve" action; no value-reading action is recorded.
      const audit = await server.adminGet("/v1/audit");
      assert.equal(audit.statusCode, 200);
      const entries = ((audit.body as { entries?: AuditEntry[] }).entries ?? []).filter(
        (entry) => entry.path === "openclaw-int/verify-only",
      );
      // The seeding `phoenix set` also leaves audit entries for this path, so
      // assert on the presence/absence of specific actions rather than "all".
      assert.ok(
        entries.some((entry) => entry.action === "dry-resolve" && entry.agent === "int-main"),
        "dry-run leaves a dry-resolve audit trail",
      );
      assert.ok(!entries.some((entry) => entry.action === "read_value" || entry.action === "resolve"));
      assert.ok(!audit.raw.includes("synthetic-verify-value"), "audit log must not contain the secret value");
      st.diagnostic("dry-run is audited as action=dry-resolve (never read_value/resolve)");
    });

    await t.test("audit captures X-OpenClaw-* hints but never the session key or secret values", async () => {
      const tool = createPhoenixResolveTool(mainConfig, {
        agentId: "integration-agent",
        sessionKey: "synthetic-session-key-sentinel",
        sessionId: "session-int-1",
        messageChannel: "integration-channel",
        requesterSenderId: "synthetic-sender@example.invalid",
        senderIsOwner: true,
      });
      const result = toolDetails(
        await tool.execute("call-resolve-audited", { refs: ["phoenix://openclaw-int/db-pass"] }),
      );
      assert.equal(result.ok, true);

      const audit = await server.adminGet("/v1/audit");
      assert.equal(audit.statusCode, 200);
      const entries = (audit.body as { entries?: AuditEntry[] }).entries ?? [];
      const entry = entries
        .filter((candidate) => candidate.path === "openclaw-int/db-pass" && candidate.action === "resolve")
        .at(-1);
      assert.ok(entry, "resolve left an audit entry");
      assert.equal(entry.agent, "int-main");
      assert.equal(entry.status, "allowed");
      assert.equal(entry.metadata?.["openclaw.agent"], "integration-agent");
      assert.equal(entry.metadata?.["openclaw.session_id"], "session-int-1");
      assert.equal(entry.metadata?.["openclaw.channel"], "integration-channel");
      assert.equal(entry.metadata?.["openclaw.requester_sender"], "synthetic-sender@example.invalid");
      assert.equal(entry.metadata?.["openclaw.sender_is_owner"], "true");
      assert.ok(
        !("openclaw.session_key" in (entry.metadata ?? {})),
        "the server must not capture the session key as metadata",
      );
      assert.ok(!audit.raw.includes("synthetic-session-key-sentinel"), "session key must not appear in audit output");
      assert.ok(!audit.raw.includes("synthetic-value-2"), "secret value must not appear in audit output");
    });

    await t.test("require_sealed policy forces sealed envelopes through the plugin", async () => {
      // The attestation policy must be enabled after seeding: require_sealed
      // also gates writes, so a policy-first server rejects `phoenix set`.
      const policyPath = path.join(server.runDir, "policy.json");
      await fsp.writeFile(
        policyPath,
        `${JSON.stringify({
          attestation: { "openclaw-sealedonly/*": { require_sealed: true, allow_unseal: false } },
        })}\n`,
        "utf8",
      );
      await server.stop();
      await server.patchConfig((config) => {
        config.policy = { path: policyPath };
      });
      await server.start();

      // Plaintext-mode resolve of a require_sealed path is refused per-ref.
      const plaintextTool = createPhoenixResolveTool(mainConfig, { agentId: "main" });
      const refused = toolDetails(
        await plaintextTool.execute("call-sealedonly-plaintext", {
          refs: ["phoenix://openclaw-sealedonly/key"],
        }),
      );
      assert.equal(refused.ok, false);
      assert.match(
        (refused.errors as Record<string, string>)["phoenix://openclaw-sealedonly/key"],
        /attestation required/,
      );

      // Sealed-mode resolve with the registered seal key succeeds.
      const sealedTool = createPhoenixResolveTool(sealedConfig, { agentId: "main" });
      const rawSealed = await sealedTool.execute("call-sealedonly-sealed", {
        refs: ["phoenix://openclaw-sealedonly/key"],
      });
      assert.ok(!JSON.stringify(rawSealed).includes("synthetic-sealed-value"));
      const sealed = toolDetails(rawSealed);
      assert.equal(sealed.ok, true);
      assert.equal(sealed.mode, "sealed");
      const envelope = decodeSealedToken(
        (sealed.values as Record<string, string>)["phoenix://openclaw-sealedonly/key"],
      );
      assert.equal(envelope.ref, "phoenix://openclaw-sealedonly/key");
    });

    await t.test("mTLS client-certificate auth resolves over https", async () => {
      const mtlsServer = new PhoenixServer(binaries);
      t.after(async () => {
        await mtlsServer.dispose();
      });
      await mtlsServer.init();
      await mtlsServer.patchConfig((config) => {
        const auth = config.auth as { mtls: Record<string, unknown> };
        auth.mtls.enabled = true;
      });
      await mtlsServer.start({ https: true });

      mtlsServer.cliOk(["set", "mtls-ns/key", "-v", "synthetic-mtls-value"]);
      mtlsServer.cliOk(["agent", "create", "mtls-agent", "-t", "synthetic-mtls-bootstrap", "--acl", "mtls-ns/*:read"]);
      const clientDir = path.join(mtlsServer.runDir, "client");
      await fsp.mkdir(clientDir);
      mtlsServer.cliOk(["cert", "issue", "mtls-agent", "-o", clientDir]);

      const mtlsConfig: PhoenixPluginConfig = {
        server: mtlsServer.url,
        caCert: mtlsServer.caCertPath,
        clientCert: path.join(clientDir, "mtls-agent.crt"),
        clientKey: path.join(clientDir, "mtls-agent.key"),
        defaultNamespace: "mtls-ns",
        sealMode: false,
      };

      const statusTool = createPhoenixStatusTool(mtlsConfig, { agentId: "main" });
      const status = toolDetails(await statusTool.execute("call-mtls-status", {}));
      assert.equal(status.ok, true);
      assert.equal(status.authMode, "mtls");
      assert.ok(status.tls, "phoenix_status reports the TLS peer certificate over https");

      const tool = createPhoenixResolveTool(mtlsConfig, { agentId: "main" });
      const result = toolDetails(await tool.execute("call-mtls-resolve", { refs: ["key"] }));
      assert.equal(result.ok, true);
      assert.deepEqual(result.values, { "phoenix://mtls-ns/key": "synthetic-mtls-value" });
    });
  });
}
