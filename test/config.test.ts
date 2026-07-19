import test from "node:test";
import assert from "node:assert/strict";
import { resolvePhoenixPluginConfig } from "../src/config.ts";

test("resolvePhoenixPluginConfig reads env fallbacks and resolves paths", () => {
  const config = resolvePhoenixPluginConfig(
    {
      server: "https://phoenix.internal:9090/",
      clientCert: "./client.crt",
      clientKey: "./client.key",
      sealKeyFile: "./agent.seal.key",
      defaultNamespace: "openclaw",
      sealMode: true,
    },
    {
      resolvePath: (input) => `/resolved/${input}`,
    },
  );

  assert.equal(config.server, "https://phoenix.internal:9090");
  assert.equal(config.clientCert, "/resolved/./client.crt");
  assert.equal(config.clientKey, "/resolved/./client.key");
  assert.equal(config.sealKeyFile, "/resolved/./agent.seal.key");
  assert.equal(config.defaultNamespace, "openclaw");
  assert.equal(config.sealMode, true);
});

test("resolvePhoenixPluginConfig accepts token auth from env", () => {
  const config = resolvePhoenixPluginConfig(
    {},
    {
      env: {
        PHOENIX_SERVER: "http://phoenix:9090",
        PHOENIX_TOKEN: "test-token",
      },
    },
  );

  assert.equal(config.server, "http://phoenix:9090");
  assert.equal(config.token, "test-token");
  assert.equal(config.sealMode, false);
});

test("resolvePhoenixPluginConfig reads PHOENIX_SEAL_KEY when sealed mode is enabled", () => {
  const config = resolvePhoenixPluginConfig(
    {},
    {
      env: {
        PHOENIX_SERVER: "http://phoenix:9090",
        PHOENIX_TOKEN: "test-token",
        PHOENIX_SEAL_MODE: "true",
        PHOENIX_SEAL_KEY: "./agent.seal.key",
      },
      resolvePath: (input) => `/resolved/${input}`,
    },
  );

  assert.equal(config.server, "http://phoenix:9090");
  assert.equal(config.token, "test-token");
  assert.equal(config.sealMode, true);
  assert.equal(config.sealKeyFile, "/resolved/./agent.seal.key");
});

test("resolvePhoenixPluginConfig accepts tokenFile auth", () => {
  const config = resolvePhoenixPluginConfig(
    {
      server: "http://phoenix:9090",
      tokenFile: "./phoenix-token",
    },
    {
      resolvePath: (input) => `/resolved/${input}`,
    },
  );

  assert.equal(config.server, "http://phoenix:9090");
  assert.equal(config.tokenFile, "/resolved/./phoenix-token");
  assert.equal(config.sealMode, false);
});

test("resolvePhoenixPluginConfig accepts per-agent identity mappings without top-level auth", () => {
  const config = resolvePhoenixPluginConfig(
    {
      server: "https://phoenix.internal:9090/",
      caCert: "./ca.crt",
      sealMode: true,
      agents: {
        main: {
          tokenFile: "./main.token",
          sealKeyFile: "./main.seal.key",
          defaultNamespace: "openclaw-main",
        },
        kit: {
          server: "https://phoenix-kit.internal:9090/",
          tokenFile: "./kit.token",
          sealKeyFile: "./kit.seal.key",
          defaultNamespace: "openclaw-kit",
          caCert: "./kit-ca.crt",
        },
      },
    },
    {
      env: {},
      resolvePath: (input) => `/resolved/${input}`,
    },
  );

  assert.equal(config.server, "https://phoenix.internal:9090");
  assert.equal(config.caCert, "/resolved/./ca.crt");
  assert.equal(config.sealMode, true);
  assert.equal(config.agents?.main?.tokenFile, "/resolved/./main.token");
  assert.equal(config.agents?.main?.sealKeyFile, "/resolved/./main.seal.key");
  assert.equal(config.agents?.main?.defaultNamespace, "openclaw-main");
  assert.equal(config.agents?.kit?.server, "https://phoenix-kit.internal:9090");
  assert.equal(config.agents?.kit?.caCert, "/resolved/./kit-ca.crt");
});

test("resolvePhoenixPluginConfig rejects invalid agent ids and accepts free-form valid ids", () => {
  for (const badAgentId of ["Bad-Caps", "1starts-with-digit", "has space", "has/slash", "-leading-dash", ""]) {
    assert.throws(
      () =>
        resolvePhoenixPluginConfig(
          {
            server: "http://phoenix:9090",
            sealMode: false,
            agents: {
              [badAgentId]: {
                tokenFile: "./agent.token",
                defaultNamespace: "openclaw-agent",
              },
            },
          },
          { env: {} },
        ),
      /is not a valid OpenClaw agent id/,
      `expected agent id ${JSON.stringify(badAgentId)} to be rejected`,
    );
  }

  const config = resolvePhoenixPluginConfig(
    {
      server: "http://phoenix:9090",
      sealMode: false,
      agents: {
        "custom-agent_7": {
          tokenFile: "./custom.token",
          defaultNamespace: "openclaw-custom",
        },
      },
    },
    { env: {} },
  );
  assert.equal(config.agents?.["custom-agent_7"]?.defaultNamespace, "openclaw-custom");
});

test("resolvePhoenixPluginConfig rejects duplicate per-agent token files and seal keys", () => {
  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
          sealMode: true,
          agents: {
            main: {
              tokenFile: "./shared.token",
              sealKeyFile: "./main.seal.key",
              defaultNamespace: "openclaw-main",
            },
            kit: {
              tokenFile: "./shared.token",
              sealKeyFile: "./kit.seal.key",
              defaultNamespace: "openclaw-kit",
            },
          },
        },
        { env: {}, resolvePath: (input) => `/resolved/${input}` },
      ),
    /tokenFile must be unique/,
  );

  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
          sealMode: true,
          agents: {
            main: {
              tokenFile: "./main.token",
              sealKeyFile: "./shared.seal.key",
              defaultNamespace: "openclaw-main",
            },
            kit: {
              tokenFile: "./kit.token",
              sealKeyFile: "./shared.seal.key",
              defaultNamespace: "openclaw-kit",
            },
          },
        },
        { env: {}, resolvePath: (input) => `/resolved/${input}` },
      ),
    /sealKeyFile must be unique/,
  );
});

test("resolvePhoenixPluginConfig requires per-agent seal keys when inherited sealed mode is enabled", () => {
  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
          sealMode: true,
          agents: {
            main: {
              tokenFile: "./main.token",
              defaultNamespace: "openclaw-main",
            },
          },
        },
        { env: {} },
      ),
    /agents\.main\.sealKeyFile is required/,
  );
});

test("resolvePhoenixPluginConfig requires a persistent seal key file in sealed mode", () => {
  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
          token: "test-token",
          sealMode: true,
        },
        { env: {} },
      ),
    /sealMode requires sealKeyFile \(or PHOENIX_SEAL_KEY\)/,
  );
});

test("resolvePhoenixPluginConfig rejects missing auth", () => {
  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
        },
        { env: {} },
      ),
    /requires token auth, tokenFile auth, per-agent agents config, or both clientCert and clientKey/,
  );
});
