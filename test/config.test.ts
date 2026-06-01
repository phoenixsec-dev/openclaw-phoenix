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
    /requires token auth, tokenFile auth, or both clientCert and clientKey/,
  );
});
