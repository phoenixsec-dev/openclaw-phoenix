import test from "node:test";
import assert from "node:assert/strict";
import { resolvePhoenixPluginConfig } from "../src/config.ts";

test("resolvePhoenixPluginConfig reads env fallbacks and resolves paths", () => {
  const config = resolvePhoenixPluginConfig(
    {
      server: "https://phoenix.internal:9090/",
      clientCert: "./client.crt",
      clientKey: "./client.key",
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

test("resolvePhoenixPluginConfig rejects missing auth", () => {
  assert.throws(
    () =>
      resolvePhoenixPluginConfig(
        {
          server: "http://phoenix:9090",
        },
        { env: {} },
      ),
    /requires either token auth or both clientCert and clientKey/,
  );
});
