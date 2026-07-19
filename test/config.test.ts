import test from "node:test";
import assert from "node:assert/strict";
import { phoenixPluginConfigSchema, resolvePhoenixPluginConfig } from "../src/config.ts";

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
      env: {},
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
      env: {},
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
  for (const badAgentId of ["Bad-Caps", "has space", "has/slash", "-leading-dash", "_leading-underscore", ""]) {
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

  // Digit-leading ids are valid: OpenClaw's VALID_ID_RE accepts them.
  const config = resolvePhoenixPluginConfig(
    {
      server: "http://phoenix:9090",
      sealMode: false,
      agents: {
        "custom-agent_7": {
          tokenFile: "./custom.token",
          defaultNamespace: "openclaw-custom",
        },
        "67agent": {
          tokenFile: "./67agent.token",
          defaultNamespace: "openclaw-67",
        },
      },
    },
    { env: {} },
  );
  assert.equal(config.agents?.["custom-agent_7"]?.defaultNamespace, "openclaw-custom");
  assert.equal(config.agents?.["67agent"]?.defaultNamespace, "openclaw-67");
});

test("JSON schema constrains defaultNamespace the same way the runtime does", () => {
  const schema = phoenixPluginConfigSchema.jsonSchema as {
    properties: {
      defaultNamespace: { pattern?: string };
      agents: { patternProperties: Record<string, { properties: { defaultNamespace: { pattern?: string } } }> };
    };
  };
  const topLevelPattern = schema.properties.defaultNamespace.pattern;
  const agentIdentitySchema = Object.values(schema.properties.agents.patternProperties)[0];
  const perAgentPattern = agentIdentitySchema.properties.defaultNamespace.pattern;

  assert.ok(topLevelPattern, "top-level defaultNamespace schema must declare a pattern");
  assert.equal(perAgentPattern, topLevelPattern, "per-agent pattern must match top-level");

  const patternRe = new RegExp(topLevelPattern);
  for (const rejected of [".", "..", "../status", "ns/sub", "x/../status", "a b", ""]) {
    assert.equal(patternRe.test(rejected), false, `schema pattern must reject ${JSON.stringify(rejected)}`);
  }
  for (const accepted of ["openclaw", "ns.prod", "team-a_1", ".hidden"]) {
    assert.equal(patternRe.test(accepted), true, `schema pattern must accept ${JSON.stringify(accepted)}`);
  }
});

test("resolvePhoenixPluginConfig rejects traversal-capable default namespaces", () => {
  for (const badNamespace of ["../status", "x/../status", "ns/sub", "..", ".", "a b"]) {
    for (const target of ["top-level", "per-agent"] as const) {
      assert.throws(
        () =>
          resolvePhoenixPluginConfig(
            target === "top-level"
              ? {
                  server: "http://phoenix:9090",
                  token: "t",
                  sealMode: false,
                  defaultNamespace: badNamespace,
                }
              : {
                  server: "http://phoenix:9090",
                  sealMode: false,
                  agents: {
                    main: { tokenFile: "./main.token", defaultNamespace: badNamespace },
                  },
                },
            { env: {} },
          ),
        /single namespace segment/,
        `expected ${target} namespace ${JSON.stringify(badNamespace)} to be rejected`,
      );
    }
  }
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

test("resolvePhoenixPluginConfig rejects malformed configs", () => {
  const cases: Array<{ name: string; config: Record<string, unknown>; expected: RegExp }> = [
    {
      name: "invalid server URL",
      config: { server: "not-a-url", token: "t" },
      expected: /must be a valid URL/,
    },
    {
      name: "non-http server protocol",
      config: { server: "ftp://x", token: "t" },
      expected: /must use http:\/\/ or https:\/\//,
    },
    {
      name: "per-agent invalid server",
      config: {
        server: "http://phoenix:9090",
        sealMode: false,
        agents: {
          main: { server: "not-a-url", tokenFile: "./main.token", defaultNamespace: "main-ns" },
        },
      },
      expected: /agents\.main\.server must be a valid URL/,
    },
    {
      name: "top-level defaultNamespace containing a colon",
      config: { server: "http://phoenix:9090", token: "t", defaultNamespace: "phoenix://ns" },
      expected: /must be a namespace name, not a URI/,
    },
    {
      name: "per-agent defaultNamespace containing a colon",
      config: {
        server: "http://phoenix:9090",
        sealMode: false,
        agents: {
          main: { tokenFile: "./main.token", defaultNamespace: "phoenix://ns" },
        },
      },
      expected: /agents\.main\.defaultNamespace must be a namespace name, not a URI/,
    },
    {
      name: "top-level mTLS half-pair",
      config: { server: "http://phoenix:9090", token: "t", clientCert: "./client.crt" },
      expected: /mTLS requires both clientCert and clientKey/,
    },
    {
      name: "per-agent mTLS half-pair",
      config: {
        server: "http://phoenix:9090",
        sealMode: false,
        agents: {
          main: {
            tokenFile: "./main.token",
            defaultNamespace: "main-ns",
            clientCert: "./main.crt",
          },
        },
      },
      expected: /agents\.main mTLS override requires both clientCert and clientKey/,
    },
    {
      name: "missing per-agent defaultNamespace",
      config: {
        server: "http://phoenix:9090",
        sealMode: false,
        agents: {
          main: { tokenFile: "./main.token" },
        },
      },
      expected: /agents\.main\.defaultNamespace is required/,
    },
    {
      name: "empty agents object",
      config: { server: "http://phoenix:9090", agents: {} },
      expected: /agents must configure at least one OpenClaw agent identity/,
    },
    {
      name: "non-object agents",
      config: { server: "http://phoenix:9090", agents: "nope" },
      expected: /agents must be an object/,
    },
  ];

  for (const testCase of cases) {
    assert.throws(
      () => resolvePhoenixPluginConfig(testCase.config, { env: {} }),
      testCase.expected,
      `expected config case "${testCase.name}" to be rejected`,
    );
  }
});

test("phoenixPluginConfigSchema.validate reports errors without throwing", () => {
  const bad = phoenixPluginConfigSchema.validate({ server: "not-a-url", token: "t" });
  assert.equal(bad.ok, false);
  assert.ok(!bad.ok && bad.errors.length === 1);
  assert.match(!bad.ok ? bad.errors[0] : "", /must be a valid URL/);

  const good = phoenixPluginConfigSchema.validate({
    server: "http://127.0.0.1:9090",
    token: "t",
    sealMode: false,
  });
  assert.equal(good.ok, true);
});
