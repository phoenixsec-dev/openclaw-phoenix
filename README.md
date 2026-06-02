# openclaw-phoenix

OpenClaw plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix) -- encrypted secrets, per-agent access control, attestation, and audit for OpenClaw deployments.

## Status

Phase 1 development plugin. Local-link install only for now.

## What this does

This plugin adds three native OpenClaw tools plus a CLI helper:

- `phoenix_resolve` — resolve one or more `phoenix://` refs through Phoenix
- `phoenix_list` — list visible secret paths
- `phoenix_status` — check connectivity, admin-visible status, and TLS cert health
- `openclaw phoenix verify` — dry-run all `phoenix://` refs currently present in the active gateway config

It also registers a gateway-startup connectivity check so Phoenix misconfiguration is surfaced immediately during startup.

The tools are registered as optional OpenClaw plugin tools. Expose them deliberately with `tools.alsoAllow` (for example, start with `phoenix_status` only) or a plugin/group allowlist. Keep `phoenix_resolve` and `phoenix_list` denied until per-agent Phoenix identities and sealed-response policy are ready.

Important: this Phase 1 plugin is a **tool-based integration**. It does **not** hook Phoenix into OpenClaw's built-in SecretRef object resolution, so raw `phoenix://...` strings in gateway config env fields are not supported by this plugin alone. For built-in OpenClaw SecretRefs and bootstrap/config secrets, use Phoenix CLI v0.14.0+ as an exec provider (`phoenix resolve --stdin-json`, alias `phoenix openclaw-exec-provider`).

## Installation

```bash
openclaw plugins install ./path/to/openclaw-phoenix -l
```

See also:
- `docs/openclaw-guide.md`
- `docs/integrations.md`
- `examples/openclaw-plugin/`
- `examples/openclaw-docker/`

## Configuration

Recommended live configuration maps trusted OpenClaw runtime agent ids to separate Phoenix identities. The plugin selects the identity from `ctx.agentId` supplied by OpenClaw's plugin runtime; tool arguments and raw HTTP headers cannot choose an identity.

```json5
{
  plugins: {
    allow: ["phoenix-secrets"],
    entries: {
      "phoenix-secrets": {
        enabled: true,
        config: {
          server: "https://phoenix:9090",
          sealMode: true,
          // Optional shared TLS material; individual agents may override these.
          // caCert: "/etc/phoenix/ca.crt",
          // clientCert: "/etc/phoenix/openclaw.crt",
          // clientKey: "/etc/phoenix/openclaw.key",
          agents: {
            main: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/main",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/main.seal.key",
              defaultNamespace: "openclaw-main"
            },
            kit: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/kit",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/kit.seal.key",
              defaultNamespace: "openclaw-kit"
            },
            phoenix: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/phoenix",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/phoenix.seal.key",
              defaultNamespace: "openclaw-phoenix"
            },
            echo: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/echo",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/echo.seal.key",
              defaultNamespace: "openclaw-echo"
            },
            relay: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/relay",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/relay.seal.key",
              defaultNamespace: "openclaw-relay"
            }
          }
        }
      }
    }
  }
}
```

Per-agent entries support optional `server`, `caCert`, `clientCert`, `clientKey`, and `sealMode` overrides. Token files and seal key files must be unique per mapped agent; startup also rejects duplicate token/seal-key material. Unknown or unmapped `ctx.agentId` values fail closed with remediation instead of falling back to a shared token.

Single-identity fields (`token`, `tokenFile`, `sealKeyFile`, `defaultNamespace`, and their environment fallbacks) remain available for diagnostics/dev only. They are **not** a per-agent trust boundary and should not be used to expose live `phoenix_resolve`/`phoenix_list` to multiple agents.

Environment fallbacks for diagnostic single-identity mode:

- `PHOENIX_SERVER`
- `PHOENIX_TOKEN`
- `PHOENIX_TOKEN_FILE`
- `PHOENIX_CA_CERT`
- `PHOENIX_CLIENT_CERT`
- `PHOENIX_CLIENT_KEY`
- `PHOENIX_DEFAULT_NAMESPACE`
- `PHOENIX_SEAL_MODE`
- `PHOENIX_SEAL_KEY` — path to the diagnostic identity's persistent X25519 seal private key file

### Sealed mode

`sealMode: true` requires a persistent private seal key file. In per-agent mode, configure `agents.<id>.sealKeyFile` for each mapped agent; in diagnostic single-identity mode, use `sealKeyFile` or `PHOENIX_SEAL_KEY`. The plugin reads the selected agent's key file at startup/status/verify/resolve time, rejects over-broad permissions (group/other bits must be clear; `chmod 600` is recommended), derives the matching public key, and sends it as `X-Phoenix-Seal-Key` on `phoenix_resolve` requests. Tool output stays opaque as `PHOENIX_SEALED:*`; the plugin does not return plaintext values in sealed mode.

Before live use, register each agent's derived public seal key with Phoenix for that agent identity. A configured key file alone is not enough if Phoenix has no registered public key. `openclaw phoenix verify` is a diagnostic shared-identity helper; live per-agent access still depends on Phoenix-side public-key registration and policy for each runtime identity. For CT120, keep the conservative rollout policy: do not deploy or enable broad `phoenix_resolve`/`phoenix_list` access until scoped per-agent credentials, registered public seal keys, and tool allowlists have been validated.

## Development

Run tests locally:

```bash
npm test
```

## Notes

- `sealMode: true` returns opaque `PHOENIX_SEALED:` tokens instead of plaintext values and requires `agents.<id>.sealKeyFile` in per-agent mode or `sealKeyFile`/`PHOENIX_SEAL_KEY` in diagnostic single-identity mode.
- Phoenix's current REST API does not expose a server version field, so `phoenix_status` reports that as unavailable instead of guessing.
- No secrets or credentials are written to disk by this plugin.
- `agents.<id>.tokenFile` reads an existing scoped bearer token for the trusted runtime `ctx.agentId`; operators do not need to paste token values into `openclaw.json` or `/etc/default/openclaw`. Keep token file permissions tight (`0600`); group/other bits are rejected.
- `agents.<id>.sealKeyFile` reads an existing per-agent private seal key file; keep permissions tight (`0600`) and never commit it.
- `X-OpenClaw-*` request headers are metadata/audit hints only. Phoenix identity is enforced by the selected token/seal key, not by trusting raw headers.
