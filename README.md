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

```json5
{
  plugins: {
    allow: ["phoenix-secrets"],
    entries: {
      "phoenix-secrets": {
        enabled: true,
        config: {
          server: "https://phoenix:9090",
          // Prefer tokenFile or PHOENIX_TOKEN_FILE over embedding token values.
          tokenFile: "/home/openclaw/.config/phoenix/token",
          // Optional mTLS:
          // caCert: "/etc/phoenix/ca.crt",
          // clientCert: "/etc/phoenix/openclaw.crt",
          // clientKey: "/etc/phoenix/openclaw.key",
          defaultNamespace: "openclaw",
          sealMode: true
        }
      }
    }
  }
}
```

Environment fallbacks:

- `PHOENIX_SERVER`
- `PHOENIX_TOKEN`
- `PHOENIX_TOKEN_FILE`
- `PHOENIX_CA_CERT`
- `PHOENIX_CLIENT_CERT`
- `PHOENIX_CLIENT_KEY`
- `PHOENIX_DEFAULT_NAMESPACE`
- `PHOENIX_SEAL_MODE`

## Development

Run tests locally:

```bash
npm test
```

## Notes

- `sealMode: true` returns opaque `PHOENIX_SEALED:` tokens instead of plaintext values.
- Phoenix's current REST API does not expose a server version field, so `phoenix_status` reports that as unavailable instead of guessing.
- No secrets or credentials are written to disk by this plugin.
- `tokenFile` reads an existing scoped bearer token at runtime so operators do not need to paste token values into `openclaw.json` or `/etc/default/openclaw`.
