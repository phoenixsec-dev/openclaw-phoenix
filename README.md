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

## Installation

```bash
openclaw plugins install ./path/to/openclaw-phoenix -l
```

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
          // Prefer PHOENIX_TOKEN in the gateway environment for secrets.
          token: "phoenix_token_here",
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
