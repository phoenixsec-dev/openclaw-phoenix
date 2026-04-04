# openclaw-phoenix

OpenClaw plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix) -- encrypted secrets, per-agent access control, attestation, and audit for OpenClaw deployments.

## Status

Early development. Not yet published to npm.

## What this does

Phoenix is a secrets manager purpose-built for AI agents. This plugin integrates it natively into OpenClaw so agents can resolve secrets at runtime with per-request access control, sealed responses (values never enter model context), and a full audit trail.

Two integration paths:

- **Plugin tools** (runtime) -- agents call `phoenix_resolve` during execution. Per-request ACLs, sealed mode, step-up approval for privileged secrets.
- **Exec provider** (startup) -- OpenClaw's built-in exec provider calls Phoenix at gateway boot for bulk secret resolution. Simpler but no per-agent scoping.

## Requirements

- Phoenix server (v0.13.3+) running and accessible from the OpenClaw gateway
- OpenClaw with plugin support enabled
- Phoenix credentials (bearer token or mTLS certs) for the gateway

## Installation

```bash
# Local development
openclaw plugins install ./path/to/openclaw-phoenix -l

# From npm (not yet available)
# openclaw plugins install openclaw-phoenix
```

## Configuration

```json5
{
  plugins: {
    entries: {
      "phoenix-secrets": {
        enabled: true,
        config: {
          server: "http://phoenix:9090",
          token: "your-phoenix-token",
          // Or mTLS:
          // caCert: "/etc/phoenix/ca.crt",
          // clientCert: "/etc/phoenix/openclaw.crt",
          // clientKey: "/etc/phoenix/openclaw.key",
          sealMode: false
        }
      }
    }
  }
}
```

## Plugin tools

| Tool | Description |
|------|-------------|
| `phoenix_resolve` | Resolve one or more `phoenix://` references to values (or sealed tokens) |
| `phoenix_list` | List available secret paths |
| `phoenix_status` | Check Phoenix connectivity, cert validity, session info |

## Related

- [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix)
- [OpenClaw Plugin Documentation](https://docs.openclaw.ai/tools/plugin)

## License

MIT
