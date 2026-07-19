# openclaw-phoenix

OpenClaw plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix) -- encrypted secrets, per-agent access control, attestation, and audit for OpenClaw deployments.

## Status

Package-oriented release hardening is in progress. This plugin is intended to ship with Phoenix as an installable OpenClaw plugin package, not as local-link-only. Parent release review still gates publishing/deployment from this tree.

## What this does

This plugin adds three native OpenClaw tools plus a CLI helper:

- `phoenix_resolve` — resolve one or more `phoenix://` refs through Phoenix
- `phoenix_list` — list visible secret paths
- `phoenix_status` — check connectivity, admin-visible status, and TLS cert health
- `openclaw phoenix verify` — dry-run all `phoenix://` refs currently present in the active gateway config

It also registers a warning-only gateway-startup preflight so Phoenix misconfiguration is surfaced immediately without killing the OpenClaw gateway.

The tools are registered as optional OpenClaw plugin tools. Expose them deliberately with `tools.alsoAllow` (for example, start with `phoenix_status` only) or a plugin/group allowlist. Keep `phoenix_resolve` and `phoenix_list` denied until per-agent Phoenix identities and sealed-response policy are ready.

Startup preflight is diagnostic only: Phoenix down/auth/TLS/seal-key issues and duplicate per-agent token/seal-key material are logged as warnings. Runtime tool execution independently fingerprints all mapped per-agent token/seal-key material and fails closed if two agents share credential contents, so a warning cannot silently collapse the live per-agent trust boundary. Active OpenClaw SecretRefs resolved through the Phoenix CLI exec-provider path still fail startup/reload through OpenClaw's built-in secrets system.

Important: this package is a **runtime tool-based integration**. It does **not** hook Phoenix into OpenClaw's built-in SecretRef object resolution, so raw `phoenix://...` strings in gateway config env fields are not supported by this plugin alone. For built-in OpenClaw SecretRefs and bootstrap/config secrets, use Phoenix CLI v0.14.0+ as an exec provider (`phoenix resolve --stdin-json`, alias `phoenix openclaw-exec-provider`).

## Installation

Package install after the release source is approved (OpenClaw checks ClawHub first, then npm for bare package specs):

```bash
openclaw plugins install openclaw-phoenix
# Optional: pin the exact package version once chosen for release.
openclaw plugins install openclaw-phoenix@<version> --pin
```

Local source development is still supported. Use a link install when you want OpenClaw to load this checkout directly:

```bash
openclaw plugins install -l ./path/to/openclaw-phoenix
```

See also:
- `docs/openclaw-guide.md`
- `docs/integrations.md`
- `docs/release-coordination.md`
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

Per-agent entries support optional `server`, `caCert`, `clientCert`, `clientKey`, and `sealMode` overrides. Token files and seal key files must be unique per mapped agent, and the selected host files must have no group/other permission bits (`chmod 600` is recommended). Startup preflight warns about duplicate token/seal-key contents; every runtime tool call revalidates that material and fails closed until duplicates are corrected. Unknown or unmapped `ctx.agentId` values fail closed with remediation instead of falling back to a shared token.

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

Before live use, register each agent's derived public seal key with Phoenix for that agent identity. A configured key file alone is not enough if Phoenix has no registered public key. `openclaw phoenix verify` is a diagnostic shared-identity helper; when per-agent mappings use top-level `sealMode: true`, its top-level diagnostic identity must also configure its own `sealKeyFile` (or `PHOENIX_SEAL_KEY`). Per-agent `agents.<id>.sealKeyFile` values are not reused by the CLI. Live per-agent access still depends on Phoenix-side public-key registration and policy for each runtime identity. For production gateways, keep the conservative rollout policy: do not deploy or enable broad `phoenix_resolve`/`phoenix_list` access until scoped per-agent credentials, registered public seal keys, and tool allowlists have been validated.

## Development

Run tests locally:

```bash
npm test
```

Run the OpenClaw plugin load/registration smoke explicitly:

```bash
npm run smoke:openclaw
```

The smoke uses `OPENCLAW_REPO` when set, otherwise `/mnt/projects/openclaw`. If the local OpenClaw checkout is absent it reports a TAP skip with that instruction. It imports the plugin through the documented `openclaw/plugin-sdk/plugin-entry` seam with a smoke SDK shim, verifies the local OpenClaw checkout exposes that SDK subpath, captures tool/service/CLI registration, and does not read real Phoenix secrets or deploy anything.

## Package release checklist

Before parent release approval/publish:

- Bump the development version in `package.json` from `0.1.1` to the parent-approved release version before publishing, then confirm the matching version/tag. Suggested first package release line: `0.2.0` or the next Phoenix-aligned version chosen by the parent release plan; do not publish the current `0.1.1` package metadata.
- Confirm/set an approved public repository or ClawHub source (`--source-repo`, `--source-commit`, `--source-ref`) before publishing. This package intentionally omits `repository` metadata until parent release approval so public package metadata does not point at a private/internal source.
- Confirm package metadata (`name`, `license`, `files`, `exports`, `openclaw.install`, `openclaw.compat`, `openclaw.build`) and inspect package contents with `npm pack --dry-run`.
- Run `npm test`, `npm run smoke:openclaw`, and `git diff --check` from this repo.
- Validate OpenClaw built-in SecretRefs through the Phoenix CLI exec provider separately from this plugin.
- Use `docs/release-coordination.md` to verify the Phoenix server audit-only `X-OpenClaw-*` header contract and per-agent seal-key registration inventory.
- Keep rollout conservative: allow `phoenix_status` first, then enable `phoenix_resolve`/`phoenix_list` only after per-agent token files, seal key files (`0600`), Phoenix-side public seal-key registration, and tool allowlists have been validated.
- Re-check examples/docs for plaintext secrets before publishing.

Draft release-note bullets for parent review:

- Packageable OpenClaw Phoenix plugin with runtime `phoenix_status`, `phoenix_resolve`, and `phoenix_list` tools.
- Warning-only startup preflight and `openclaw phoenix verify` diagnostics for Phoenix connectivity/configuration.
- Per-agent token/seal-key mapping with sealed-response UX and conservative allowlist guidance.
- Documentation aligned with Phoenix CLI exec-provider SecretRefs for bootstrap/config secrets.

## Notes

- `sealMode: true` returns opaque `PHOENIX_SEALED:` tokens instead of plaintext values and requires `agents.<id>.sealKeyFile` in per-agent mode or `sealKeyFile`/`PHOENIX_SEAL_KEY` in diagnostic single-identity mode.
- Phoenix's current REST API does not expose a server version field, so `phoenix_status` reports that as unavailable instead of guessing.
- No secrets or credentials are written to disk by this plugin.
- `agents.<id>.tokenFile` reads an existing scoped bearer token for the trusted runtime `ctx.agentId`; operators do not need to paste token values into `openclaw.json` or `/etc/default/openclaw`. Keep token file permissions tight (`0600`); group/other bits are rejected.
- `agents.<id>.sealKeyFile` reads an existing per-agent private seal key file; keep permissions tight (`0600`) and never commit it.
- `X-OpenClaw-*` request headers are metadata/audit hints only. Phoenix identity is enforced by the selected token/seal key, not by trusting raw headers.
