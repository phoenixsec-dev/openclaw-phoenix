# openclaw-phoenix

OpenClaw plugin for [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix) -- encrypted secrets, per-agent access control, attestation, and audit for OpenClaw deployments.

## Status

Package-oriented release hardening is in progress. This plugin is intended to ship with Phoenix as an installable OpenClaw plugin package, not as local-link-only. Parent release review still gates publishing/deployment from this tree.

## What this does

This plugin adds three native OpenClaw tools plus a CLI helper:

- `phoenix_resolve` — resolve one or more `phoenix://` refs through Phoenix
- `phoenix_list` — list visible secret paths
- `phoenix_status` — check connectivity, admin-visible status, and TLS cert health
- `openclaw phoenix verify` — dry-run all literal `phoenix://` refs currently present in the active gateway config. Limitation: the scan only detects strings starting with the literal `phoenix://` prefix; path-only SecretRef ids (for example bare `namespace/path` ids resolved through the Phoenix CLI exec provider's secrets configuration) are not scanned and are not covered by `verify`.

It also registers a warning-only gateway-startup preflight so Phoenix misconfiguration is surfaced immediately without killing the OpenClaw gateway. The preflight makes an authenticated, read-only probe (`GET /v1/policy/check`) for every configured Phoenix identity, so it verifies both that the server is reachable and that the configured token or mTLS client certificate is accepted — with distinct warnings for "Phoenix is unreachable" versus "Phoenix is reachable but rejected the configured credentials". Warning messages never include token or key material.

The tools are registered as optional OpenClaw plugin tools. Expose them deliberately with `tools.alsoAllow` (for example, start with `phoenix_status` only) or a plugin/group allowlist. Keep `phoenix_resolve` and `phoenix_list` denied until per-agent Phoenix identities and sealed-response policy are ready.

Startup preflight is diagnostic only and never fatal: Phoenix down/auth/TLS/seal-key issues and duplicate per-agent token/seal-key material are logged as warnings through the gateway's plugin logger (they appear in the gateway log, not necessarily on stdout), and the gateway always continues to start. What the preflight checks: per-agent identity material (readable files, tight permissions, uniqueness), local seal-key configuration loads, and an authenticated read-only probe per identity that validates connectivity and credential acceptance. What it does **not** guarantee: it does not check ACL grants on any secret path, server-side seal-key registration, or that any specific ref resolves — a clean preflight does not mean later `phoenix_resolve` calls will succeed. Runtime tool execution independently fingerprints all mapped per-agent token/seal-key material and fails closed if two agents share credential contents, so a warning cannot silently collapse the live per-agent trust boundary. Active OpenClaw SecretRefs resolved through the Phoenix CLI exec-provider path still fail startup/reload through OpenClaw's built-in secrets system.

Important: this package is a **runtime tool-based integration**. It does **not** hook Phoenix into OpenClaw's built-in SecretRef object resolution, so raw `phoenix://...` strings in gateway config env fields are not supported by this plugin alone. For built-in OpenClaw SecretRefs and bootstrap/config secrets, use Phoenix CLI v0.14.0+ as an exec provider (`phoenix resolve --stdin-json`, alias `phoenix openclaw-exec-provider`).

## Transport security

Phoenix is **LAN-scoped by design**: use across the internet/WAN (public ingress, hostile-network operation) is out of scope and unsupported. Within that envelope:

- **Loopback plaintext is the supported default.** `http://127.0.0.1:9090` never reaches a network interface, and single-machine deployments are the common case.
- **LAN is in scope but is not a trust boundary.** A LAN includes containers on shared bridges, IoT devices, guest WiFi, and anything that has compromised one host. Phoenix is a credential concentrator: one sniffed bearer token yields everything that token's ACL permits.
- **Enable TLS whenever requests cross a wire.** Any non-loopback `server` URL should be `https://`, with `caCert` (or `PHOENIX_CA_CERT`) pointed at the Phoenix CA certificate. Phoenix's internal CA issues the server certificate with IP SANs, so `https://<ip>:9090` validates without public DNS, a reverse proxy, or Let's Encrypt.

When a configured Phoenix server URL (top-level or a per-agent override) uses plain `http://` to a non-loopback address, the plugin emits a security warning naming what is exposed — the bearer token and resolved secret values, in cleartext, readable by anything on that network segment — and how to fix it. The warning surfaces in three places:

- the gateway-startup preflight logs it through the gateway's plugin logger
- `phoenix_status` includes it in its structured `notes`
- `openclaw phoenix verify` reports it in the result's `warnings` and prints it

The plugin **warns and never refuses**: hard-failing on plain HTTP would break existing published deployments with no migration path. This warn-only posture is deliberate and shared by `phoenix-server` itself and the Hermes Phoenix plugin.

## Installation

The plugin runs inside the OpenClaw gateway process, so the gateway host's Node version governs: current OpenClaw releases (2026.6.x) require Node >= 22.19.

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
            "example-agent": {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/example-agent",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/example-agent.seal.key",
              defaultNamespace: "openclaw-example-agent"
            },
            "my-agent": {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/my-agent",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/my-agent.seal.key",
              defaultNamespace: "openclaw-my-agent"
            }
          }
        }
      }
    }
  }
}
```

Per-agent entries support optional `server`, `caCert`, `clientCert`, `clientKey`, and `sealMode` overrides. Token files and seal key files must be unique per mapped agent, and the selected host token, seal key, and mTLS client key files must have no group/other permission bits (`chmod 600` is recommended). Startup preflight warns about duplicate token/seal-key contents; every runtime tool call revalidates that material and fails closed until duplicates are corrected. Unknown or unmapped `ctx.agentId` values fail closed with remediation instead of falling back to a shared token.

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

The smoke uses `OPENCLAW_REPO` when set, otherwise an `openclaw` checkout next to this repo. If the local OpenClaw checkout is absent it reports a TAP skip with that instruction. It imports the plugin through the documented `openclaw/plugin-sdk/plugin-entry` seam, preferring the checkout's real `definePluginEntry` and falling back to a smoke SDK shim when the checkout cannot be loaded standalone (set `OPENCLAW_SMOKE_REQUIRE_REAL_SDK=1` to fail instead of falling back). It verifies the checkout exposes that SDK subpath, captures tool/service/CLI registration, and does not read real Phoenix secrets or deploy anything.

### Integration tests

```bash
npm run test:integration
```

This tier boots a throwaway local `phoenix-server` (fresh store under `os.tmpdir()`, listening on `127.0.0.1` only, seeded with synthetic secrets) and drives the plugin's real tools, startup preflight, `openclaw phoenix verify` path, sealed responses, audit metadata, and mTLS against it. The server and its temp directory are torn down after the run.

Server acquisition, in order:

- `PHOENIX_SERVER_BIN` — path to a prebuilt `phoenix-server` binary (`PHOENIX_CLI_BIN` for the `phoenix` CLI; defaults to a `phoenix` binary next to `PHOENIX_SERVER_BIN`).
- Otherwise it builds both binaries from a Phoenix source checkout at `PHOENIX_SRC` (default: a `phoenix` checkout next to this repo) using the Go toolchain from `GO` (default `go` on `PATH`).

If neither a prebuilt binary nor a buildable checkout is available, the suite reports a TAP skip with those instructions instead of failing; set `PHOENIX_INTEGRATION_REQUIRED=1` to turn that skip into a failure for CI/release gates. `npm test` does not run this tier and stays fully offline.

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
