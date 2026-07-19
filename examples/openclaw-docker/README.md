# OpenClaw + Phoenix Docker examples

This folder shows two patterns:
- bearer token auth
- mTLS auth

## Usage

1. Copy `.env.example` to `.env`
2. Fill in your local values
3. Pick a compose file
4. Start the stack with Docker Compose

These examples intentionally use environment variables and mounted files only.
Do not commit real tokens, certificates, or seal private keys.

Because `openclaw.jsonc` enables sealed mode and per-agent identities, create/register a Phoenix token file and seal key file for each mapped agent (`main`, `kit`, `phoenix`, `echo`, `relay`). Set the matching `PHOENIX_TOKEN_FILE_*_HOST` and `PHOENIX_SEAL_KEY_*_HOST` values. Lock down both host token files and host seal key files before starting Compose (for example, `chmod 600 ./tokens/echo ./keys/echo.seal.key`); group/other bits must be clear. The compose files mount all token/seal-key files read-only inside the gateway container, but read-only mounts alone do not satisfy the plugin's permission checks.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `.env.example`
- `openclaw.jsonc`

## Notes

- The plugin path talks to Phoenix over HTTP(S) directly.
- The mTLS Compose file deliberately overrides `PHOENIX_SERVER` to `https://phoenix:9090`; do not use an `http://` URL with client certificate settings because the plugin only applies TLS material to HTTPS requests.
- The gateway only needs the minimum Phoenix auth material and per-agent seal private keys.
- Host token/seal-key file modes must be `0600`-style before bind mounting; `:ro` protects the mounted view but does not fix insecure host modes.
- Single-identity config is diagnostic/dev only and is not a per-agent trust boundary.
- `openclaw phoenix verify` is a diagnostic shared-identity helper; validate live per-agent access with tool calls from each mapped agent.
- For release/package installs, install `openclaw-phoenix` with `openclaw plugins install openclaw-phoenix`; these compose files keep a local checkout bind mount for example/dev use.

Important: the included `openclaw.jsonc` enables the plugin only. It intentionally does not use raw `phoenix://...` strings in built-in OpenClaw env settings. Use Phoenix CLI exec-provider SecretRefs for bootstrap/config secrets.
