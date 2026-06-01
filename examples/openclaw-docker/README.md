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

Because `openclaw.jsonc` enables sealed mode and per-agent identities, create/register a Phoenix token file and seal key file for each mapped agent (`main`, `kit`, `phoenix`, `echo`, `relay`). Set the matching `PHOENIX_TOKEN_FILE_*_HOST` and `PHOENIX_SEAL_KEY_*_HOST` values, and keep seal keys private (for example, `chmod 600 ./keys/echo.seal.key`). The compose files mount all token/seal-key files read-only inside the gateway container.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `.env.example`
- `openclaw.jsonc`

## Notes

- The plugin path talks to Phoenix over HTTP(S) directly.
- The gateway only needs the minimum Phoenix auth material and per-agent seal private keys.
- Single-identity config is diagnostic/dev only and is not a per-agent trust boundary.
- `openclaw phoenix verify` is a diagnostic shared-identity helper; validate live per-agent access with tool calls from each mapped agent.


Important: the included `openclaw.jsonc` enables the plugin only. It intentionally does not use raw `phoenix://...` strings in built-in OpenClaw env settings.
