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

Because `openclaw.jsonc` enables sealed mode, create/register a persistent Phoenix seal key first, set `PHOENIX_SEAL_KEY_HOST` to that host file, and keep it private (for example, `chmod 600 ./openclaw-agent.seal.key`). The compose files mount it read-only at `PHOENIX_SEAL_KEY` inside the gateway container.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `.env.example`
- `openclaw.jsonc`

## Notes

- The plugin path talks to Phoenix over HTTP(S) directly.
- The gateway only needs the minimum Phoenix auth material and its own seal private key.
- `openclaw phoenix verify` validates local seal-key loading and sends the derived public key on dry-run requests, but live Phoenix use still requires server-side public-key registration.


Important: the included `openclaw.jsonc` enables the plugin only. It intentionally does not use raw `phoenix://...` strings in built-in OpenClaw env settings.
