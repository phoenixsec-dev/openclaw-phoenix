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
Do not commit real tokens or certificates.

## Files

- `docker-compose.bearer.yml`
- `docker-compose.mtls.yml`
- `.env.example`
- `openclaw.jsonc`

## Notes

- The plugin path talks to Phoenix over HTTP(S) directly.
- The gateway only needs the minimum Phoenix auth material.
- `openclaw phoenix verify` is a good first smoke test after startup.


Important: the included `openclaw.jsonc` enables the plugin only. It intentionally does not use raw `phoenix://...` strings in built-in OpenClaw env settings.
