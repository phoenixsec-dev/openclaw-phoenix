# OpenClaw plugin config example

This folder contains a minimal OpenClaw config example for the Phoenix plugin tool path.

## Install

```bash
openclaw plugins install ./path/to/openclaw-phoenix -l
```

## Verify

```bash
openclaw phoenix verify
```

## Files

- `openclaw.jsonc` — plugin enablement and sample `phoenix://` refs
- `.env.example` — environment variables to provide to the gateway process

## Sealed mode key

This example enables `sealMode`, so `PHOENIX_SEAL_KEY` must point to a persistent Phoenix seal private key file. Generate/register the key with Phoenix first, keep the private key local, and lock it down (for example, `chmod 600 /path/to/openclaw-agent.seal.key`).

Important: this example does not put `phoenix://...` strings into built-in OpenClaw env fields, because the current plugin does not implement built-in SecretRef resolution.
