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


Important: this example does not put `phoenix://...` strings into built-in OpenClaw env fields, because the current plugin does not implement built-in SecretRef resolution.
