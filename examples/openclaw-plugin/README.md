# OpenClaw plugin config example

This folder contains a minimal OpenClaw config example for the Phoenix plugin tool path.

## Install

```bash
openclaw plugins install ./path/to/openclaw-phoenix -l
```

## Verify

`openclaw phoenix verify` is a diagnostic shared-identity command. This per-agent example is meant to be validated through live tool calls from each mapped OpenClaw agent (`main`, `kit`, `phoenix`, `echo`, `relay`).

## Files

- `openclaw.jsonc` — plugin enablement and sample `phoenix://` refs
- `.env.example` — environment variables to provide to the gateway process

## Per-agent identity and sealed keys

This example enables `sealMode` and configures `agents.<id>.tokenFile` plus `agents.<id>.sealKeyFile` for each trusted OpenClaw agent id. Generate/register a separate Phoenix token and seal key for every mapped agent, keep private files local, and lock seal keys down (for example, `chmod 600 /path/to/echo.seal.key`).

Important: this example does not put `phoenix://...` strings into built-in OpenClaw env fields, because the current plugin does not implement built-in SecretRef resolution. Single-identity config is diagnostic/dev only and is not a per-agent trust boundary.
