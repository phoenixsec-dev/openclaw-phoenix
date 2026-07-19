# OpenClaw plugin config example

This folder contains a minimal OpenClaw config example for the Phoenix plugin tool path.

## Install

Use the approved package release when available:

```bash
openclaw plugins install openclaw-phoenix
```

For local source development, link this checkout instead:

```bash
openclaw plugins install -l ./path/to/openclaw-phoenix
```

## Verify

`openclaw phoenix verify` is a diagnostic shared-identity command. This per-agent example is meant to be validated through live tool calls from each mapped OpenClaw agent (`main`, `kit`, `phoenix`, `echo`, `relay`).

## Files

- `openclaw.jsonc` — plugin enablement and sample `phoenix://` refs
- `.env.example` — environment variables to provide to the gateway process

## Per-agent identity and sealed keys

This example enables `sealMode` and configures `agents.<id>.tokenFile` plus `agents.<id>.sealKeyFile` for each trusted OpenClaw agent id. Generate/register a separate Phoenix token and seal key for every mapped agent, keep private files local, and lock both token files and seal key files down so group/other bits are clear (for example, `chmod 600 /path/to/echo.token /path/to/echo.seal.key`). Register each derived public seal key in Phoenix before enabling sealed `phoenix_resolve`/`phoenix_list` access.

Conservative rollout: allow `phoenix_status` first. Keep `phoenix_resolve` and `phoenix_list` denied until scoped per-agent credentials, file modes, public seal-key registration, and tool allowlists are validated.

Important: this example does not put `phoenix://...` strings into built-in OpenClaw env fields, because this plugin package does not implement built-in SecretRef resolution. Use the Phoenix CLI exec provider for OpenClaw bootstrap/config SecretRefs. Single-identity config is diagnostic/dev only and is not a per-agent trust boundary.
