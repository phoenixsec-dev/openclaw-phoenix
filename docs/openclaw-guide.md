# OpenClaw + Phoenix Guide

This guide explains how to run [Phoenix Secrets Manager](https://github.com/phoenixsec-dev/phoenix) with OpenClaw.

## Audience

Use this if you want:
- OpenClaw agents to resolve secrets at runtime
- Phoenix ACL, attestation, sealed responses, and audit logs
- a repeatable local/dev deployment pattern

## Integration paths

There are two integration paths:

1. **Plugin path — recommended now**
   - OpenClaw loads this plugin
   - agents call `phoenix_resolve`, `phoenix_list`, and `phoenix_status`
   - Phoenix policy is enforced per request
   - sealed mode can keep values out of model-visible tool output
   - this avoids the Docker lifecycle issues around `phoenix exec`
   - **important:** this Phase 1 plugin does **not** hook into OpenClaw's built-in SecretRef resolution

2. **Exec provider path — fallback/simple path**
   - OpenClaw resolves refs at startup via its built-in exec provider
   - best for bulk startup-only secrets
   - simpler operationally, but weaker for per-agent policy enforcement
   - **status:** the protocol is documented here, but Phoenix CLI support for the OpenClaw stdin/stdout exec protocol is a separate Phoenix-side change and is not implemented in this repo

## Recommended usage by risk tier

- **Tier 0 / Tier 1**: exec provider is acceptable if startup-only injection is enough
- **Tier 1 / Tier 2**: prefer the plugin path
- **Privileged or policy-sensitive secrets**: prefer plugin path with sealed mode enabled

## OpenClaw ↔ Phoenix concept mapping

| OpenClaw concept | Phoenix concept | Notes |
| --- | --- | --- |
| Gateway process | Phoenix client identity | Authenticates with bearer token or mTLS |
| Agent tool call | Secret resolution request | Phoenix enforces ACL/attestation per request |
| Agent/session context | Optional request metadata | This plugin sends `X-OpenClaw-*` headers today, but current Phoenix server code does not consume them yet |
| OpenClaw SecretRef object | Built-in OpenClaw secret resolution | Separate from this plugin; uses `{ source, provider, id }` object shape |
| Plugin tool `phoenix://...` ref | Phoenix secret path | `phoenix://namespace/name` maps to `namespace/name` inside plugin tool calls |
| Shared config namespace | Shared Phoenix namespace | Good default: `openclaw/shared/*` |
| Agent-specific config | Agent-scoped namespace | Good default: `openclaw/agents/<agent-id>/*` |

## Recommended namespace layout

```text
openclaw/shared/openai-api-key
openclaw/shared/anthropic-api-key
openclaw/agents/researcher/github-token
openclaw/agents/deployer/proxmox-api-token
openclaw/admin/breakglass
```

Suggested policy split:
- `openclaw/shared/*` — shared low/medium-risk provider tokens
- `openclaw/agents/<id>/*` — secrets scoped to a single agent role
- `openclaw/admin/*` — privileged, step-up or tightly attested secrets

## Recommended role structure

Example intent:
- `openclaw-gateway`
  - startup-only or shared-access role
  - namespace: `openclaw/shared/*`
- `openclaw-agent`
  - normal runtime role
  - namespace: `openclaw/shared/*`, `openclaw/agents/<agent-id>/*`
- `openclaw-privileged`
  - high-risk operations
  - namespace: specific infra/admin paths only
  - step-up approval enabled

## Installing the plugin

Local development install:

```bash
openclaw plugins install ./path/to/openclaw-phoenix -l
```

Then enable/configure it in OpenClaw config:

```json5
{
  plugins: {
    allow: ["phoenix-secrets"],
    entries: {
      "phoenix-secrets": {
        enabled: true,
        config: {
          server: "https://phoenix:9090",
          defaultNamespace: "openclaw",
          sealMode: true
        }
      }
    }
  }
}
```

That enables the tool-based integration only. It does **not** wire Phoenix into `agents.defaults.env` or other built-in SecretRef fields by itself.

## Important distinction: plugin refs vs OpenClaw SecretRefs

These are **not** the same thing:

1. **Plugin tool refs**
   - used when an agent calls `phoenix_resolve`
   - string form: `phoenix://namespace/secret-name`

2. **OpenClaw built-in SecretRefs**
   - used by OpenClaw's built-in secret providers
   - object form: `{ source, provider, id }`

This Phase 1 plugin supports the first form only. Installing the plugin does **not** make raw `phoenix://...` strings inside `agents.defaults.env` work as built-in OpenClaw secrets.

If you want built-in startup secret resolution, use the exec-provider path once Phoenix-side support for OpenClaw's exec protocol exists.

## Plugin configuration

Config fields:

- `server` — Phoenix base URL
- `token` — bearer token, optional if mTLS is used
- `caCert` — optional CA bundle path
- `clientCert` — client cert path for mTLS
- `clientKey` — client private key path for mTLS
- `defaultNamespace` — lets callers use bare ids like `api-key`
- `sealMode` — when true, `phoenix_resolve` returns `PHOENIX_SEALED:` tokens

Environment fallbacks:

- `PHOENIX_SERVER`
- `PHOENIX_TOKEN`
- `PHOENIX_CA_CERT`
- `PHOENIX_CLIENT_CERT`
- `PHOENIX_CLIENT_KEY`
- `PHOENIX_DEFAULT_NAMESPACE`
- `PHOENIX_SEAL_MODE`

## Authentication patterns

### Bearer token pattern

Use this for simple local/dev setups.

- mount or inject `PHOENIX_TOKEN` into the OpenClaw gateway environment
- scope the token narrowly
- do **not** use a broad admin token as the normal gateway credential

### mTLS pattern

Use this for stronger machine identity.

- mount `caCert`, `clientCert`, and `clientKey` into the gateway container
- point plugin config or env vars at those mounted paths
- keep file permissions tight

## Tool behavior

### `phoenix_resolve`

Input:

```json
{
  "refs": [
    "phoenix://openclaw/shared/openai-api-key",
    "github-token"
  ]
}
```

Behavior:
- bare ids use `defaultNamespace` when configured
- on success returns values
- in sealed mode returns opaque `PHOENIX_SEALED:` tokens
- on partial success returns both `values` and `errors`

### `phoenix_list`

Lists visible paths only, not secret values.

### `phoenix_status`

Checks:
- Phoenix connectivity
- `/v1/health`
- `/v1/status` when current credentials are allowed
- TLS peer certificate details when HTTPS is used

Note: Phoenix's current REST API does not expose a server version field, so this plugin reports version as unavailable instead of guessing.

## Startup behavior

The plugin registers a startup preflight that verifies Phoenix connectivity.

If Phoenix is unreachable or TLS/auth is broken, the plugin reports an actionable startup error. In current OpenClaw behavior this is surfaced through plugin startup/service error logging; whether the whole gateway hard-fails depends on OpenClaw core startup semantics.

## Verification workflow

Run:

```bash
openclaw phoenix verify
```

What it does:
- scans the active OpenClaw config for `phoenix://` references
- calls Phoenix dry-run resolution via `/v1/resolve?dry_run=true`
- reports OK/FAIL per ref without returning plaintext secret values

Use this after:
- changing Phoenix URL/auth config
- rotating gateway credentials
- adding new `phoenix://` refs to OpenClaw config

## Docker Compose pattern

See `examples/openclaw-docker/` for copy-pasteable examples.

Key points:
- plugin path uses direct API calls from gateway to Phoenix
- mount only the minimum token/cert material into the gateway
- prefer env vars for token injection
- do not bake secrets into images or commit them to files
- do not put raw `phoenix://...` strings into built-in OpenClaw env/config fields unless you are using a real SecretRef-backed provider path

## Step-up approval behavior

This plugin already surfaces structured denial payloads from Phoenix, including approval-related responses when Phoenix returns them.

Operationally:
1. agent/tool requests a protected secret
2. Phoenix may deny or require approval
3. tool result includes structured error data and remediation hints
4. operator approves through Phoenix-side workflow
5. agent retries after approval

Full conversational approval UX is a later phase, but the payloads are structured now so the agent can explain what happened.

## Exec provider protocol reference

OpenClaw exec secret providers use stdin/stdout JSON, not CLI args.

Input to provider process:

```json
{
  "protocolVersion": 1,
  "provider": "phoenix",
  "ids": ["openclaw/shared/openai-api-key", "openclaw/shared/anthropic-api-key"]
}
```

Expected output:

```json
{
  "protocolVersion": 1,
  "values": {
    "openclaw/shared/openai-api-key": "sk-...",
    "openclaw/shared/anthropic-api-key": "sk-ant-..."
  }
}
```

Migration note:
- older docs/examples that imply `phoenix resolve <ref>` argument-by-argument execution are not compatible with OpenClaw's actual exec provider contract
- if you need exec mode, implement or wait for Phoenix CLI support for this protocol on the Phoenix side

## Anti-patterns

Avoid:
- using one shared admin token for every OpenClaw environment
- committing tokens, certs, or private keys into this repo or compose files
- baking Phoenix credentials into container images
- assuming exec-provider startup resolution gives per-agent isolation
- assuming `phoenix exec` lifecycle issues apply to the plugin path — the plugin uses direct HTTP API calls instead
- exposing broad infra credentials under `openclaw/shared/*`

## Suggested rollout order

1. start with bearer token + plugin path in a dev environment
2. enable `openclaw phoenix verify`
3. move to mTLS for long-lived deployments
4. enable sealed mode for sensitive paths
5. tighten namespaces and roles before introducing privileged secrets
