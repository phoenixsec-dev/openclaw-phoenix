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

2. **Exec provider path — bootstrap/config path**
   - OpenClaw resolves refs at startup via its built-in exec provider
   - best for gateway auth tokens, model/API keys, channel bot tokens, and other startup-only secrets
   - Phoenix CLI v0.14.0+ supports OpenClaw's stdin/stdout exec protocol via `phoenix resolve --stdin-json` (aliases: `phoenix openclaw-exec-provider`, `phoenix secret-provider openclaw`)
   - simpler operationally, but weaker for per-agent runtime policy enforcement than plugin tool calls

## Recommended usage by risk tier

- **Tier 0 / Tier 1**: exec provider is acceptable if startup-only injection is enough
- **Tier 1 / Tier 2**: prefer the plugin path
- **Privileged or policy-sensitive secrets**: prefer plugin path with sealed mode enabled

## OpenClaw ↔ Phoenix concept mapping

| OpenClaw concept | Phoenix concept | Notes |
| --- | --- | --- |
| Gateway process | Phoenix plugin runtime | Holds config, but should not be the live trust boundary for multiple agents |
| Trusted `ctx.agentId` | Phoenix client identity selector | Plugin chooses the mapped token file/seal key from OpenClaw runtime context only |
| Agent tool call | Secret resolution request | Phoenix enforces ACL/attestation for the selected bearer token/session and seal key |
| Agent/session context | Optional request metadata | `X-OpenClaw-*` headers are audit hints only; raw headers are not trusted for identity |
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

Then enable/configure it in OpenClaw config with per-agent identities:

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
          agents: {
            main: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/main",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/main.seal.key",
              defaultNamespace: "openclaw-main"
            },
            kit: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/kit",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/kit.seal.key",
              defaultNamespace: "openclaw-kit"
            },
            phoenix: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/phoenix",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/phoenix.seal.key",
              defaultNamespace: "openclaw-phoenix"
            },
            echo: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/echo",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/echo.seal.key",
              defaultNamespace: "openclaw-echo"
            },
            relay: {
              tokenFile: "/home/openclaw/.config/phoenix/tokens/relay",
              sealKeyFile: "/home/openclaw/.config/phoenix/keys/relay.seal.key",
              defaultNamespace: "openclaw-relay"
            }
          }
        }
      }
    }
  }
}
```

That enables the tool-based integration only. It does **not** wire Phoenix into `agents.defaults.env` or other built-in SecretRef fields by itself. When `agents` is configured, tool calls without a mapped trusted `ctx.agentId` fail closed instead of using a shared fallback.

The plugin registers its tools as optional. Expose them intentionally through OpenClaw tool policy. A conservative first rollout is to allow only `phoenix_status` and deny `phoenix_resolve`/`phoenix_list` until per-agent identity and sealed-mode behavior are validated.

```json5
{
  tools: {
    alsoAllow: ["phoenix_status"],
    deny: ["phoenix_resolve", "phoenix_list"]
  }
}
```

## Important distinction: plugin refs vs OpenClaw SecretRefs

These are **not** the same thing:

1. **Plugin tool refs**
   - used when an agent calls `phoenix_resolve`
   - string form: `phoenix://namespace/secret-name`

2. **OpenClaw built-in SecretRefs**
   - used by OpenClaw's built-in secret providers
   - object form: `{ source, provider, id }`

This Phase 1 plugin supports the first form only. Installing the plugin does **not** make raw `phoenix://...` strings inside `agents.defaults.env` work as built-in OpenClaw secrets.

If you want built-in startup secret resolution, use OpenClaw's exec-provider path with Phoenix CLI v0.14.0+.

## Plugin configuration

Config fields:

- `server` — Phoenix base URL, inherited by per-agent mappings unless an agent overrides it
- `sealMode` — when true, `phoenix_resolve` returns `PHOENIX_SEALED:` tokens; inherited by agents unless they override it
- `agents` — mapping from trusted OpenClaw `ctx.agentId` values (`main`, `kit`, `phoenix`, `echo`, `relay`) to Phoenix identities
- `agents.<id>.tokenFile` — required per-agent bearer token file; must be unique across mapped agents
- `agents.<id>.sealKeyFile` — required for that agent when effective `sealMode` is true; must be unique across mapped agents
- `agents.<id>.defaultNamespace` — default namespace used when that agent passes bare ids like `api-key`
- `agents.<id>.server`, `caCert`, `clientCert`, `clientKey`, `sealMode` — optional per-agent overrides

Diagnostic/dev single-identity fields still exist:

- `token`, `tokenFile`, `sealKeyFile`, `defaultNamespace`
- `PHOENIX_TOKEN`, `PHOENIX_TOKEN_FILE`, `PHOENIX_DEFAULT_NAMESPACE`, `PHOENIX_SEAL_KEY`

Single-identity mode is useful for local diagnostics and `openclaw phoenix verify`, but it is **not** per-agent trust. Do not expose live `phoenix_resolve`/`phoenix_list` to multiple agents with one shared token.

Environment fallbacks shared by both modes:

- `PHOENIX_SERVER`
- `PHOENIX_CA_CERT`
- `PHOENIX_CLIENT_CERT`
- `PHOENIX_CLIENT_KEY`
- `PHOENIX_SEAL_MODE`

## Sealed mode seal keys

When `sealMode` is true, the plugin must use a persistent seal key for the selected identity. In per-agent mode, configure `agents.<id>.sealKeyFile` for each mapped agent. The plugin validates the selected file during startup/status/verify/resolve, rejects group/other permissions, derives the public X25519 key locally, and sends that public key as `X-Phoenix-Seal-Key` on `phoenix_resolve` requests.

Operational checklist:
1. Generate a separate seal key pair for each OpenClaw agent identity, writing each private key to a local file.
2. Keep private key files mounted/readable only by the OpenClaw gateway process; do not commit them. Use restrictive permissions such as `chmod 600 /path/to/echo.seal.key`.
3. Register each derived/printed public key with Phoenix for the matching agent or role-session identity before live requests.
4. Use live tool calls from each agent identity to validate Phoenix-side public-key registration and policy. `openclaw phoenix verify` is a diagnostic shared-identity helper and does not prove every runtime agent identity is authorized.
5. Keep `phoenix_resolve` and `phoenix_list` denied until scoped auth, per-agent identity mapping, and sealed behavior are validated.

CT120 policy: keep rollout conservative. Do not deploy this plugin change to CT120 or enable broad Phoenix tools there until scoped per-agent credentials, registered public seal keys, and allowlists have been validated separately.

## Authentication patterns

### Bearer token pattern

Use this for simple local/dev setups and per-agent runtime identities.

- for live tools, prefer `agents.<id>.tokenFile` pointing at an existing scoped token file for each mapped OpenClaw agent
- top-level `tokenFile`/`PHOENIX_TOKEN_FILE` is diagnostic/dev only and does not provide per-agent isolation
- if you inject `PHOENIX_TOKEN` directly, scope it narrowly and understand it becomes part of the gateway process environment
- do **not** use a broad admin token as the normal gateway credential

### mTLS pattern

Use this for stronger machine identity.

- mount `caCert`, `clientCert`, and `clientKey` into the gateway container
- point shared plugin config or per-agent overrides at those mounted paths
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
- bare ids use the selected agent's `defaultNamespace` when per-agent mappings are configured
- on success returns values
- in sealed mode loads the selected agent's `sealKeyFile`, sends the derived public key as `X-Phoenix-Seal-Key`, and returns opaque `PHOENIX_SEALED:` tokens
- in sealed mode ignores plaintext `values` from the response so tool output remains opaque
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

The plugin registers a startup preflight that verifies Phoenix connectivity. When `agents` is configured, startup checks each mapped agent identity with its selected token file and seal key, and rejects duplicate token or seal-key material across mapped agents.

If Phoenix is unreachable or TLS/auth is broken, the plugin reports an actionable startup error. In current OpenClaw behavior this is surfaced through plugin startup/service error logging; whether the whole gateway hard-fails depends on OpenClaw core startup semantics.

## Verification workflow

Run:

```bash
openclaw phoenix verify
```

What it does:
- validates local sealed-mode key loading for the configured diagnostic identity when `sealMode` is enabled
- scans the active OpenClaw config for `phoenix://` references
- calls Phoenix dry-run resolution via `/v1/resolve?dry_run=true`
- sends the derived public seal key on dry-run requests when sealed mode is enabled
- reports OK/FAIL per ref without returning plaintext secret values

`openclaw phoenix verify` runs outside agent tool context, so it cannot select `ctx.agentId`. If per-agent mappings are enabled without a top-level diagnostic identity, the command asks for one rather than pretending to verify per-agent trust. Dry-run verification does not prove live sealed access is registered/authorized for every runtime agent; Phoenix-side public-key registration and policy still need live rollout checks from each mapped agent.

Use this after:
- changing Phoenix URL/auth config
- rotating a diagnostic credential
- adding new `phoenix://` refs to OpenClaw config

## Docker Compose pattern

See `examples/openclaw-docker/` for copy-pasteable examples.

Key points:
- plugin path uses direct API calls from gateway to Phoenix
- mount only the minimum token/cert material into the gateway
- prefer per-agent token files over env vars for live runtime tools
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
- older docs/examples that imply plain `phoenix resolve <ref>` argument-by-argument execution are not compatible with OpenClaw's actual exec provider contract; use `phoenix resolve --stdin-json` or one of its OpenClaw aliases
- if you need exec mode, implement or wait for Phoenix CLI support for this protocol on the Phoenix side

## Anti-patterns

Avoid:
- using one shared admin token for every OpenClaw environment
- exposing `phoenix_resolve` or `phoenix_list` to multiple agents with only single-identity diagnostic config
- letting tool parameters such as `agentId` or `identity` choose Phoenix credentials
- treating raw `X-OpenClaw-*` headers as a Phoenix trust boundary
- committing tokens, certs, or private keys into this repo or compose files
- baking Phoenix credentials into container images
- assuming exec-provider startup resolution gives per-agent isolation
- assuming `phoenix exec` lifecycle issues apply to the plugin path — the plugin uses direct HTTP API calls instead
- exposing broad infra credentials under `openclaw/shared/*`

## Suggested rollout order

1. start with per-agent bearer token files + plugin path in a dev environment
2. generate/register per-agent seal keys and enable sealed mode
3. allow `phoenix_status` first and confirm startup checks each mapped identity
4. test live `phoenix_resolve` from each mapped agent identity; confirm unmapped agents are denied
5. optionally add a top-level diagnostic identity for `openclaw phoenix verify`
6. move to mTLS for long-lived deployments where useful
7. tighten namespaces and roles before introducing privileged secrets
