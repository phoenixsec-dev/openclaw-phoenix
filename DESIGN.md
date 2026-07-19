# OpenClaw Integration Plan (v2)

**Date:** 2026-03-22 (v2 rewrite)
**Status:** Draft — ready for review
**Author:** Aaron (via Claude Code planning session)
**Supersedes:** v1 of this file (2026-03-20) — corrected factual errors about
OpenClaw's plugin architecture and exec protocol, reoriented around plugin-first
approach
**Target release:** v1.0 (OpenClaw-integrated release)

---

## What changed from v1

v1 was built on three wrong assumptions:

1. **"OpenClaw doesn't have a plugin architecture."** It does. Full plugin SDK
   with `registerProvider`, `registerTool`, `registerHook`, `registerChannel`,
   etc. Third-party plugins are fully supported. The *secrets provider* system
   is hardcoded to env/file/exec, but a plugin can register tools and hooks
   that work alongside the secrets system.

2. **"The exec provider calls `phoenix resolve <ref>` as a CLI command."** It
   doesn't. The exec provider sends a JSON payload via stdin:
   ```json
   { "protocolVersion": 1, "provider": "phoenix", "ids": ["path1", "path2"] }
   ```
   and expects JSON back on stdout:
   ```json
   { "protocolVersion": 1, "values": { "path1": "secret-value" } }
   ```
   Phoenix doesn't implement this protocol today. The current
   `docs/integrations.md` exec backend examples are incomplete.

3. **"Subagents can get their own env vars."** They can't. Subagents are
   separate processes against the same gateway. They share the gateway's
   in-memory secrets snapshot (eager, atomic resolution at startup). There is
   no mechanism for per-subagent env var separation. Subagent isolation must
   happen at the plugin tool level, not the secrets provider level.

v1 recommended docs + CLI setup tooling and deferred the plugin. That's
backwards. The plugin is the integration path. This plan puts it first.

---

## Problem Statement

Phoenix solves a security problem that OpenClaw explicitly acknowledges but does
not address: **skills and subagents run with the same privileges as the
orchestrator, and any skill can read environment variables and config files
containing secrets.** OpenClaw's SecretRef system moved secrets out of config
files, but the resolved values are still plaintext in the gateway process's
memory, unencrypted on disk, and accessible to any tool in the execution
context.

Phoenix closes that gap: encryption at rest, per-agent access control,
attestation-gated resolution, sealed responses that keep values out of model
context, and an audit trail of every access.

**The goal of this integration work is to make Phoenix the native secrets
backend for OpenClaw deployments** — via a first-class OpenClaw plugin that
operators install and configure in minutes.

---

## Current Integration Story

### What works today

1. **Exec backend integration** — OpenClaw's `exec` provider can call Phoenix,
   but Phoenix doesn't implement the required stdin JSON protocol yet.
   The `docs/integrations.md` examples show a CLI-args pattern that doesn't
   match OpenClaw's actual exec provider contract.

2. **Docker Compose sidecar** — Phoenix runs as a network-adjacent service.
   OpenClaw reaches it via Compose DNS. Bearer token or mTLS auth.

3. **MCP server** — Agents using Claude can resolve secrets through Phoenix
   MCP tools (`phoenix_resolve`, `phoenix_get`, `phoenix_list`) with sealed
   mode keeping values out of context.

4. **Namespace/ACL scoping** — Policies can scope secrets to `openclaw/*`
   namespaces, restricting which agents/roles see which secrets.

5. **SDKs** — Go, Python, and TypeScript SDKs can resolve secrets
   programmatically.

### Prior research (openclaw-workspace)

Extensive research exists in `/home/aaron/openclaw-workspace/research/`:

- `agent-secrets-management-research.md` — 1581-line survey of how Agent Zero,
  LangChain, AutoGen, OpenHands, n8n, Vault handle secrets. Phased
  implementation plan. Homelab MVP spec.
- `openclaw-built-in-secrets-feature-report.md` — analysis of OpenClaw's
  2026-02-26 secrets feature. Recommends "OpenClaw as operator/control plane
  UX, Phoenix as security/policy backend."
- `phoenix-gate4-attestation-and-placeholder-plan.md` — placeholder secrets
  model (`secret://proxmox/api-token`), attestation flow, policy rules.
  6-week MVP timeline.
- `key-pair-authentication-for-ai-agents-2026-03-01.md` — machine identity
  patterns, mTLS hygiene, verified Phoenix token+binary mounts work in
  container.
- `phoenix-demand-map.md` — market research on secrets management pain points.

### Tiered risk model (from existing research)

The openclaw-workspace research established a risk tiering that this plan
adopts:

- **Tier 0 (low-risk):** API keys for LLM providers, embedding services.
  Leak = cost, not compromise.
- **Tier 1 (medium):** Git SSH keys, service API tokens. Leak = unauthorized
  access to specific services.
- **Tier 2 (high-risk):** Infrastructure credentials (Proxmox API, admin
  passwords, deployment tokens). Leak = full infrastructure compromise.

Phoenix should handle all tiers, but step-up approval and strict attestation
are most critical for Tier 2.

---

## Gaps

### G1: No plugin (critical — this plan's primary deliverable)

OpenClaw has a plugin SDK. Phoenix doesn't have a plugin. The exec backend
is a workaround, not a real integration. A native plugin can:

- Register tools that resolve secrets on-demand (not just at startup)
- Register hooks that validate access before delivery
- Provide structured error responses (attestation failures, approval needed)
- Surface Phoenix capabilities in OpenClaw's CLI (`openclaw plugins list`)
- Install via `openclaw plugins install` — standard operator workflow

### G2: Exec protocol mismatch

Phoenix's `resolve` command doesn't implement OpenClaw's exec provider stdin
JSON protocol. Even if we build the plugin, fixing this is still valuable
for operators who want the simpler exec-only path.

### G3: Docker lifecycle

Documented in `DOCKER-SECRETS-GAP-please-read.md`. The plugin changes the
framing: if the plugin calls Phoenix's REST API directly (not through
`phoenix exec`), the Docker question simplifies to "how does the gateway
container authenticate to Phoenix at startup" — mount a token or cert, set
env vars.

The `phoenix exec` Docker lifecycle problem is still real for non-OpenClaw
Docker deployments, but it's no longer the #1 blocker for OpenClaw
specifically.

### G4: No concept mapping documentation

Same gap as v1. OpenClaw operators don't know how to map gateway/orchestrator/
agent/subagent to Phoenix roles/sessions/namespaces.

### G5: Subagent isolation

Subagents share the gateway's secrets snapshot. Per-subagent scoping **cannot
work through the secrets provider path** — it must work through plugin tools
that check caller identity and apply Phoenix ACLs per-request. This is a
plugin design concern, not a secrets provider concern.

---

## OpenClaw Plugin Architecture (what we're building on)

### How OpenClaw plugins work

**Source:** `/home/aaron/openclaw/docs/tools/plugin.md`,
`/home/aaron/openclaw/docs/plugins/architecture.md`,
`/home/aaron/openclaw/src/plugin-sdk/index.ts`

**Discovery precedence:**
1. `plugins.load.paths` (config-specified file or directory)
2. Workspace extensions: `<workspace>/.openclaw/extensions/*.ts` or `*/index.ts`
3. Global extensions: `~/.openclaw/extensions/*.ts` or `*/index.ts`
4. Bundled extensions

**Plugin shape options:**
- `plain-capability` — one capability type
- `hybrid-capability` — multiple capability types
- `hook-only` — hooks, no capabilities
- `non-capability` — tools, commands, services

**Registration API:**
```typescript
const plugin = {
  id: "phoenix-secrets",
  name: "Phoenix Secrets Manager",
  register(api: OpenClawPluginApi) {
    api.registerTool({ /* ... */ });
    api.registerHook("before_prompt_build", async (req) => { /* ... */ });
    api.registerCli(({ program }) => { /* ... */ }, { commands: ["phoenix"] });
    api.registerHttpRoute({ /* ... */ });
  }
};
```

**Available registrations:** `registerProvider`, `registerTool`, `registerHook`,
`registerChannel`, `registerSpeechProvider`, `registerMediaUnderstandingProvider`,
`registerWebSearchProvider`, `registerHttpRoute`, `registerCli`, and more.

**Installation:**
```bash
openclaw plugins install phoenix-secrets          # from npm
openclaw plugins install ./path/to/plugin         # local copy
openclaw plugins install ./path/to/plugin -l      # link for dev
```

**Security model:**
- Workspace-origin plugins disabled by default
- `plugins.deny` wins over `plugins.allow`
- Path ownership and permission validation on load

### What a Phoenix plugin would be

A **non-capability plugin** (tools + hooks + commands, no model provider).
It registers:

1. **Tools** — `phoenix_resolve`, `phoenix_get`, `phoenix_list` available to
   agents as callable tools (similar to MCP tools but native to OpenClaw)
2. **Hooks** — `before_prompt_build` to inject sealed references,
   `on_secret_resolve` if available to intercept SecretRef resolution
3. **Commands** — `openclaw phoenix status`, `openclaw phoenix verify` for
   operator diagnostics
4. **HTTP routes** — optional health/status endpoints

### Exec provider protocol (for fallback/simple path)

Even with the plugin, we should also implement the exec provider protocol
so operators who don't want a plugin can use the simpler exec path.

**Protocol (from `/home/aaron/openclaw/src/secrets/resolve.ts` lines 687-734):**

Input (stdin):
```json
{ "protocolVersion": 1, "provider": "phoenix", "ids": ["openclaw/shared/openai-key", "openclaw/shared/anthropic-key"] }
```

Output (stdout):
```json
{ "protocolVersion": 1, "values": { "openclaw/shared/openai-key": "sk-...", "openclaw/shared/anthropic-key": "sk-ant-..." } }
```

Exec provider config:
```json
{
  "secrets": {
    "providers": {
      "phoenix": {
        "source": "exec",
        "command": "/usr/local/bin/phoenix",
        "args": ["resolve", "--openclaw-exec"],
        "env": {
          "PHOENIX_SERVER": "http://phoenix:9090"
        },
        "passEnv": ["PHOENIX_TOKEN", "PHOENIX_CA_CERT", "PHOENIX_CLIENT_CERT", "PHOENIX_CLIENT_KEY"],
        "timeoutMs": 10000
      }
    }
  }
}
```

Key constraints:
- `shell: false` — no shell parsing, args as array
- `passEnv` allowlist — only specified env vars are inherited
- Timeout configurable (default 5s, Phoenix may need more for mTLS handshake)
- `maxOutputBytes` default 1MB (plenty for secrets)
- Path ownership validation on the command binary

---

## Concept Mapping: OpenClaw to Phoenix

### Verified facts (not assumptions)

These are confirmed from the OpenClaw codebase, not guessed:

1. **OpenClaw's gateway is the trust anchor.** The gateway process resolves
   secrets eagerly at startup into an in-memory snapshot. All agents and
   subagents read from this snapshot.

2. **Subagents share the gateway's secrets snapshot.** There is no per-subagent
   env var separation. Subagent isolation for secrets must happen at the tool
   level (plugin tools with per-request ACL checks), not the provider level.

3. **Secret resolution is eager and atomic.** All SecretRefs resolve at
   activation (startup, reload, manual `secrets.reload`). Full success or
   keep last-known-good. No lazy per-request resolution.

4. **Subagent spawn limits exist.** Max 5 active children per agent by default
   (`maxChildrenPerAgent`). Max spawn depth configurable
   (`maxSpawnDepth`). These limits are relevant for Phoenix session token
   fan-out.

5. **OpenClaw "role" is behavioral, not access-scoped.** Agent personality,
   boot sequence, reporting chain. Phoenix "role" is an access scope
   (namespaces, attestation, step-up). Different concepts, same word.

### The mapping

| OpenClaw Concept | Phoenix Concept | Notes |
|---|---|---|
| **Gateway** | Bootstrap trust (token or mTLS cert) | Gateway holds Phoenix credentials. Authenticated principal for startup resolution. |
| **Orchestrator** | Role (e.g., `openclaw-orchestrator`) | Broad namespace access. Own session token. |
| **Agent** | Role (1:1 or N:1) | Each agent identity maps to a Phoenix role with scoped namespace access. |
| **Subagent** | Plugin tool call with caller context | Subagents can't get their own secrets provider config. Isolation happens when subagents call plugin tools — the plugin checks caller identity and applies per-agent Phoenix ACLs. |
| **OpenClaw role** | *(no mapping)* | Behavioral construct. Phoenix doesn't model it. |
| **OpenClaw session** | Phoenix session | 1:1 when using plugin tools. Gateway startup resolution uses the gateway's session. |
| **SecretRef** | `phoenix://` reference | Via exec provider (startup) or plugin tool (runtime). |
| **Step-up approval** | Phoenix step-up (v1) | Agent requests privileged secret via plugin tool → Phoenix returns `APPROVAL_REQUIRED` → human approves → agent retries. |

### Two resolution paths

This is the key architectural insight. OpenClaw + Phoenix has **two distinct
secret resolution paths**, and the security properties differ:

**Path A: Exec provider (startup resolution)**
- Resolves all SecretRefs at gateway startup
- Bulk resolution into shared in-memory snapshot
- All agents/subagents see the same resolved values
- No per-agent scoping possible
- Good for: Tier 0/1 secrets (API keys, service tokens) where all agents
  need the same credentials

**Path B: Plugin tools (runtime resolution)**
- Agent calls `phoenix_resolve` tool during execution
- Per-request resolution with caller context
- Plugin can enforce per-agent ACLs, attestation, step-up
- Sealed mode keeps values out of model context
- Good for: Tier 2 secrets (infrastructure creds, admin tokens) where
  access should be scoped and audited per-agent

The recommended pattern: use Path A for shared low-risk credentials (LLM API
keys), use Path B for anything sensitive. The plugin makes Path B possible.

### Recommended namespace structure

```
openclaw/                          # top-level namespace
  shared/                          # Tier 0/1 — all agents via exec provider
    llm-api-key
    embedding-api-key
  orchestrator/                    # Tier 1/2 — orchestrator via plugin tool
    admin-api-key
    deployment-credentials
  agents/
    <agent-name>/                  # Tier 1 — per-agent via plugin tool
      tool-credentials
      service-api-key
  privileged/                      # Tier 2 — step-up required
    infra-admin
    payment-keys
```

### Recommended role structure

```yaml
roles:
  openclaw-gateway:
    # Gateway process — startup resolution for shared secrets
    namespaces: ["openclaw/shared/*"]
    attestation: [source_ip]
    step_up: false

  openclaw-orchestrator:
    # Orchestrator agent — broader runtime access via plugin tools
    namespaces: ["openclaw/shared/*", "openclaw/orchestrator/*", "openclaw/agents/*"]
    attestation: [uid, source_ip]
    step_up: false

  openclaw-agent:
    # Standard agent — own namespace + shared, via plugin tools
    namespaces: ["openclaw/shared/*", "openclaw/agents/${agent_name}/*"]
    attestation: [uid, source_ip]
    step_up: false

  openclaw-privileged:
    # Any agent accessing Tier 2 secrets
    namespaces: ["openclaw/privileged/*"]
    attestation: [uid, source_ip, cert_fingerprint]
    step_up: true
    step_up_ttl: 15m
```

### Safest default for privileged actions

**Deny by default, step-up for anything destructive.**

- Gateway credential (`openclaw-gateway`) scoped to `openclaw/shared/*` only.
  Used at startup for bulk exec resolution. Not passed to agents.
- Standard agents get `openclaw-agent` role via plugin — scoped to shared +
  own namespace, no step-up.
- Tier 2 access requires `openclaw-privileged` role with `step_up: true`.
- A compromised skill can read the agent's own API keys (via shared snapshot)
  but cannot escalate to infrastructure credentials without human approval.

---

## Phased Implementation Plan

### Phase 1: OpenClaw Plugin + Exec Protocol
*This is the first and primary deliverable. Start here.*

**Objective:** Ship a working OpenClaw plugin that registers Phoenix tools
and hooks, plus implement the exec provider stdin JSON protocol as a fallback
path.

**Scope:**

Plugin (TypeScript, lives in its own package):
- `registerTool` for `phoenix_resolve` — resolve one or more `phoenix://` refs
  at runtime, per-request, with caller context
- `registerTool` for `phoenix_list` — list available secret paths
- `registerTool` for `phoenix_status` — connection health, cert validity,
  session info
- documented startup service/lifecycle preflight — validate Phoenix connectivity at gateway boot,
  log warning-only diagnostics if Phoenix is unreachable
- `registerCli` / plugin CLI registrar for `openclaw phoenix verify` — dry-run validation of all
  `phoenix://` SecretRefs in config
- Plugin config schema: `server`, `token` (or cert paths), `defaultNamespace`,
  `sealMode` (boolean)
- Sealed mode support: tools return `PHOENIX_SEALED:` tokens when enabled
- Structured error responses: attestation failures, approval needed, scope
  exceeded — surfaced to the agent with remediation hints

Exec protocol (Go, in Phoenix CLI):
- `phoenix resolve --openclaw-exec` mode that reads stdin JSON protocol and
  writes stdout JSON protocol
- Batch resolution: receives array of IDs, resolves all, returns values map
- Error handling: per-ID errors in response (partial success supported by
  protocol)
- Respects OpenClaw's exec provider constraints (no shell, timeout-aware,
  clean exit codes)

**Out of scope:**
- Per-subagent session isolation (Phase 3)
- Step-up approval flow (Phase 3)
- Dashboard integration
- npm publishing (dev/local install first)
- OpenClaw upstream contributions

**Deliverables:**
- `plugins/openclaw-phoenix/` — plugin package with TypeScript source
- `plugins/openclaw-phoenix/package.json` — installable via
  `openclaw plugins install ./plugins/openclaw-phoenix`
- `cmd/phoenix/resolve_openclaw.go` — exec protocol handler
- Tests for both plugin tools and exec protocol
- Updated `docs/integrations.md` — corrected exec protocol examples

**Acceptance criteria:**
- Plugin installs via `openclaw plugins install` and appears in
  `openclaw plugins list`
- `phoenix_resolve` tool works from an agent conversation — agent can request
  and receive a secret value (or sealed token)
- `phoenix resolve --openclaw-exec` handles the stdin JSON protocol correctly
  with batch resolution
- Plugin startup preflight logs a clear warning when Phoenix server is unreachable
  and does not kill the OpenClaw gateway
- `openclaw phoenix verify` catches missing secrets, wrong server URL, ACL
  denials
- Existing Phoenix behavior (MCP, CLI, direct API) is unaffected

**Go/no-go:**
- Go: plugin resolves secrets in a real OpenClaw agent conversation; exec
  protocol handles batch resolution correctly
- No-go: if OpenClaw's plugin SDK doesn't support the registrations we need
  (verify `registerTool`, documented startup service/lifecycle registration, and `registerCli` / plugin CLI registrar actually work
  for our use case before building)

**Regression concerns:**
- New `--openclaw-exec` flag must not affect existing `phoenix resolve` behavior
- Plugin must not interfere with OpenClaw's built-in secrets resolution
- Plugin tools must not leak secret values into agent context when sealed mode
  is enabled

---

### Phase 2: Documentation + Docker Patterns
*Ships alongside or immediately after Phase 1.*

**Objective:** Produce the authoritative guide for running Phoenix with
OpenClaw, covering both resolution paths, Docker deployment, and the
concept mapping.

**Scope:**
- OpenClaw → Phoenix concept mapping (from this plan)
- Two-path architecture explanation (exec for Tier 0/1, plugin for Tier 1/2)
- Plugin installation and configuration guide
- Exec provider setup guide (corrected to actual stdin JSON protocol)
- Recommended namespace and role structure with copy-pasteable examples
- Docker Compose reference config:
  - Phoenix sidecar with OpenClaw gateway
  - Bearer token variant (simple)
  - mTLS variant (secure)
  - Gateway authentication to Phoenix (mount token/cert, set env vars)
- Step-up approval walkthrough (how the plugin surfaces approval requests)
- Anti-patterns section (entrypoint resolution, shared admin tokens, etc.)
- Docker lifecycle: document that the plugin path (API calls) avoids the
  `phoenix exec` restart problem entirely; for exec provider path, document
  systemd wrapper pattern

**Out of scope:**
- Kubernetes deployment
- Multi-instance federation
- Code changes to Phoenix (Phase 1 handles all code)

**Deliverables:**
- `docs/openclaw-guide.md` — comprehensive integration guide
- Updated `docs/integrations.md` — corrected exec examples, link to guide,
  remove duplicated content
- `examples/openclaw-docker/` — working Docker Compose example with README
- `examples/openclaw-plugin/` — plugin config example with README

**Acceptance criteria:**
- A new OpenClaw operator can follow the guide from zero to working integration
- Guide covers both exec and plugin paths with clear guidance on when to use each
- Docker example boots and resolves secrets successfully
- All code examples are tested and correct (no more wrong exec protocol docs)

**Go/no-go:**
- Go: guide reviewed, all examples tested against real Phoenix + OpenClaw
- No-go: if plugin API changed during Phase 1 in ways that invalidate the
  guide (update guide before shipping)

**Regression concerns:**
- Existing `docs/integrations.md` content must not be lost
- Corrected exec protocol docs must not break anyone relying on the old
  (incorrect) examples — add migration note if needed

---

### Phase 3: Subagent Isolation + Step-Up Approval
*Depends on v1 session identity being complete.*

**Objective:** Enable per-subagent secret scoping and human approval for
privileged access through the plugin.

**Scope:**

Subagent isolation via plugin:
- Plugin detects caller context (agent ID, subagent ID, session key) from
  OpenClaw's tool invocation metadata
- Plugin maps caller identity to a Phoenix role
- Role determines which namespaces the caller can access
- Orchestrator calling `phoenix_resolve` gets `openclaw-orchestrator` scope
- Subagent calling `phoenix_resolve` gets `openclaw-agent` scope for its
  own namespace only
- Configuration: mapping from OpenClaw agent IDs to Phoenix roles in
  plugin config

Step-up approval:
- When plugin tool hits a Tier 2 secret and Phoenix returns `APPROVAL_REQUIRED`,
  plugin returns structured response to the agent:
  - What secret was requested
  - Why approval is needed (role requires step-up)
  - How to approve (`phoenix approve <id>` from terminal or dashboard)
  - TTL before the approval request expires
- Agent can explain the situation to the human in conversation
- After human approves, agent retries the tool call and succeeds

Audit correlation:
- Plugin includes OpenClaw agent ID and session key in Phoenix API requests
- Phoenix audit log shows which OpenClaw agent accessed which secret
- Parent/child session linkage in audit entries

**Out of scope:**
- Automatic subagent detection (requires OpenClaw to expose spawn metadata
  in tool call context — verify this is available)
- Phoenix enforcing OpenClaw's subagent hierarchy (Phoenix scopes by role,
  not by OpenClaw's parent/child tree)
- Attestation levels beyond L3

**Deliverables:**
- Updated plugin with caller-context-aware role mapping
- Plugin config schema extended: `agentRoles` mapping
- Step-up approval flow in plugin tools
- Updated `docs/openclaw-guide.md` with subagent isolation section
- Example: orchestrator + 2 subagents with different secret scopes
- Tests for isolation boundaries and step-up flow

**Acceptance criteria:**
- Subagent can only resolve secrets in its scoped namespace
- Orchestrator cannot use a subagent's narrower scope to bypass its own limits
- Step-up approval flow works end-to-end: agent requests → Phoenix holds →
  human approves → agent retries → success
- Audit trail clearly shows which OpenClaw agent accessed which secret

**Go/no-go:**
- Go: v1 session identity is merged; OpenClaw tool invocation context includes
  caller identity (agent ID / session key) — verify this before building
- No-go: if OpenClaw doesn't expose caller identity in tool context (would
  need upstream contribution or a different approach)

**Regression concerns:**
- Plugin must remain functional without subagent isolation config (backward
  compatible — falls back to single-role mode)
- Step-up flow must handle timeout/expiry gracefully (agent gets clear message,
  not a hang)
- Must not create token amplification (subagent can't mint child sessions
  without limit)

---

### Phase 4: Operational Tooling + Polish
*Quality-of-life. Build when there's real usage.*

**Objective:** Make day-2 operations smooth for Phoenix+OpenClaw deployments.

**Scope:**
- `openclaw phoenix status` command (via plugin's `registerCli` / plugin CLI registrar):
  - Phoenix server connectivity and version
  - Active sessions (gateway, agents)
  - Recent access summary
  - Cert expiry warnings
  - Policy violations in last 24h
- Phoenix health check endpoint for OpenClaw monitoring:
  - `GET /v1/health/openclaw` — server up, test resolution works
- Dashboard integration (if v1 dashboard exists):
  - OpenClaw-specific view: agent tree, access patterns
  - Filter audit log by `openclaw/*` namespace
- Plugin auto-update check (compare installed vs latest version)

**Out of scope:**
- OpenClaw config management from Phoenix side
- Multi-instance coordination
- Secret rotation engine (separate post-launch track)

**Deliverables:**
- `openclaw phoenix status` command in plugin
- Health check endpoint in Phoenix server
- Dashboard view (if applicable)
- Operational runbook for common scenarios

**Acceptance criteria:**
- Operator can diagnose "why can't my agent resolve secrets" in under 2
  minutes using plugin diagnostics alone
- Health check returns actionable error messages

**Go/no-go:**
- Go: real users running Phoenix+OpenClaw in production
- No-go: nobody is using it yet (don't build for hypothetical demand)

**Regression concerns:**
- Health check must not leak secret values or metadata
- Status command must handle missing/unreachable server gracefully

---

## Explicitly Deferred

1. **npm publishing of plugin** — use local install path (`openclaw plugins
   install ./path`) until the plugin is proven. Publish when there's external
   demand.

2. **Native secrets provider registration** — OpenClaw's secrets provider
   system is hardcoded to env/file/exec. Registering a fourth provider type
   would require upstream OpenClaw changes. The plugin tool path is sufficient
   and arguably better (runtime resolution with per-request ACLs vs startup
   bulk resolution).

3. **Kubernetes deployment patterns** — separate concern. Tackle after Docker
   patterns are proven.

4. **Attestation levels L4-L8** — tool identity, process attestation, time
   windows, nonces. Would enable "only the email skill can access SMTP
   password" but is v1+ scope.

5. **OpenClaw skill marketplace trust** — Phoenix attesting skill identity
   before granting access. Requires OpenClaw to expose skill metadata.
   Speculative.

6. **Multi-instance Phoenix federation** — dev/staging/prod split.
   Post-v1 roadmap.

7. **Secret rotation with gateway reload** — requires Phoenix rotation
   engine (post-launch) and OpenClaw's `secrets.reload` RPC integration.

8. **`phoenix setup openclaw` CLI command** — premature before the plugin
   exists. If setup automation is needed, it belongs in the plugin itself
   (e.g., `openclaw phoenix setup`), not in a standalone Phoenix CLI command
   that duplicates work the plugin should own.

---

## Order of Attack

```
Phase 1: Plugin + Exec Protocol ───────────── START HERE
    │                                          primary deliverable
    │
    ├──► Phase 2: Documentation ───────────── parallel or immediately after
    │                                          docs ship with the plugin
    │
    ▼
Phase 3: Subagent Isolation + Step-Up ─────── requires v1 session identity
    │                                          can plan in parallel with 1+2
    ▼
Phase 4: Operational Tooling ──────────────── build on demand
```

**Phase 1 is the whole point.** The plugin is the integration. Everything
else supports it. This phase produces two artifacts: the OpenClaw plugin
(TypeScript) and the exec protocol handler (Go). Both can be vibe-coded in
a weekend.

**Phase 2 runs alongside Phase 1.** Docs are written as the plugin takes
shape. They ship together.

**Phase 3 is the depth play.** Per-subagent isolation and step-up approval
make Phoenix genuinely valuable for multi-agent OpenClaw deployments. This
is gated on v1 session identity but can be planned now.

**Phase 4 is when real users exist.** Don't build operational tooling for
hypothetical users.

---

## Key Technical Decisions to Make During Phase 1

1. **Plugin language: TypeScript.** OpenClaw plugins are JS/TS. The plugin
   calls Phoenix's REST API directly — no dependency on the Go binary for
   runtime resolution (exec path is a separate, simpler fallback).

2. **Where does the plugin live?** Options:
   - In the Phoenix repo (`plugins/openclaw-phoenix/`) — keeps it versioned
     with Phoenix
   - Separate repo — more natural for npm publishing later
   - Recommendation: **Phoenix repo** for now, extract later if needed

3. **Auth in the plugin.** Plugin config provides `server` + `token` (or cert
   paths). Plugin creates an HTTP client at registration time. Tokens are
   read from config, not env vars, unless `passEnv` is configured.

4. **Sealed mode in plugin tools.** When `sealMode: true`, plugin tools
   return `PHOENIX_SEALED:` tokens. The agent gets opaque references it can
   pass to other tools but can't read. This is the same pattern as the MCP
   sealed mode.

5. **Exec protocol flag name.** `phoenix resolve --openclaw-exec` or
   `phoenix resolve --stdin-json` or `phoenix resolve --provider-protocol`?
   The latter two are more generic (other orchestrators could use the same
   protocol). Recommendation: `--stdin-json` — it's what it does, not who
   it's for.

---

*This plan is a living document. Update it as phases complete and as
OpenClaw's architecture evolves.*
