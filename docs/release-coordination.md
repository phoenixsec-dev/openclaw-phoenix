# OpenClaw + Phoenix Release Coordination Checklist

This checklist coordinates release gating for the `openclaw-phoenix` plugin and the Phoenix server. It is audit/planning material only: do not inspect or paste real token files, private seal keys, or secret values while filling it out.

## Phoenix server audit-only header contract

Before enabling broad runtime secret tools, verify the Phoenix server change that consumes OpenClaw metadata:

- [ ] Phoenix server PR/commit that handles OpenClaw metadata is merged or otherwise approved for the target environment.
- [ ] Code review confirms every `X-OpenClaw-*` value and `X-Phoenix-Tool` are recorded only as request/audit metadata.
- [ ] Code review confirms Phoenix auth identity, ACL, attestation, sessions, and role selection are never derived from raw `X-OpenClaw-*` headers.
- [ ] Tests or a manual negative check confirm spoofed OpenClaw headers cannot elevate a low-scope token/session/mTLS identity.
- [ ] Audit output is sanitized according to Phoenix logging policy and does not include Phoenix bearer tokens, private keys, plaintext secrets, or private seal-key material.

The plugin sends these OpenClaw metadata headers when the OpenClaw runtime context provides the matching fields:

| Header | Plugin source | Contract |
| --- | --- | --- |
| `X-OpenClaw-Agent` | trusted `ctx.agentId` | audit/correlation hint only |
| `X-OpenClaw-Session-Key` | `ctx.sessionKey` | audit/correlation hint only |
| `X-OpenClaw-Session-Id` | `ctx.sessionId` | audit/correlation hint only |
| `X-OpenClaw-Channel` | `ctx.messageChannel` | audit/correlation hint only |
| `X-OpenClaw-Requester-Sender` | `ctx.requesterSenderId` | audit/correlation hint only |
| `X-OpenClaw-Sender-Is-Owner` | `ctx.senderIsOwner === true` | audit/correlation hint only |
| `X-Phoenix-Tool` | plugin operation (`phoenix_status`, `phoenix_resolve`, or `phoenix_list`) | audit/correlation hint only |

These headers must never be treated as authentication or authoritative identity by Phoenix. They are not a substitute for Phoenix token, mTLS, session, ACL, attestation, or sealed-response policy checks.

## Transport posture (coordinated across Phoenix packages)

Phoenix is LAN-scoped by design: internet/WAN exposure is out of scope and unsupported. Loopback plaintext (`http://127.0.0.1:9090`) is the supported default; any Phoenix URL that crosses a wire — including Docker bridge networks — should be `https://` with the Phoenix CA certificate distributed to clients. A LAN is in scope but is not a trust boundary.

All three Phoenix components hold the same deliberately coordinated posture: **warn loudly on non-loopback plaintext, never refuse**. This plugin logs the warning at gateway-startup preflight, includes it in `phoenix_status` `notes`, and reports it in `openclaw phoenix verify` `warnings`; the Hermes Phoenix plugin emits an equivalent warning on its side, and `phoenix-server` gained its own startup warning and a first-class `tls:` config block in Phoenix `v0.17.0`. This plugin's warning is client-side and is emitted against any server version, including older ones that stay silent themselves. The plugin does not hard-fail on plain HTTP because this package is published and hard-failing would break existing deployments with no migration path.

Release coordination checks:

- [ ] Deployments where gateway-to-Phoenix traffic crosses a wire use `https://` with `caCert`/`PHOENIX_CA_CERT` set, or the operator has explicitly accepted the logged cleartext warning for a trusted single-host bridge.
- [ ] No deployment exposes Phoenix beyond the LAN (no public ingress, no WAN reachability); that is unsupported, not merely discouraged.
- [ ] The target `phoenix-server` build emits its own non-loopback plaintext startup warning, so operators get the signal on both ends of the connection.

## Identity and sealed-response boundaries

- The plugin selects Phoenix credential material from the OpenClaw runtime `ctx.agentId` mapping, not from tool arguments or raw HTTP headers.
- Phoenix identity must be enforced by the selected per-agent token file and/or mTLS client certificate, plus any Phoenix-minted session policy.
- In sealed mode, the plugin reads the selected agent's private seal key file locally, derives the public key, and sends that public key as `X-Phoenix-Seal-Key` on `phoenix_resolve` requests.
- The seal key proves the response encryption target and keeps tool output opaque (`PHOENIX_SEALED:*`). It does not make raw `X-OpenClaw-*` headers trustworthy.
- Phoenix-side public seal-key registration must match the selected Phoenix identity before live sealed `phoenix_resolve` is considered validated.

## Per-agent rollout inventory

Status is unknown until an operator validates each item in the target environment. Do not print token values, private keys, plaintext secrets, or public keys in this checklist or accompanying task-tracker notes. If a human intentionally records public-key fingerprints, record fingerprints only.

The agent rows below are placeholders; replace them with your deployment's actual mapped `ctx.agentId` values.

| Agent | Token file exists and mode `0600` | Seal key file exists and mode `0600` | Public seal key registered in Phoenix for matching identity | Phoenix ACL/attestation scopes checked | Live `phoenix_status` works | Live sealed `phoenix_resolve` returns `PHOENIX_SEALED:*` | `phoenix_resolve`/`phoenix_list` allowlist remains gated until validated |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `main` | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| `example-agent` | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| `my-agent` | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |

Validation notes:

- File existence/mode checks should be performed by an authorized operator in the deployment environment; this repository task should not inspect real token or seal-key paths.
- Live `phoenix_status` is the first allowed tool check because it validates connectivity/credential selection without returning secret values.
- Live sealed `phoenix_resolve` validation should use a low-risk test ref and confirm the OpenClaw tool output is an opaque `PHOENIX_SEALED:*` token, not plaintext.
- `phoenix_list` can reveal path inventory, so keep it gated with `phoenix_resolve` until per-agent identity and ACL scope are verified.

## Release gate

Do not enable broad `phoenix_resolve` or `phoenix_list` access until all of the following are true:

1. Phoenix server audit-only handling for the exact `X-OpenClaw-*` headers above is merged/verified in the target Phoenix deployment.
2. Every mapped agent (for example `main`, `example-agent`, `my-agent`) has a unique scoped token file and, when sealed mode is enabled, a unique seal-key file with group/other permissions cleared (`0600` recommended).
3. Every mapped agent's derived public seal key is registered in Phoenix for the matching identity.
4. Phoenix ACL and attestation scopes are checked for each mapped identity.
5. `phoenix_status` succeeds for each mapped identity.
6. A live sealed `phoenix_resolve` test for each mapped identity returns `PHOENIX_SEALED:*` output.
7. OpenClaw tool policy/allowlists have been reviewed so `phoenix_resolve` and `phoenix_list` are exposed only to intended agents.

Until then, keep the runtime rollout conservative: allow `phoenix_status` first, and keep `phoenix_resolve`/`phoenix_list` denied or narrowly gated.
