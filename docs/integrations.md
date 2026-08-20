# Integrations

## OpenClaw

OpenClaw + Phoenix has two complementary paths. Use the Phoenix CLI exec provider for OpenClaw built-in SecretRefs that must resolve during bootstrap/config load, and use this `openclaw-phoenix` plugin package for agent runtime tools and diagnostics.

Start here:
- [OpenClaw + Phoenix Guide](./openclaw-guide.md)
- [OpenClaw + Phoenix Release Coordination Checklist](./release-coordination.md)

Transport note: Phoenix is LAN-scoped by design (internet/WAN exposure is unsupported). Plaintext over loopback is the supported default; enable TLS (`https://` plus `PHOENIX_CA_CERT`) whenever gateway-to-Phoenix traffic crosses a wire — a LAN, including Docker bridge networks, is not a trust boundary. The plugin warns loudly on non-loopback plain `http://` and never refuses; see [Transport security](./openclaw-guide.md#transport-security).

### Plugin package path — runtime tools

Use the plugin package when you want:
- runtime resolution through `phoenix_resolve`
- visible-path discovery through `phoenix_list`
- health/connectivity diagnostics through `phoenix_status`
- Phoenix ACL/attestation on every runtime request
- sealed responses that keep values out of model-visible tool output
- plugin-side per-agent identity selection from trusted OpenClaw runtime context
- warning-only startup diagnostics that do not kill the OpenClaw gateway

Install the approved package release with:

```bash
openclaw plugins install openclaw-phoenix
```

For local source development only, link this checkout instead:

```bash
openclaw plugins install -l ./path/to/openclaw-phoenix
```

Conservative rollout: expose `phoenix_status` first. Keep `phoenix_resolve` and `phoenix_list` denied until per-agent token files, per-agent seal key files, Phoenix-side public seal-key registration, tool allowlists, and the audit-only header contract in the [release coordination checklist](./release-coordination.md) are validated.

### Exec provider path — bootstrap/config SecretRefs

OpenClaw's exec provider uses a stdin/stdout JSON protocol. It does **not** call `phoenix resolve <ref>` one argument at a time.

Protocol reminder:

```json
{
  "protocolVersion": 1,
  "provider": "phoenix",
  "ids": ["namespace/secret"]
}
```

Expected response:

```json
{
  "protocolVersion": 1,
  "values": {
    "namespace/secret": "value"
  }
}
```

This repo ships the plugin package path. Its startup preflight only warns/logs; it is not the fail-fast mechanism for config secrets. For built-in OpenClaw SecretRefs, use Phoenix CLI v0.14.0+ with `phoenix resolve --stdin-json` (aliases: `phoenix openclaw-exec-provider`, `phoenix secret-provider openclaw`) and let OpenClaw's built-in secrets system fail startup/reload when active refs cannot resolve.

### SecretRef vs plugin-tool refs

Do not confuse:
- OpenClaw built-in SecretRefs: `{ source, provider, id }`
- plugin tool refs: `phoenix://namespace/name`

This repo implements the plugin-tool path only. Installing it does not make raw `phoenix://...` strings in startup config fields resolve through Phoenix; configure the exec provider for that path.
