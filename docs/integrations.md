# Integrations

## OpenClaw

The primary OpenClaw integration is the local plugin in this repo.

Start here:
- [OpenClaw + Phoenix Guide](./openclaw-guide.md)

### Recommended path

Use the plugin path when you want:
- runtime resolution
- Phoenix ACL/attestation on every request
- sealed responses
- better future compatibility with per-agent or per-subagent controls

### Exec provider note

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

At the moment, this repo ships the plugin path. Phoenix-side exec protocol support is a separate change.


### SecretRef vs plugin-tool refs

Do not confuse:
- OpenClaw built-in SecretRefs: `{ source, provider, id }`
- plugin tool refs: `phoenix://namespace/name`

This repo currently implements the plugin-tool path only.
