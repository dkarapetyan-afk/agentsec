# agentsec 0.2 MCP tools

Stdio: `{"command":"agentsec","args":["mcp"]}`.
HTTP JSON-RPC: POST `/mcp` (alias `/v1/mcp`) with bearer authentication.
Both transports enforce the same REST permissions. HTTP tool failures appear as
`result.isError: true`, even when the HTTP response itself is 200.

| Tool | Arguments | Permission / result |
| --- | --- | --- |
| `list_namespaces` | none | read; allowed namespace names |
| `list_secrets` | namespace? | read; metadata array with name, namespace, timestamps, expiry, tags, description, masked_preview |
| `get_secret` | key, namespace? | read; raw value (avoid for agent execution) |
| `set_secret` | key, value, namespace?, description?, ttl_seconds? | write; metadata, no raw value; tags are not accepted |
| `delete_secret` | key, namespace? | write; deleted status |
| `renew_secret` | key, ttl_seconds, namespace? | write; active lease metadata; TTL 1..86400 from now |
| `run_command_with_secrets` | argv OR command, namespace?, only?, clean_env? | run; JSON exit_code/stdout/stderr with exact-value redaction |
| `doctor` | namespace?, required_keys? | authenticated diagnostics; read needed for key inspection |
| `get_audit_events` | limit? | admin; recent metadata only, limit <=1000 |

Prefer structured arguments to shell strings:

```json
{
  "argv": ["python", "app.py"],
  "only": ["API_KEY", "DATA_DIR"],
  "clean_env": true,
  "namespace": "repo:example"
}
```

`argv` is a nonempty string array; `command` is a legacy shell string.
Do not supply both. `only` is a nonempty string array, optional for compatibility;
when omitted all permitted keys are injected. `clean_env` defaults true.
Captured stdout and stderr are each bounded to 1 MiB, with a truncation marker.
No command text or argv enters audit records.

Stdio namespace omission resolves the MCP process workspace. HTTP omission infers
a single-namespace client token; otherwise it resolves the daemon workspace.
Supply an explicit namespace when a remote caller needs a different workspace.
Tool discovery lists supported tools, not a promise that the caller has every permission.

The run credential handoff is a privilege, not sandboxing or non-retrievability.
A process using an injected token can read it and transmit it. Exact-value output
redaction does not protect transformed values, disk writes, or network traffic.
