---
name: agentsec
description: >-
  Store, retrieve, inject, and audit secrets with agentsec (daemon or direct daemonless vault)
  and its MCP tools instead of .env files. Use when handling credentials, API keys, tokens,
  namespaces, secret rotation, leak scans, or a command that needs injected environment variables,
  and when the user runs /agentsec.
metadata:
  short-description: Manage secrets with agentsec (daemon or daemonless)
---

# agentsec

For agentsec 0.3.0 and later. Keep credentials and sensitive device paths in agentsec,
not workspace files, command arguments, logs, commits, chat, or dashboard records.
Templates contain placeholders only. Report key names, namespaces, and masked previews.

## Daemonless mode and daemon supervision

`agentsec` operates in two modes with seamless auto-fallback:
- **Automatic Fallback (Default)**: If the background daemon process is offline or unresponsive,
  CLI subcommands (`get`, `set`, `list`, `run`, `doctor`, `token`, `mcp`, etc.) automatically
  operate directly on encrypted namespace files inside `vault.enc/`. Each namespace has
  its own lock; waiting for one never occupies an executor or storage worker. A running daemon is NOT required for local operations or CLI/MCP execution.
- **Explicit Daemonless Mode**: Pass `--daemonless` (`-D`) or set `AGENTSEC_DAEMONLESS=1` in your
  environment to skip daemon discovery and access the local vault directly.
- **Strict Daemon Requirement**: Pass `--require-daemon` if an active daemon is mandatory (e.g.
  when using ephemeral RAM-only vaults or connecting to a custom/remote daemon URL).

Run `agentsec status` before operations; capture its output if it includes protected paths.
In direct mode, status reports `DAEMONLESS (Direct Local Vault)`.
If a background daemon is desired (e.g. for ephemeral RAM-only vaults with `daemon --ephemeral` or
shared listening socket), start `agentsec daemon` in the background and wait until online.
Ephemeral secret values and audit events are RAM-only; configuration and auth files still exist.

Use `agentsec doctor [--require KEY1,KEY2] [--json]` for authentication, version,
namespace, required-key metadata, and MCP discovery checks. Exit 1 means a failed
check. Upgrade both CLI and daemon to the same version and restart after upgrading.
Doctor tests read permission; a deliberately run-only token will fail namespace inspection.

Prefer connected agentsec MCP tools. Discover their actual schema before calling.
Otherwise resolve `agentsec` in PATH, then `/usr/local/bin/agentsec`, then
`$HOME/.cargo/bin/agentsec`. Built-in MCP stdio (`agentsec mcp` or `agentsec -D mcp`)
works in both daemon and daemonless modes. Do not start duplicate MCP servers.

## Concurrency and upgrades

There is no vault-wide lock. Namespace file locks use nonblocking acquisition and async
retry. Child process waits and both output streams are async. Credentials are acquired
and all vault locks released before process startup; a running child holds no storage
worker. MCP stdio reserves separate capacity for 32 commands and 64 other operations;
excess requests receive a busy error rather than blocking the reader.

For a pre-0.3 vault, stop older agentsec processes and run `agentsec migrate` once.
It converts the single encrypted file into an encrypted namespace directory, preserves
`vault.legacy.enc`, and resumes interrupted imports. Older binaries cannot open the new
format. Restart the daemon and MCP adapters with the upgraded binary and run doctor.

## Namespace and permissions

Omit namespace for ordinary CLI/stdio work: the client detects `repo:<git-root-name>`,
then `ws:<directory>`, then `default`. Honor the namespace supplied by the user.
HTTP MCP infers a token's single restricted namespace; otherwise its default is the
daemon workspace, not the remote caller's workspace. Supply an explicit namespace
when those differ. CLI namespace flag: `-n` / `--namespace`.

Client tokens have `read`, `write`, `run`, and/or `admin` permissions plus optional
exact namespace and key allowlists. Defaults, including migrated legacy tokens:
read/write/run, **not admin**. Only master or unscoped admin credentials can create,
list, revoke, renew client tokens, rotate the master, or read audit events.
Read permits raw retrieval/export; run permits credential injection. Run is not a
sandbox: the receiving process can use or exfiltrate its injected credentials.

A denied valid token gets HTTP 403; a missing, invalid, revoked, or expired token gets
401. MCP tool failures use `result.isError`. Do not retry with broader credentials or
remove restrictions without the user's authorization.

## Store, inspect, and execute

- Store with MCP `set_secret(key, value, namespace?, description?, ttl_seconds?)`,
  or `agentsec set KEY` using stdin/hidden input. Never pass a real value as an argument.
- Inspect with `list_secrets` / `agentsec list` or masked `agentsec get KEY`.
  MCP `get_secret` returns a raw value; avoid it when injection can do the job.
  Consume raw output inside its destination process, never in a tool transcript.
- Prefer `agentsec run --clean-env --only KEY1,KEY2 -- COMMAND...`.
  Only selected active keys are injected; forbidden/missing requested keys fail closed.
  Without `--only`, all permitted namespace keys are injected.
- MCP `run_command_with_secrets`: prefer `argv: ["program", "arg"]`, with
  `only: ["KEY1"]` and optional namespace. Alternatively use a shell `command` string;
  never supply both. `clean_env` defaults true in MCP, false in CLI.
- Clean mode retains PATH, USER, HOME plus selected secrets. Inherited daemon auth
  variables are removed in either mode. Ambient unrelated credentials can still
  remain without clean mode. Child scripts read injected environment variables.
- Stdout/stderr redact exact injected values, including across chunks. MCP captures
  at most 1 MiB per stream. Redaction does not cover encoded, transformed, partial,
  file, or network output. Never disable it with `--no-redact` for agent transcripts.

## Leases and audit

Creation TTL: 1–31536000 seconds. Secret/token metadata exposes expiry; CLI inspection
shows remaining TTL. `agentsec renew KEY --ttl SECONDS` / MCP `renew_secret` requires
write; `agentsec token renew NAME --ttl SECONDS` requires admin.
Renewal sets expiry relative to now, 1–86400 seconds, and cannot shorten a lease,
renew permanent credentials, or revive expired ones. Expired entries are checked at
access and purged approximately every second. Renew only when the user's task warrants it.

`agentsec token --rotate` updates the running daemon immediately: the old master
stops working, named client tokens remain valid. Capture the returned token privately.
Externally supplied master tokens must be rotated by their issuer.
Token creation also returns a raw token once; token listings contain metadata only.

`agentsec audit --limit 50 --json` / MCP `get_audit_events` returns recent access
metadata (client name, operation, namespace, key, timestamp, outcome), never command
text, arguments, values, or bearer tokens. Avoid secrets in names/descriptions/tags.
Persistent daemon audit is `audit.jsonl` in its configuration directory; restrict access.

## Scan and maintain integrations

Before finalizing or committing changes, run `agentsec scan` in the workspace and
`agentsec scan -n NAMESPACE` for every additional task namespace. Resolve leaks and
report scan/daemon failures accurately. Scanning matches stored values of at least
six characters and is not a complete credential detector.

`agentsec setup --agent all` updates Codex, Grok, Gemini CLI, Antigravity, and shared
discovery skill bundles. Use `--dry-run` to preview. Changed installed files are
backed up as `*.previous`; unrelated custom files and existing MCP config are preserved.
Reload skills afterward. MCP stdio config: command `agentsec`, args `["mcp"]`.

Read [CLI details](references/cli_reference.md) for flags, token administration, and setup;
[MCP schemas](references/mcp_tools.md) for tool arguments;
[safety boundaries](references/best_practices.md) for credential/path handling;
[architecture](references/architecture.md) for storage and audit lifecycle.
