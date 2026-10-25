# agentsec 0.2 CLI reference

Global: `-c/--config-dir`, `--host`, `-p/--port`, `--url`, `--token`, `-D/--daemonless`, `--require-daemon`.
Environment overrides: AGENTSEC_CONFIG_DIR, AGENTSEC_HOST, AGENTSEC_PORT,
AGENTSEC_URL (also AGENTSEC_SERVER_URL), AGENTSEC_TOKEN, AGENTSEC_DAEMONLESS.
Use injected AGENTSEC_TOKEN rather than putting bearer values in arguments.

| Command | Options / behavior |
| --- | --- |
| `daemon` | `--ephemeral` keeps secret values and audit events in RAM; configuration/auth files still exist |
| `status` | Reports ONLINE (daemon) or DAEMONLESS (direct vault), version, storage metrics |
| `set KEY` | Stdin/hidden input; `-n`, `-d`, repeatable `-t`, `--ttl 1..31536000` |
| `get KEY` | Masked inspection; `-n`; `--raw` is for privately captured process consumption only |
| `list` | Masked keys; `-n`; `--all-namespaces` filters to allowed namespaces |
| `delete KEY` | `-n`; `--all-namespace` only for authorized whole-namespace removal |
| `run` | `-n`, `--only KEY1,KEY2`, `--clean-env`, then `-- COMMAND...` |
| `renew KEY` | `-n`, required `--ttl 1..86400`; active temporary leases only |
| `scan [DIR]` | `-n`; exit 1 on leaks; values shorter than six characters are not checked |
| `audit` | Admin only; `--limit` (max 1000), `--json`; recent metadata newest first |
| `doctor` | `-n`, `--require KEY1,KEY2`, `--json`; exit 1 if any check fails |
| `setup` | `--agent all\|codex\|grok\|gemini`, `--dry-run`; skill bundles only, not MCP configuration |
| `mcp` | Stdio adapter; operates in both daemon and daemonless direct modes |

## Tokens (owner/admin only)

```bash
agentsec token create deploy -n repo:example --permission run --key API_KEY --ttl 900
agentsec token create reader -n repo:example --permission read --key API_KEY,DATA_DIR
agentsec token list
agentsec token renew deploy --ttl 1800
agentsec token revoke deploy
```

`--permission` and `--key` accept comma-separated values or repeated flags; `-n`
is repeatable. Omitted permissions mean read/write/run. Admin implies all operations
and is rejected alongside namespace/key restrictions. Legacy `token --create`,
`--list`, `--revoke` remain supported with the same restrictions.
Creation returns raw token once. Capture it within a process and store via agentsec;
do not send it to chat or a workspace file. Listings never return raw tokens.

`agentsec token` prints the raw locally configured master token.
`agentsec token --rotate` rotates the live daemon and saves its new token atomically,
without restart. Long-lived clients with the old token must reconnect; named tokens
continue working. Externally supplied master tokens are not rotated by this command.

## Run safety

```bash
agentsec run --clean-env --only API_KEY,DATA_DIR -- python app.py
agentsec run -n repo:example --only API_KEY -- npm test
```

Selection intersects token scope. Explicitly requesting a missing/expired or forbidden
key fails before spawning. Without `--only`, all permitted keys are injected.
CLI retains ambient environment by default; clean mode keeps PATH, USER, HOME.
Daemon bearer environment variables are stripped before selected secrets are added.
Exact injected values are redacted from both output streams; explicit `--no-redact`
exists for trusted interactive workflows only, never automatic agent logging.

## Install locations

- Codex: `${CODEX_HOME:-$HOME/.codex}/skills/agentsec`.
- Grok: `${GROK_HOME:-$HOME/.grok}/skills/agentsec`.
- Gemini CLI: `$HOME/.gemini/skills/agentsec`.
- Antigravity: `${GEMINI_CONFIG_DIR:-$HOME/.gemini/config}/skills/agentsec`.
- Shared discovery: `$HOME/.agents/skills/agentsec`, respecting existing symlinks.

Setup overwrites only bundled files, backs up changes as `*.previous`, and preserves
unrelated custom resources. Review custom instructions in backups before removing them.
