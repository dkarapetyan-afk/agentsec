# Credential and protected-path safety

Store credentials and device-specific roots in agentsec. Code consumes selected
injected environment variables and uses relative defaults, never machine-specific
usernames, drive letters, mount points, or absolute paths.
Standard configuration references such as `$HOME` and `CODEX_HOME` are portable.

Use stdin/hidden input or the connected MCP secret setter, not positional values.
Prefer masked metadata over raw retrieval and `run --clean-env --only KEY1,KEY2`
over injecting everything. Do not print injected DATA_DIR or other protected paths.
Samples/templates must contain placeholders only.

Give agents a short-lived token with only the required operation, namespace, and
exact key names. Client tokens default to non-admin read/write/run; select narrower
permissions explicitly. Admin is intentionally unscoped and should not be supplied
to child workloads. Do not escalate a denied token without authorization.

Default output redaction matches exact injected byte strings, across stdout/stderr
chunks. It is not protection against base64, hashes, partial values, network access,
or files written by the child. Run permission exposes injected credentials to that
process; it does not make execution safe. Use OS isolation for untrusted workloads.

The audit API and file contain operation metadata only. Names, descriptions, and
tags are metadata too: never place secret values there. Restrict access to audit
records and token/configuration files; audit is not tamper-proof against the owner.

Scan before finalizing or committing, in every namespace used. Scan checks stored
values of at least six characters and skips common build/vendor/encrypted files.
It cannot identify every unknown credential or guarantee a clean workspace.

After updating binaries, restart the daemon, reconnect long-lived MCP adapters,
run doctor, and reload agent skills. Live master-token rotation is different: it
does not require a daemon restart, but clients using the old master must reconnect.
