# agentsec 0.3 architecture

CLI and stdio MCP dispatch via `ClientBackend`: either `DaemonClient` (calling the
authenticated REST daemon over loopback/network) or `DirectClient` (operating directly
on encrypted namespace files inside `vault.enc/`, with a separate file lock per
namespace and no vault-wide lock). Namespace names map to BLAKE2s-256 filenames;
the namespace identity is authenticated inside each encrypted file. Lock acquisition
uses nonblocking OS calls with async retry and a five-second deadline. HTTP MCP forwards requests through that same
implementation using the original caller credential. Operations are gated by permission,
namespace, and exact key scope.

- Read: list metadata, retrieve raw values, export permitted values.
- Write: set/delete/renew permitted secrets; namespace deletion is unavailable to
  key-restricted tokens.
- Run: hand off permitted selected credentials for child environment injection.
- Admin: manage named tokens, live master rotation, and audit inspection. Admin
  tokens must be unscoped. Legacy tokens migrate to read/write/run, not admin.

The persistent vault uses ChaCha20-Poly1305 with a generated random 256-bit key;
an Argon2id derivation helper also exists. Protected secret wrappers zeroize on drop;
other serialized/copy buffers and child environments do not provide a whole-process
memory-scrubbing guarantee. Auth/client-token files are locally protected, not encrypted.

The daemon defaults to loopback; host configuration can override it. Local health
and MCP discovery GET requests may be unauthenticated. All secret operations,
JSON-RPC POST requests, and forwarded health/discovery requests require authentication.
Use TLS and carefully scoped client tokens for remote connections.

Expired values/tokens are rejected on access and proactively removed about every
second. Renewal permits active temporary leases only, at most 24 hours from now,
without shortening. Live rotation atomically replaces the master token file and
the in-memory auth credential; existing named tokens are unchanged.

Audit records only timestamp/client/operation/namespace/key/outcome, with no
credential values, bearer tokens, arguments, or command strings. Persistent mode
appends audit.jsonl with Unix mode 0600; API retains the newest 1000 events.
Ephemeral secret/audit data is memory-only, but configuration/auth files still exist.

Child execution runs in the caller process for CLI/stdio, and in the daemon for
HTTP MCP. Selected environment injection creates no .env file. Exact-value output
redaction operates on bytes across chunks; MCP captures are capped at 1 MiB per
stream. Ambient administration credentials are removed, but this is not an OS sandbox.

Vault filesystem operations are async; encryption uses short CPU jobs. Ephemeral
namespace locks and the sharded namespace index use async synchronization. Audit
buffers are sharded, with no audit mutex held across disk writes. Child waits and
stdout/stderr use async process/pipe I/O. Only process startup uses a short worker
job, and no storage lock or worker is retained while a child runs. MCP stdio has
separate command and operation admission budgets, so long commands cannot exhaust
ordinary operation capacity. Responses correlate by ID and may finish out of order.

`agentsec migrate` is an offline, resumable conversion from the pre-0.3 format. It
preserves the encrypted original as `vault.legacy.enc`, imports namespaces separately,
and marks completion only after import. Older clients must be stopped during conversion
and restarted using the upgraded binary. Partial migrations reject ordinary access
until resumed. Migration never renews credentials or changes their metadata.
