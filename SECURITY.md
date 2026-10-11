# Security Policy & Threat Model

The **agentsec** project prioritizes the confidentiality, integrity, and safety of developer and AI agent credentials. Because `agentsec` manages sensitive keys and in-memory environment injection, we hold the codebase to high security standards.

---

## 1. Reporting a Vulnerability

If you discover a security vulnerability in `agentsec`, **please do not open a public GitHub issue**. Instead, follow responsible disclosure:

1. **Email Disclosure**: Send a detailed advisory to `security@agentsec.dev` (or the repository maintainers via GitHub Private Vulnerability Reporting).
2. **Details to Include**:
   - Component affected (daemon, CLI, REST API, stdio MCP, runner/redaction engine, crypto vault).
   - Steps to reproduce or proof-of-concept (PoC).
   - Potential impact and severity assessment.
   - Any suggested mitigations or patches.
3. **Response Timeline**:
   - Maintainers will acknowledge receipt within **48 hours**.
   - An initial triage assessment and proposed remediation plan will be provided within **5 business days**.
   - Once a fix is verified, a patch release and security advisory will be coordinated.

---

## 2. Threat Model & Boundaries

Understanding the security posture of `agentsec` requires recognizing both its guarantees and operating system boundaries.

### ✅ What `agentsec` Protects Against (In Scope)

1. **Accidental Repository Leaks (`.env` Elimination)**:
   - Eliminates plaintext `.env` files in project directories, preventing accidental inclusion in `git commit`, `git diff`, and public pushes.
2. **Zero-File In-Memory Process Injection**:
   - Injects credentials directly into child process RAM via environment variables during `agentsec run`.
   - Never writes credentials to temporary disks, named pipes, or configuration files in the workspace.
3. **Log & Terminal Disclosure**:
   - Masked previews by default (e.g., `sk-a...****...2345`) for listings and inspections to prevent terminal scrollback capture.
   - Dynamic stdout/stderr stream redaction for injected subprocesses, redacting secret byte sequences even when split across TCP or I/O chunk boundaries.
4. **Least-Privilege Agent Access**:
   - Scoped multi-client tokens restrict AI agents to specific namespaces and key allowlists.
   - Client tokens cannot escalate privileges or administer other tokens.
5. **At-Rest Protection**:
   - Persistent vault storage is encrypted with ChaCha20-Poly1305 AEAD using a randomly generated 256-bit master key.
   - Secrets implement `Zeroize` on drop to wipe plaintext buffers when memory is deallocated.
   - Ephemeral mode (`agentsec daemon --ephemeral`) keeps all vault data strictly in RAM.

### ⚠️ What `agentsec` Does Not Protect Against (Out of Scope / OS Limitations)

1. **Host-Level Root/Administrator Compromise**:
   - If an attacker possesses `root` access or administrator privileges on the host system, they can inspect `/proc/<PID>/environ`, dump process RAM, or read socket memory regardless of user-space protections.
2. **Malicious Parent or Injected Process with Direct Memory Access**:
   - Processes with active `ptrace` capabilities or debugger attachments targeting the child process can inspect child memory.
3. **Host Kernel Compromise or Hardware Keyloggers**:
   - Operating system kernel vulnerabilities, kernel-level keyloggers, or hardware snooping fall outside the user-space daemon threat model.

---

## 3. Supported Versions

| Version | Supported |
| :--- | :---: |
| `0.2.x` | ✅ Yes |
| `< 0.2.0` | ❌ No |

Security updates are backported to the latest minor version release branch.
