# Contributing to agentsec

Thank you for your interest in contributing to **agentsec**! We welcome contributions, bug fixes, enhancements, documentation improvements, and feedback.

---

## 1. Development Setup

### Prerequisites
- **Rust toolchain**: 1.78.0 or newer (stable).
- **Cargo**: Standard package manager included with Rust.
- **Git**

### Clone and Build
```bash
git clone https://github.com/dkarapetyan-afk/agentsec.git
cd agentsec

# Build in debug mode
cargo build

# Run test suite
cargo test --all-targets

# Run linter and formatter check
cargo clippy --all-targets --all-features -D warnings
cargo fmt -- --check
```

---

## 2. Development Guidelines

1. **Keep Secrets Out of the Repository**:
   - Never commit actual API keys, private keys, or passwords.
   - Use mock values (e.g. `dummy-temporary-value`, `sk_test_...`) in test fixtures.
   - Run `agentsec scan` or local secret linters before submitting PRs.
2. **Preserve Security Invariants**:
   - Secret buffers must implement `Zeroize` on drop where practical.
   - All client-facing lists must mask secret previews.
   - Streaming child runner output must preserve redaction logic.
   - Client tokens must not have permission to manage other client tokens or escalate privileges.
3. **Format & Lint**:
   - All code must pass `cargo fmt -- --check` and `cargo clippy --all-targets --all-features -D warnings`.
4. **Documentation**:
   - Keep docstrings and comments accurate and up-to-date.
   - If adding a new CLI flag or REST/MCP endpoint, update [`README.md`](README.md) and relevant test files.

---

## 3. Pull Request Workflow

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes and add corresponding unit and integration tests.
3. Run the full validation suite:
   ```bash
   cargo fmt -- --check
   cargo clippy --all-targets --all-features -D warnings
   cargo test --all-targets
   ```
4. Push your branch and open a Pull Request against `main`.
5. Provide a clear summary of your changes, motivation, and test coverage in the PR description.
