#!/usr/bin/env bash
# Retrieve a secret value or inspect metadata safely via agentsec get
set -euo pipefail

find_agentsec() {
    if command -v agentsec >/dev/null 2>&1; then
        command -v agentsec
    elif [ -x "/usr/local/bin/agentsec" ]; then
        echo "/usr/local/bin/agentsec"
    elif [ -x "${HOME}/.cargo/bin/agentsec" ]; then
        echo "${HOME}/.cargo/bin/agentsec"
    else
        echo "agentsec"
    fi
}

AGENTSEC_BIN="$(find_agentsec)"

if ! command -v "$AGENTSEC_BIN" >/dev/null 2>&1 && [ ! -x "$AGENTSEC_BIN" ]; then
    echo "Error: agentsec binary not found. Please ensure agentsec is installed in PATH." >&2
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 <key> [-n <namespace>] [--raw]" >&2
    echo "Example: $0 OPENAI_API_KEY" >&2
    echo "Raw output must be captured privately, never printed to an agent transcript." >&2
    exit 1
fi

exec "$AGENTSEC_BIN" get "$@"
