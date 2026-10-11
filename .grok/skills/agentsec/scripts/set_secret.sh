#!/usr/bin/env bash
# Store or update a secret under a namespace via agentsec set
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

if [ $# -lt 1 ]; then
    echo "Usage: $0 <key> [-n <namespace>] [--description <desc>] [--ttl <seconds>]" >&2
    echo "Supply the value through stdin or hidden interactive input, never arguments." >&2
    exit 1
fi

exec "$AGENTSEC_BIN" set "$@"
