#!/usr/bin/env bash
# Check agentsec daemon connection, process status, and storage metrics
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
exec "$AGENTSEC_BIN" doctor "$@"
