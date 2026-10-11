#!/usr/bin/env bash
# Execute a command with secrets injected into RAM environment variables via agentsec run
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
    echo "Usage: $0 [--clean-env] [--only KEY1,KEY2] [-n <namespace>] -- <command...>" >&2
    echo "Example: $0 --clean-env --only API_KEY -- npm test" >&2
    exit 1
fi

exec "$AGENTSEC_BIN" run "$@"
