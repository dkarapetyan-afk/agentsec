#!/usr/bin/env bash
set -euo pipefail

# Ensure standard environment paths for cron execution
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
export HOME="${HOME:-/home/terry}"
export USER="${USER:-terry}"

SESSION_NAME="agentsec-daemon"
DAEMON_URL="http://127.0.0.1:52199/health"
LOG_FILE="/var/log/agentsec-watchdog.log"

log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [watchdog] $*"
}

is_healthy() {
    curl -s -f --connect-timeout 2 --max-time 3 "$DAEMON_URL" > /dev/null 2>&1
}

has_tmux_session() {
    tmux has-session -t "$SESSION_NAME" 2>/dev/null
}

main() {
    local healthy=0
    local in_tmux=0

    if is_healthy; then
        healthy=1
    fi

    if has_tmux_session; then
        in_tmux=1
    fi

    if [ "$healthy" -eq 1 ] && [ "$in_tmux" -eq 1 ]; then
        # Both daemon HTTP endpoint and tmux session are healthy
        exit 0
    fi

    log "WARNING: agentsec is down (healthy=$healthy, tmux_session=$in_tmux). Initiating recovery..."

    # If a dead or unresponsive session remains, terminate it
    if [ "$in_tmux" -eq 1 ]; then
        log "Terminating unresponsive tmux session '$SESSION_NAME'..."
        tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
        sleep 1
    fi

    # Spawn daemon inside dedicated tmux session
    log "Starting agentsec daemon in detached tmux session '$SESSION_NAME'..."
    tmux new-session -d -s "$SESSION_NAME" "/usr/local/bin/agentsec daemon"

    # Wait up to 5 seconds for health endpoint to report ready
    local attempts=0
    local max_attempts=5
    local recovered=0

    while [ "$attempts" -lt "$max_attempts" ]; do
        sleep 1
        if is_healthy; then
            recovered=1
            break
        fi
        attempts=$((attempts + 1))
    done

    if [ "$recovered" -eq 1 ]; then
        log "SUCCESS: agentsec daemon is online and healthy in tmux session '$SESSION_NAME'."
    else
        log "ERROR: agentsec daemon failed to report healthy after startup attempt."
        exit 1
    fi
}

main "$@"
