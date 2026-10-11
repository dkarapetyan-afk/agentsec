#!/usr/bin/env bash
# agentsec-watchdog.sh
# Periodic watchdog script to ensure the agentsec secret manager daemon is active.
# Designed for execution via cron (* * * * *) and on boot (@reboot).

set -euo pipefail

# Ensure standard environment paths for cron execution
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"

DAEMON_PORT="${AGENTSEC_PORT:-52199}"
DAEMON_URL="http://127.0.0.1:${DAEMON_PORT}/health"
CONFIG_DIR="${AGENTSEC_CONFIG_DIR:-$HOME/.config/agentsec}"
LOG_FILE="${AGENTSEC_WATCHDOG_LOG:-$CONFIG_DIR/watchdog.log}"

mkdir -p "$CONFIG_DIR"

log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [watchdog] $*"
}

is_healthy() {
    curl -s -f --connect-timeout 2 --max-time 3 "$DAEMON_URL" > /dev/null 2>&1
}

find_agentsec() {
    if command -v agentsec >/dev/null 2>&1; then
        command -v agentsec
    elif [ -x "$HOME/.cargo/bin/agentsec" ]; then
        echo "$HOME/.cargo/bin/agentsec"
    elif [ -x "/usr/local/bin/agentsec" ]; then
        echo "/usr/local/bin/agentsec"
    else
        echo "agentsec"
    fi
}

rotate_log_if_needed() {
    local max_bytes=10485760 # 10MB limit
    if [ -f "$LOG_FILE" ]; then
        local current_size
        current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$current_size" -ge "$max_bytes" ]; then
            mv -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
            touch "$LOG_FILE" 2>/dev/null || true
            log "Notice: Rotated ${LOG_FILE} (exceeded 10MB limit)."
        fi
    fi
}

main() {
    rotate_log_if_needed

    # 1. Check if daemon is already healthy
    if is_healthy; then
        exit 0
    fi

    log "WARNING: agentsec daemon health check failed at $DAEMON_URL. Initiating recovery..."

    local agentsec_bin
    agentsec_bin=$(find_agentsec)

    # 2. If systemd user service is available and active, attempt systemctl restart
    if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled agentsec >/dev/null 2>&1; then
        log "Restarting via systemctl --user restart agentsec..."
        systemctl --user restart agentsec 2>/dev/null || true
    else
        # 3. Fallback: Spawn daemon process in background
        log "Spawning daemon in background using $agentsec_bin daemon..."
        nohup "$agentsec_bin" daemon >> "$CONFIG_DIR/daemon.log" 2>&1 &
    fi

    # 4. Wait up to 10 seconds for health endpoint to report ok
    local attempts=0
    local max_attempts=10
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
        log "SUCCESS: agentsec daemon is back online and healthy on port $DAEMON_PORT."
        exit 0
    else
        log "ERROR: agentsec daemon failed to report healthy after startup attempt."
        exit 1
    fi
}

main "$@"
