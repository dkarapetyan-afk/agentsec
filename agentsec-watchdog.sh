#!/usr/bin/env bash
set -euo pipefail

# Ensure standard environment paths for cron execution
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
export USER="${USER:-$(id -un 2>/dev/null || whoami 2>/dev/null || echo '')}"
export HOME="${HOME:-$(getent passwd "$USER" 2>/dev/null | cut -d: -f6 || eval echo "~$USER")}"

SESSION_NAME="agentsec-daemon"
DAEMON_PORT="${AGENTSEC_PORT:-52199}"
DAEMON_URL="http://127.0.0.1:${DAEMON_PORT}/health"
CONFIG_DIR="${AGENTSEC_CONFIG_DIR:-$HOME/.config/agentsec}"
LOG_FILE="${AGENTSEC_WATCHDOG_LOG:-/var/log/agentsec-watchdog.log}"

find_binary() {
    local name="$1"
    local fallback="$2"
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
    elif [ -x "$fallback" ]; then
        echo "$fallback"
    else
        echo "$name"
    fi
}

AGENTSEC_BIN=$(find_binary "agentsec" "/usr/local/bin/agentsec")
CLOUDFLARED_BIN=$(find_binary "cloudflared" "/usr/local/bin/cloudflared")

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

has_split_tunnel_pane() {
    local pane_count
    pane_count=$(tmux list-panes -t "$SESSION_NAME" 2>/dev/null | wc -l || echo 0)
    [ "$pane_count" -ge 2 ]
}

rotate_log_if_needed() {
    local max_bytes=10485760 # 10MB limit
    if [ -f "$LOG_FILE" ]; then
        local current_size
        current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        if [ "$current_size" -ge "$max_bytes" ]; then
            mv -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
            touch "$LOG_FILE" 2>/dev/null || true
            chmod 664 "$LOG_FILE" 2>/dev/null || true
            log "Notice: Rotated ${LOG_FILE} because size exceeded 10MB threshold."
        fi
    fi
}

main() {
    rotate_log_if_needed

    local healthy=0
    local in_tmux=0
    local has_tunnel=0

    if is_healthy; then
        healthy=1
    fi

    if has_tmux_session; then
        in_tmux=1
        if has_split_tunnel_pane; then
            has_tunnel=1
        fi
    fi

    if [ "$healthy" -eq 1 ] && [ "$in_tmux" -eq 1 ] && [ "$has_tunnel" -eq 1 ]; then
        # Daemon HTTP endpoint, tmux session, and split tunnel pane are all healthy
        exit 0
    fi

    log "WARNING: agentsec session check failed (healthy=$healthy, tmux_session=$in_tmux, split_tunnel=$has_tunnel). Initiating recovery..."

    # If a dead, single-pane, or unresponsive session remains, terminate it
    if [ "$in_tmux" -eq 1 ]; then
        log "Terminating unresponsive or unsplit tmux session '$SESSION_NAME'..."
        tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
        sleep 1
    fi

    # Spawn daemon inside dedicated tmux session with horizontal split for Cloudflare tunnel
    log "Starting agentsec daemon and Cloudflare tunnel in detached tmux session '$SESSION_NAME'..."
    tmux new-session -d -s "$SESSION_NAME" -x 160 -y 40 -n "agentsec"
    tmux set-option -t "$SESSION_NAME" history-limit 5000 2>/dev/null || true

    # Split window horizontally
    tmux split-window -h -t "$SESSION_NAME"

    # Label pane titles
    tmux select-pane -t "${SESSION_NAME}:0.0" -T "agentsec daemon (Port ${DAEMON_PORT})" 2>/dev/null || true
    tmux select-pane -t "${SESSION_NAME}:0.1" -T "Cloudflare Tunnel" 2>/dev/null || true

    # Start agentsec daemon in Pane 0 (left)
    tmux send-keys -t "${SESSION_NAME}:0.0" "$AGENTSEC_BIN daemon" C-m

    # Start Cloudflare tunnel in Pane 1 (right)
    tmux send-keys -t "${SESSION_NAME}:0.1" "$CLOUDFLARED_BIN tunnel --url http://127.0.0.1:${DAEMON_PORT}" C-m

    # Wait up to 10 seconds for health endpoint to report ready
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

    if [ "$recovered" -ne 1 ]; then
        log "ERROR: agentsec daemon failed to report healthy after startup attempt."
        exit 1
    fi

    log "SUCCESS: agentsec daemon is online and healthy in tmux pane 0."

    # Discover and record trycloudflare.com URL from Pane 1
    local tunnel_url=""
    for i in {1..15}; do
        local pane_out
        pane_out=$(tmux capture-pane -p -J -S -100 -t "${SESSION_NAME}:0.1" 2>/dev/null || true)
        tunnel_url=$(echo "$pane_out" | grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' | head -n 1 || true)
        if [ -n "$tunnel_url" ]; then
            log "Discovered Cloudflare Tunnel URL: $tunnel_url"
            mkdir -p "$CONFIG_DIR" 2>/dev/null || true
            echo "$tunnel_url" > "$CONFIG_DIR/tunnel.url" 2>/dev/null || true
            break
        fi
        sleep 1
    done

    if [ -n "$tunnel_url" ]; then
        local ext_check
        ext_check=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$tunnel_url/health" 2>/dev/null || true)
        if [ "$ext_check" = "401" ]; then
            log "SUCCESS: External access verified (authentication enforced, HTTP 401 on unauthenticated external probe)."
        else
            log "Notice: External probe status: $ext_check"
        fi
    fi
}

main "$@"
