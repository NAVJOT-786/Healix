#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# Watchdog — monitors the AI Healing Agent process and restarts it if it dies.
#
# Runs as a sidecar process in the same container. Uses a PID file to track
# the agent process. On restart, creates a marker file so agent.py can detect
# the recovery and send a self-heal notification.
#
# Environment:
#   WATCHDOG_INTERVAL_SEC   — check interval (default: 10)
#   WATCHDOG_HEALTH_URL     — agent health endpoint (default: http://localhost:8080/health)
#   AGENT_MARKER_DIR        — where to write the self-heal marker (default: /tmp)
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

INTERVAL="${WATCHDOG_INTERVAL_SEC:-10}"
HEALTH_URL="${WATCHDOG_HEALTH_URL:-http://localhost:8080/health}"
MARKER_DIR="${AGENT_MARKER_DIR:-/tmp}"
AGENT_MARKER="${MARKER_DIR}/.ai-healer-self-healed"
AGENT_PID_FILE="${MARKER_DIR}/.ai-healer.pid"
AGENT_CMD="python -u agent.py"
LOG_PREFIX="[watchdog]"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_PREFIX} $*"; }

# Wait for the agent to start and write its PID
wait_for_agent() {
    local max_wait=30
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if [ -f "$AGENT_PID_FILE" ]; then
            local pid
            pid=$(cat "$AGENT_PID_FILE" 2>/dev/null || true)
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                log "Agent process found (PID=$pid)"
                return 0
            fi
        fi
        # Fallback: check if agent.py process is running
        if pgrep -f "python.*agent.py" >/dev/null 2>&1; then
            local pid
            pid=$(pgrep -f "python.*agent.py" | head -1)
            echo "$pid" > "$AGENT_PID_FILE"
            log "Agent process found via pgrep (PID=$pid)"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    log "WARNING: Could not find agent process after ${max_wait}s"
    return 1
}

# Start the agent process
start_agent() {
    log "Starting agent..."
    $AGENT_CMD &
    local pid=$!
    echo "$pid" > "$AGENT_PID_FILE"
    log "Agent started (PID=$pid)"
}

# Check if agent is alive
check_agent() {
    if [ -f "$AGENT_PID_FILE" ]; then
        local pid
        pid=$(cat "$AGENT_PID_FILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    # Fallback: check via pgrep
    if pgrep -f "python.*agent.py" >/dev/null 2>&1; then
        local pid
        pid=$(pgrep -f "python.*agent.py" | head -1)
        echo "$pid" > "$AGENT_PID_FILE"
        return 0
    fi
    return 1
}

# Restart the agent
restart_agent() {
    log "Agent is DOWN — initiating self-heal restart..."

    # Kill any lingering agent process
    if [ -f "$AGENT_PID_FILE" ]; then
        local old_pid
        old_pid=$(cat "$AGENT_PID_FILE" 2>/dev/null || true)
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            kill -9 "$old_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$AGENT_PID_FILE"
    fi

    # Kill any orphaned agent processes
    pkill -9 -f "python.*agent.py" 2>/dev/null || true
    sleep 2

    # Create marker so agent knows it was self-healed
    echo "$(date '+%Y-%m-%d %H:%M:%S UTC')" > "$AGENT_MARKER"
    log "Self-heal marker written to $AGENT_MARKER"

    # Start fresh agent
    start_agent
    sleep 3

    if check_agent; then
        log "Self-heal SUCCESSFUL — agent restarted (PID=$(cat "$AGENT_PID_FILE"))"
    else
        log "Self-heal FAILED — agent still down after restart"
    fi
}

# ── Main loop ─────────────────────────────────────────────────────────────────
log "Watchdog starting (interval=${INTERVAL}s)"

# Start the agent initially
start_agent
sleep 3

if ! wait_for_agent; then
    log "WARNING: Agent not ready, but watchdog will keep trying"
fi

log "Watchdog entering monitor loop"

while true; do
    sleep "$INTERVAL"

    if check_agent; then
        # Agent is healthy — nothing to do
        :
    else
        log "Agent process not found — triggering self-heal"
        restart_agent
    fi
done
