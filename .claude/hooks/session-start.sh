#!/bin/bash
# SessionStart hook for DAST Scanner
# Checks if scanner is running and reports status

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

read_runtime_value() {
    key="$1"
    [ -f "$SCRIPT_DIR/.env" ] || return 0
    awk -F= -v key="$key" '$1 == key { value = substr($0, index($0, "=") + 1) } END { print value }' "$SCRIPT_DIR/.env" |
        sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

if [ -n "${SHAKERSCAN_API_BASE:-}" ]; then
    API_BASE="$SHAKERSCAN_API_BASE"
else
    bind_host="$(read_runtime_value SHAKERSCAN_BIND_HOST)"
    api_port="$(read_runtime_value SHAKERSCAN_API_PORT)"
    case "$bind_host" in
        ""|0.0.0.0) bind_host=localhost ;;
        *:*) bind_host="[$bind_host]" ;;
    esac
    API_BASE="http://${bind_host}:${api_port:-8080}"
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "SCANNER_STATUS=docker_missing"
    exit 0
fi

# Check if scanner API is responding
if curl -s --connect-timeout 2 "$API_BASE/health" > /dev/null 2>&1; then
    # Scanner is running, get stats
    STATS=$(curl -s "$API_BASE/queue/stats" 2>/dev/null)
    RUNNING=$(echo "$STATS" | grep -o '"running":[0-9]*' | cut -d: -f2)
    PENDING=$(echo "$STATS" | grep -o '"pending":[0-9]*' | cut -d: -f2)

    echo "SCANNER_STATUS=running"
    echo "SCANNER_RUNNING=${RUNNING:-0}"
    echo "SCANNER_PENDING=${PENDING:-0}"
else
    # Check if containers exist but are stopped
    if docker compose ps 2>/dev/null | grep -q "scanner"; then
        echo "SCANNER_STATUS=stopped"
    else
        echo "SCANNER_STATUS=not_started"
    fi
fi
