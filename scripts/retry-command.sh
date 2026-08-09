#!/usr/bin/env bash
set -euo pipefail

attempts="${SHAKERSCAN_RETRY_ATTEMPTS:-4}"
base_delay="${SHAKERSCAN_RETRY_BASE_DELAY_SECONDS:-5}"

if [[ ! "$attempts" =~ ^[1-9][0-9]*$ ]] || [[ ! "$base_delay" =~ ^[1-9][0-9]*$ ]]; then
    echo "retry-command: retry settings must be positive integers" >&2
    exit 2
fi
if [[ "$#" -eq 0 ]]; then
    echo "usage: retry-command.sh command [argument ...]" >&2
    exit 2
fi

attempt=1
while true; do
    if "$@"; then
        exit 0
    else
        status=$?
    fi
    if [[ "$attempt" -ge "$attempts" ]]; then
        echo "retry-command: command failed after ${attempts} attempts (exit ${status})" >&2
        exit "$status"
    fi
    delay=$((attempt * base_delay))
    echo "retry-command: attempt ${attempt}/${attempts} failed; retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
done
