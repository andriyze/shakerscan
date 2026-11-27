#!/usr/bin/env bash
set -euo pipefail

attempts="${SHAKERSCAN_RETRY_ATTEMPTS:-4}"
base_delay="${SHAKERSCAN_RETRY_BASE_DELAY_SECONDS:-5}"
retry_mode="${SHAKERSCAN_RETRY_MODE:-transient}"

if [[ ! "$attempts" =~ ^[1-9][0-9]*$ ]] || [[ ! "$base_delay" =~ ^[1-9][0-9]*$ ]]; then
    echo "retry-command: retry settings must be positive integers" >&2
    exit 2
fi
if [[ "$#" -eq 0 ]]; then
    echo "usage: retry-command.sh command [argument ...]" >&2
    exit 2
fi
if [[ "$retry_mode" != "transient" && "$retry_mode" != "all" ]]; then
    echo "retry-command: SHAKERSCAN_RETRY_MODE must be transient or all" >&2
    exit 2
fi

log_file="$(mktemp "${TMPDIR:-/tmp}/shakerscan-retry.XXXXXX")"
trap 'rm -f "$log_file"' EXIT

is_retryable_failure() {
    [[ "$retry_mode" == "all" ]] && return 0
    # Keep this deliberately narrow. Syntax errors, missing files, failed tests,
    # and other deterministic build failures must fail on the first attempt.
    grep -Eiq \
        'TLS handshake timeout|i/o timeout|connection (reset|refused|timed out)|temporary failure|unexpected EOF|context deadline exceeded|network is unreachable|no such host|server misbehaving|429 Too Many Requests|toomanyrequests|50[234] (Bad Gateway|Service Unavailable|Gateway Timeout)' \
        "$log_file"
}

attempt=1
while true; do
    : > "$log_file"
    if "$@" 2>&1 | tee "$log_file"; then
        exit 0
    else
        status=$?
    fi
    if [[ "$attempt" -ge "$attempts" ]]; then
        echo "retry-command: command failed after ${attempts} attempts (exit ${status})" >&2
        exit "$status"
    fi
    if ! is_retryable_failure; then
        echo "retry-command: failure is not classified as transient; not retrying (exit ${status})" >&2
        exit "$status"
    fi
    delay=$((attempt * base_delay))
    echo "retry-command: attempt ${attempt}/${attempts} failed; retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
done
