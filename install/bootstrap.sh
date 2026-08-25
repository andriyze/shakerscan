#!/bin/sh
# Stable-channel dispatcher served by https://install.shakerscan.com.

set -eu

CHANNEL_RAW_BASE="${SHAKERSCAN_CHANNEL_RAW_BASE:-https://raw.githubusercontent.com/andriyze/shakerscan/main}"
RELEASE_RAW_ROOT="${SHAKERSCAN_RELEASE_RAW_ROOT:-https://raw.githubusercontent.com/andriyze/shakerscan}"
SELECTED_VERSION="${SHAKERSCAN_INSTALL_VERSION:-}"

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [ -z "$SELECTED_VERSION" ]; then
    SELECTED_VERSION="$(curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION")" || \
        fail "failed to resolve the stable ShakerScan release channel"
    SELECTED_VERSION="$(printf '%s' "$SELECTED_VERSION" | tr -d '[:space:]')"
fi

if ! printf '%s' "$SELECTED_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
    fail "release channel returned an unsafe version"
fi

release_base="$RELEASE_RAW_ROOT/v$SELECTED_VERSION"
tmp="$(mktemp "${TMPDIR:-/tmp}/shakerscan-bootstrap.XXXXXX")"
cleanup() {
    rm -f -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

curl -fsSL "$release_base/install/index.sh" -o "$tmp" || \
    fail "failed to download the v$SELECTED_VERSION installer"

SHAKERSCAN_INSTALL_VERSION="$SELECTED_VERSION" \
SHAKERSCAN_RAW_BASE="$release_base" \
    sh "$tmp" "$@"
