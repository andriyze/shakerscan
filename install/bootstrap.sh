#!/bin/sh
# Stable-channel dispatcher served by https://install.shakerscan.com.

set -eu

CHANNEL_RAW_BASE="${SHAKERSCAN_CHANNEL_RAW_BASE:-https://raw.githubusercontent.com/andriyze/shakerscan/main}"
RELEASE_RAW_ROOT="${SHAKERSCAN_RELEASE_RAW_ROOT:-https://raw.githubusercontent.com/andriyze/shakerscan}"
SELECTED_VERSION="${SHAKERSCAN_INSTALL_VERSION:-}"
# An operator pinning an exact source tree -- restoring a previous release, testing a branch --
# must get THAT tree's installer and files. This dispatcher used to overwrite the caller's base
# with the current stable channel, so a rollback pinned to a previous version silently reinstalled
# current stable: the one command whose entire purpose is "not the current version" did the
# opposite. An explicit base now suppresses channel resolution entirely.
EXPLICIT_RAW_BASE="${SHAKERSCAN_RAW_BASE:-}"

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [ -z "$EXPLICIT_RAW_BASE" ] && [ -z "$SELECTED_VERSION" ]; then
    SELECTED_VERSION="$(curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION")" || \
        fail "failed to resolve the stable ShakerScan release channel"
    SELECTED_VERSION="$(printf '%s' "$SELECTED_VERSION" | tr -d '[:space:]')"
fi

if [ -n "$SELECTED_VERSION" ] && \
   ! printf '%s' "$SELECTED_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
    fail "release channel returned an unsafe version"
fi

if [ -n "$EXPLICIT_RAW_BASE" ]; then
    release_base="$EXPLICIT_RAW_BASE"
else
    release_base="$RELEASE_RAW_ROOT/v$SELECTED_VERSION"
fi
tmp="$(mktemp "${TMPDIR:-/tmp}/shakerscan-bootstrap.XXXXXX")"
cleanup() {
    rm -f -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

curl -fsSL "$release_base/install/index.sh" -o "$tmp" || \
    fail "failed to download the installer from $release_base"

# The installer comes from the same tree it will install from, so the file manifest always matches
# the revision it is fetched from.
SHAKERSCAN_INSTALL_VERSION="$SELECTED_VERSION" \
SHAKERSCAN_RAW_BASE="$release_base" \
    sh "$tmp" "$@"
