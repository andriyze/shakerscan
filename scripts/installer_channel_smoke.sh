#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-channel-smoke.XXXXXX")"
trap 'rm -rf -- "$SMOKE_ROOT"' EXIT

stable_version="$(tr -d '[:space:]' < "$ROOT_DIR/install/STABLE_VERSION")"
release_dir="$SMOKE_ROOT/releases/v$stable_version"
channel_dir="$SMOKE_ROOT/channel/install"
mkdir -p "$release_dir" "$channel_dir" "$SMOKE_ROOT/home"
git -C "$ROOT_DIR" archive "v$stable_version" | tar -x -C "$release_dir"
cp "$ROOT_DIR/install/STABLE_VERSION" "$channel_dir/STABLE_VERSION"

export HOME="$SMOKE_ROOT/home"
export SHAKERSCAN_HOME="$HOME/.shakerscan"
export SHAKERSCAN_BIN_DIR="$HOME/.local/bin"
export SHAKERSCAN_START=0
export SHAKERSCAN_CHANNEL_RAW_BASE="file://$SMOKE_ROOT/channel"
export SHAKERSCAN_RELEASE_RAW_ROOT="file://$SMOKE_ROOT/releases"

sh "$ROOT_DIR/install/bootstrap.sh" >/dev/null

test "$(tr -d '[:space:]' < "$SHAKERSCAN_HOME/VERSION")" = "$stable_version"
test -f "$SHAKERSCAN_HOME/scanner.sh"
test -f "$SHAKERSCAN_HOME/docker-compose.release.yml"
test -x "$SHAKERSCAN_BIN_DIR/shakerscan"

printf 'stable installer channel %s: ok\n' "$stable_version"
