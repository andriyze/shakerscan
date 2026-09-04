#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?usage: scripts/public_install_smoke.sh VERSION [receipt.json]}"
RECEIPT="${2:-public-smoke-receipt.json}"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-public-smoke.XXXXXX")"
SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd -P)"
SMOKE_HOME="$SMOKE_ROOT/home"
RUNTIME="$SMOKE_HOME/.shakerscan"
BIN_DIR="$SMOKE_HOME/.local/bin"
PROJECT="shakerscan-public-smoke-$$"

# The smoke runs a complete second stack, so it must never fight the operator's own stack for
# the default ports (the 2.0.1 promotion failed on 127.0.0.1:6379 with the dev stack running).
# Each port is the first free one at or above a high default; the installer and its compose
# files take them through the same variables an operator would use. Override with
# SHAKERSCAN_SMOKE_{API,UI,POSTGRES,REDIS}_PORT to pin one.
free_port() {
    local port="$1"
    while ! python3 -c 'import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", int(sys.argv[1])))
s.close()' "$port" 2>/dev/null; do
        port=$((port + 1))
        if [ "$port" -gt 65000 ]; then
            echo "public smoke: no free port found at or above $1" >&2
            exit 1
        fi
    done
    echo "$port"
}
API_PORT="${SHAKERSCAN_SMOKE_API_PORT:-$(free_port 18080)}"
UI_PORT="${SHAKERSCAN_SMOKE_UI_PORT:-$(free_port 13000)}"
POSTGRES_PORT="${SHAKERSCAN_SMOKE_POSTGRES_PORT:-$(free_port 15432)}"
REDIS_PORT="${SHAKERSCAN_SMOKE_REDIS_PORT:-$(free_port 16379)}"
echo "public smoke: api=$API_PORT ui=$UI_PORT postgres=$POSTGRES_PORT redis=$REDIS_PORT"

check_equal() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "public smoke: $label expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

cleanup() {
    if [ -x "$BIN_DIR/shakerscan" ]; then
        HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" \
            SHAKERSCAN_API_PORT="$API_PORT" SHAKERSCAN_UI_PORT="$UI_PORT" \
            POSTGRES_PORT="$POSTGRES_PORT" REDIS_PORT="$REDIS_PORT" \
            "$BIN_DIR/shakerscan" stop >/dev/null 2>&1 || true
        docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
            --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
            down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    # Containers write scan artifacts into the bind-mounted results tree as root. A cleanup that
    # cannot remove them must not turn a passed smoke into a failure: the runner is ephemeral, so
    # leftovers are reported and ignored.
    if ! rm -rf "$SMOKE_ROOT" 2>/dev/null; then
        docker run --rm -v "$SMOKE_ROOT:/smoke" --entrypoint sh "shakerscan/shakerscan-scanner:$VERSION" \
            -c 'rm -rf /smoke/home/.shakerscan/results' >/dev/null 2>&1 || true
        rm -rf "$SMOKE_ROOT" 2>/dev/null || \
            echo "smoke cleanup: leftover root-owned files under $SMOKE_ROOT (ignored)" >&2
    fi
}
trap cleanup EXIT

mkdir -p "$SMOKE_HOME"
curl -fsSL https://install.shakerscan.com | \
    HOME="$SMOKE_HOME" SHAKERSCAN_HOME="$RUNTIME" SHAKERSCAN_BIN_DIR="$BIN_DIR" \
    SHAKERSCAN_INSTALL_VERSION="$VERSION" SHAKERSCAN_START=0 SHELL=/bin/bash sh
check_equal "installed version" "$(tr -d '[:space:]' < "$RUNTIME/VERSION")" "$VERSION"

HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" WORKERS=1 \
    SHAKERSCAN_API_PORT="$API_PORT" SHAKERSCAN_UI_PORT="$UI_PORT" \
    POSTGRES_PORT="$POSTGRES_PORT" REDIS_PORT="$REDIS_PORT" \
    "$BIN_DIR/shakerscan" start -y

api_health="$(curl -fsS "http://127.0.0.1:$API_PORT/health")"
ui_identity="$(curl -fsS "http://127.0.0.1:$UI_PORT/api/build-identity")"
check_equal "API version" "$(jq -r '.scanner_version' <<<"$api_health")" "$VERSION"
check_equal "UI version" "$(jq -r '.ui_version' <<<"$ui_identity")" "$VERSION"
source_revision="$(jq -r '.source_revision' <<<"$api_health")"
[[ "$source_revision" =~ ^[0-9a-f]{40}$ ]] || {
    echo "public smoke: API did not report an exact source revision" >&2
    exit 1
}
check_equal "UI source revision" "$(jq -r '.source_revision' <<<"$ui_identity")" "$source_revision"
check_equal "worker identity" "$(jq -r '.worker_build.fleet_uniform' <<<"$api_health")" "true"

jq -n --arg version "$VERSION" --arg source_sha "$source_revision" \
  --arg scanner "$(sed -n 's/^SCANNER_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg api "$(sed -n 's/^API_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg ui "$(sed -n 's/^UI_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg signer "$(sed -n 's/^SIGNER_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg tested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
  schema_version: "shakerscan-public-smoke/v2",
  version: $version,
  source_sha: $source_sha,
  images: {scanner:$scanner, api:$api, ui:$ui, signer:$signer},
  tested_at: $tested_at,
  scope_exclusions: ["model_intake"],
  checks: {
    clean_install: "pass",
    ui_api_identity: "pass",
    worker_identity: "pass"
  }
}' > "$RECEIPT"
echo "Public install smoke passed; receipt: $RECEIPT"
