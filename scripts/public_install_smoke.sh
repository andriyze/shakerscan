#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?usage: scripts/public_install_smoke.sh VERSION [receipt.json]}"
RECEIPT="${2:-public-smoke-receipt.json}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-public-smoke.XXXXXX")"
SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd -P)"
SMOKE_HOME="$SMOKE_ROOT/home"
RUNTIME="$SMOKE_HOME/.shakerscan"
BIN_DIR="$SMOKE_HOME/.local/bin"
PROJECT="shakerscan-public-smoke-$$"
API_PORT=8080
UI_PORT=3000
POSTGRES_PORT=5432
REDIS_PORT=6379

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
    rm -rf "$SMOKE_ROOT"
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

session="$(curl -fsS "http://127.0.0.1:$UI_PORT/api/model-intake/operator-credential")"
check_equal "local session reason" "$(jq -r '.reason' <<<"$session")" "local_session"
token="$(jq -r '.token' <<<"$session")"
curl -fsS -H "Authorization: Bearer $token" -H "Origin: http://127.0.0.1:$UI_PORT" \
    "http://127.0.0.1:$API_PORT/model-intake/submissions?limit=1" >/dev/null

docker run --rm --network host --entrypoint python \
    -v "$ROOT_DIR/scripts/model_intake_browser_smoke.py:/tmp/model_intake_browser_smoke.py:ro" \
    "shakerscan/shakerscan-scanner:$VERSION" \
    /tmp/model_intake_browser_smoke.py "http://127.0.0.1:$UI_PORT"

plan="$(curl -fsS "http://127.0.0.1:$API_PORT/model-intake/runners/install-plan")"
check_equal "install kind" "$(jq -r '.install_kind' <<<"$plan")" "curl_install"
case "$(jq -r '.command' <<<"$plan")" in
    "cd $RUNTIME && sudo ./scanner.sh model-intake-runner install"*) ;;
    *) echo "public smoke: Firecracker command does not enter the curl runtime" >&2; exit 1 ;;
esac

jq -n --arg version "$VERSION" --arg source_sha "$source_revision" \
  --arg scanner "$(sed -n 's/^SCANNER_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg api "$(sed -n 's/^API_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg ui "$(sed -n 's/^UI_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg signer "$(sed -n 's/^SIGNER_IMAGE=//p' "$RUNTIME/release-image-lock.env")" \
  --arg tested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
  schema_version: "shakerscan-public-smoke/v1",
  version: $version,
  source_sha: $source_sha,
  images: {scanner:$scanner, api:$api, ui:$ui, signer:$signer},
  tested_at: $tested_at,
  checks: {
    clean_install: "pass",
    ui_api_identity: "pass",
    worker_identity: "pass",
    model_intake_local_session: "pass",
    model_intake_browser_session: "pass",
    firecracker_command: "pass"
  }
}' > "$RECEIPT"
echo "Public install smoke passed; receipt: $RECEIPT"
