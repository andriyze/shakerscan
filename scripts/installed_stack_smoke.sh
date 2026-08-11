#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-installed-stack.XXXXXX")"
SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd -P)"
SMOKE_HOME="$SMOKE_ROOT/home"
RUNTIME="$SMOKE_HOME/.shakerscan"
BIN_DIR="$SMOKE_HOME/.local/bin"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
PROJECT="shakerscan-installed-smoke-$$"
API_PORT=$((38000 + ($$ % 500)))
UI_PORT=$((39000 + ($$ % 500)))
POSTGRES_PORT=$((42000 + ($$ % 500)))
REDIS_PORT=$((43000 + ($$ % 500)))

check_equal() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "installed-stack smoke: $label expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

cleanup() {
    if [ -x "$BIN_DIR/shakerscan" ]; then
        HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" \
            SCANNER_IMAGE_TAG="$VERSION" SCANNER_IMAGE_REPO=shakerscan-scanner \
            API_IMAGE_REPO=shakerscan-api UI_IMAGE_REPO=shakerscan-ui \
            MODEL_INTAKE_SIGNER_IMAGE_REPO=shakerscan-model-intake-signer \
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
HOME="$SMOKE_HOME" SHAKERSCAN_HOME="$RUNTIME" SHAKERSCAN_BIN_DIR="$BIN_DIR" \
    SHAKERSCAN_RAW_BASE="file://$ROOT_DIR" SHAKERSCAN_START=0 SHELL=/bin/bash \
    sh "$ROOT_DIR/install/index.sh" >/dev/null

HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" WORKERS=1 \
    SCANNER_IMAGE_TAG="$VERSION" SCANNER_IMAGE_REPO=shakerscan-scanner \
    API_IMAGE_REPO=shakerscan-api UI_IMAGE_REPO=shakerscan-ui \
    MODEL_INTAKE_SIGNER_IMAGE_REPO=shakerscan-model-intake-signer \
    SHAKERSCAN_PULL_IMAGES=0 SHAKERSCAN_API_PORT="$API_PORT" SHAKERSCAN_UI_PORT="$UI_PORT" \
    POSTGRES_PORT="$POSTGRES_PORT" REDIS_PORT="$REDIS_PORT" \
    "$BIN_DIR/shakerscan" start -y

api_health="$(curl -fsS "http://127.0.0.1:$API_PORT/health")"
ui_identity="$(curl -fsS "http://127.0.0.1:$UI_PORT/api/build-identity")"
check_equal "API version" "$(jq -r '.scanner_version' <<<"$api_health")" "$VERSION"
check_equal "UI version" "$(jq -r '.ui_version' <<<"$ui_identity")" "$VERSION"
check_equal "worker identity" "$(jq -r '.worker_build.fleet_uniform' <<<"$api_health")" "true"

session="$(curl -fsS "http://127.0.0.1:$UI_PORT/api/model-intake/operator-credential")"
check_equal "local session reason" "$(jq -r '.reason' <<<"$session")" "local_session"
check_equal "local session availability" "$(jq -r '.available' <<<"$session")" "true"
token="$(jq -r '.token' <<<"$session")"
curl -fsS -H "Authorization: Bearer $token" \
    -H "Origin: http://127.0.0.1:$UI_PORT" \
    "http://127.0.0.1:$API_PORT/model-intake/submissions?limit=1" >/dev/null

plan="$(curl -fsS "http://127.0.0.1:$API_PORT/model-intake/runners/install-plan")"
check_equal "install kind" "$(jq -r '.install_kind' <<<"$plan")" "curl_install"
case "$(jq -r '.command' <<<"$plan")" in
    "cd $RUNTIME && sudo ./scanner.sh model-intake-runner install"*) ;;
    *) echo "installed-stack smoke: Firecracker command does not enter $RUNTIME" >&2; exit 1 ;;
esac

echo "installed-stack smoke passed: release identity, local Model Intake session, and Firecracker guidance"
