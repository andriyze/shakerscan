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
JUICE_CONTAINER="${PROJECT}-juice-shop"
API_PORT=$((38000 + ($$ % 500)))
UI_PORT=$((39000 + ($$ % 500)))
POSTGRES_PORT=$((42000 + ($$ % 500)))
REDIS_PORT=$((43000 + ($$ % 500)))
JUICE_PORT=$((44000 + ($$ % 500)))

check_equal() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" != "$expected" ]; then
        echo "installed-stack smoke: $label expected '$expected', got '$actual'" >&2
        exit 1
    fi
}

cleanup() {
    docker rm -f "$JUICE_CONTAINER" >/dev/null 2>&1 || true
    if [ -x "$BIN_DIR/shakerscan" ]; then
        HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" \
            SHAKERSCAN_DISABLE_IMAGE_LOCK=1 \
            SCANNER_IMAGE="shakerscan-scanner:$VERSION" API_IMAGE="shakerscan-api:$VERSION" \
            UI_IMAGE="shakerscan-ui:$VERSION" SIGNER_IMAGE="shakerscan-model-intake-signer:$VERSION" \
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
    # Containers write scan artifacts into the bind-mounted results tree as root. A cleanup that
    # cannot remove them must not turn a passed smoke into a failure: the runner is ephemeral, so
    # leftovers are reported and ignored.
    if ! rm -rf "$SMOKE_ROOT" 2>/dev/null; then
        docker run --rm -v "$SMOKE_ROOT:/smoke" --entrypoint sh "shakerscan-scanner:$VERSION" \
            -c 'rm -rf /smoke/home/.shakerscan/results' >/dev/null 2>&1 || true
        rm -rf "$SMOKE_ROOT" 2>/dev/null || \
            echo "smoke cleanup: leftover root-owned files under $SMOKE_ROOT (ignored)" >&2
    fi
}
trap cleanup EXIT

mkdir -p "$SMOKE_HOME"
mkdir -p "$SMOKE_ROOT/assets/v$VERSION"
printf '%s\n' \
  "SCANNER_IMAGE=shakerscan/shakerscan-scanner@sha256:$(printf '1%.0s' {1..64})" \
  "API_IMAGE=shakerscan/shakerscan-api@sha256:$(printf '2%.0s' {1..64})" \
  "UI_IMAGE=shakerscan/shakerscan-ui@sha256:$(printf '3%.0s' {1..64})" \
  "SIGNER_IMAGE=shakerscan/shakerscan-model-intake-signer@sha256:$(printf '4%.0s' {1..64})" \
  "RUNTIME_MANIFEST_SHA256=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$ROOT_DIR/install/MANIFEST.sha256")" \
  > "$SMOKE_ROOT/assets/v$VERSION/release-image-lock.env"
HOME="$SMOKE_HOME" SHAKERSCAN_HOME="$RUNTIME" SHAKERSCAN_BIN_DIR="$BIN_DIR" \
    SHAKERSCAN_RAW_BASE="file://$ROOT_DIR" SHAKERSCAN_START=0 \
    SHAKERSCAN_DISABLE_IMAGE_LOCK=1 \
    SHAKERSCAN_RELEASE_ASSET_ROOT="file://$SMOKE_ROOT/assets" SHELL=/bin/bash \
    sh "$ROOT_DIR/install/index.sh" >/dev/null

HOME="$SMOKE_HOME" COMPOSE_PROJECT_NAME="$PROJECT" WORKERS=1 \
    SHAKERSCAN_DISABLE_IMAGE_LOCK=1 \
    SCANNER_IMAGE="shakerscan-scanner:$VERSION" API_IMAGE="shakerscan-api:$VERSION" \
    UI_IMAGE="shakerscan-ui:$VERSION" SIGNER_IMAGE="shakerscan-model-intake-signer:$VERSION" \
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

if [ "${INSTALLED_STACK_SMOKE_E2E:-0}" = "1" ]; then
    scorecard_path="${INSTALLED_STACK_SMOKE_E2E_SCORECARD:?INSTALLED_STACK_SMOKE_E2E_SCORECARD is required}"
    network_name="${PROJECT}_default"
    docker run --detach --name "$JUICE_CONTAINER" \
        --publish "127.0.0.1:$JUICE_PORT:3000" \
        --network "$network_name" --network-alias juice-shop \
    bkimminich/juice-shop@sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a \
        >/dev/null
    for _attempt in $(seq 1 60); do
        if docker run --rm --network "$network_name" --entrypoint python3 \
            "shakerscan-scanner:$VERSION" -c \
            'import urllib.request; assert urllib.request.urlopen("http://juice-shop:3000/", timeout=3).status == 200' \
            >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    docker run --rm --network "$network_name" --entrypoint python3 \
        "shakerscan-scanner:$VERSION" -c \
        'import urllib.request; assert urllib.request.urlopen("http://juice-shop:3000/", timeout=5).status == 200' \
        >/dev/null
    fixture_host="host.docker.internal"
    if [ "$(uname -s)" = "Linux" ]; then
        fixture_host="$(docker network inspect "$network_name" \
            --format '{{(index .IPAM.Config 0).Gateway}}')"
    fi
    e2e_args=(--area all --scorecard "$scorecard_path")
    if [ -n "${INSTALLED_STACK_SMOKE_E2E_EXCLUDE_AREAS:-}" ]; then
        IFS=',' read -r -a excluded_areas <<<"$INSTALLED_STACK_SMOKE_E2E_EXCLUDE_AREAS"
        for excluded_area in "${excluded_areas[@]}"; do
            e2e_args+=(--exclude-area "$excluded_area")
        done
    fi
    SHAKERSCAN_API="http://127.0.0.1:$API_PORT" \
        SHAKERSCAN_E2E_CLI="$BIN_DIR/shakerscan" \
        SHAKERSCAN_E2E_CLI_HOME="$SMOKE_HOME" \
        SHAKERSCAN_E2E_HONEY_HOST="$fixture_host" \
        SHAKERSCAN_E2E_FIXTURES_HOST="shakerscan-fixtures.internal" \
        SHAKERSCAN_E2E_DAST_TARGET="http://juice-shop:3000" \
        SHAKERSCAN_E2E_HUNT_TARGET="http://juice-shop:3000" \
        SHAKERSCAN_E2E_MODEL_INTAKE_OPERATOR_TOKEN="$token" \
        SHAKERSCAN_RELEASE_DECLARED_DEBT="${SHAKERSCAN_RELEASE_DECLARED_DEBT:-}" \
        python3 "$ROOT_DIR/tests/e2e/run_e2e.py" "${e2e_args[@]}"
    check_equal "exact-image E2E gate" "$(jq -r '.gate' "$scorecard_path")" "pass"
    if [ -n "${INSTALLED_STACK_SMOKE_DAST_RECALL_JSON:-}" ]; then
        recall_path="$INSTALLED_STACK_SMOKE_DAST_RECALL_JSON"
        mkdir -p "$(dirname "$recall_path")"
        benchmark_status=0
        python3 "$ROOT_DIR/scripts/benchmark_targets.py" juice_shop \
            --api "http://127.0.0.1:$API_PORT" --auth --enforce-quality \
            --target-url "juice_shop=http://juice-shop:3000" \
            --auth-target-url "juice_shop=http://127.0.0.1:$JUICE_PORT" || benchmark_status=$?
        cp "$ROOT_DIR/results/benchmark-runs/benchmark-juice_shop.json" "$recall_path"
        # --enforce-quality exits non-zero on a quality-bar shortfall. When the
        # release owner has authorized waiving that shortfall for this version the
        # measured card is still produced (certification records it as declared
        # debt); without a waiver the shortfall fails the smoke exactly as before.
        if [ "$benchmark_status" -ne 0 ] && [ "${SHAKERSCAN_RELEASE_WAIVE_DAST_QUALITY:-}" != "1" ]; then
            echo "DAST recall benchmark failed the enforced quality bar (status $benchmark_status)" >&2
            exit "$benchmark_status"
        fi
    fi
    if [ -n "${INSTALLED_STACK_SMOKE_FAULT_DIR:-}" ]; then
        fault_dir="$INSTALLED_STACK_SMOKE_FAULT_DIR"
        mkdir -p "$fault_dir"
        for script in \
            run_scan_cancellation_race.py \
            run_scan_reservation_identity.py \
            run_scan_action_resume.py; do
            docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
                --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
                cp "$ROOT_DIR/tests/e2e/$script" "api:/tmp/$script"
        done
        docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
            --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
            exec -T -w /app api python /tmp/run_scan_cancellation_race.py --json \
            > "$fault_dir/scan-cancellation-race.json"
        docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
            --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
            exec -T -w /app api python /tmp/run_scan_reservation_identity.py --json \
            > "$fault_dir/scan-reservation-identity.json"
        docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
            --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
            exec -T -w /app api python /tmp/run_scan_action_resume.py --json \
            > "$fault_dir/scan-action-resume.json"
        check_equal "cancellation race" "$(jq -r '.passed' "$fault_dir/scan-cancellation-race.json")" "true"
        check_equal "reservation identity" "$(jq -r '.passed' "$fault_dir/scan-reservation-identity.json")" "true"
        check_equal "action resume" "$(jq -r '.passed' "$fault_dir/scan-action-resume.json")" "true"
    fi
    if [ -n "${INSTALLED_STACK_SMOKE_BROWSER_JSON:-}" ]; then
        PLAYWRIGHT_BASE_URL="http://127.0.0.1:$UI_PORT" \
            CI=1 \
            PLAYWRIGHT_REAL_STACK=1 \
            SHAKERSCAN_API_URL="http://127.0.0.1:$API_PORT" \
            SHAKERSCAN_E2E_SCAN_TARGET="http://juice-shop:3000" \
            npm --prefix "$ROOT_DIR/ui" run test:browser
        mkdir -p "$(dirname "$INSTALLED_STACK_SMOKE_BROWSER_JSON")"
        cp "$ROOT_DIR/ui/test-results/browser-results.json" \
            "$INSTALLED_STACK_SMOKE_BROWSER_JSON"
    fi
fi

echo "installed-stack smoke passed: release identity, local Model Intake session, and Firecracker guidance"
