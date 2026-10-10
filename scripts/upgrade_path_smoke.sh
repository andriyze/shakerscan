#!/usr/bin/env bash
# Upgrade a real installed release that holds data to a candidate, then call every API route.
#
# A clean install runs every schema statement; an upgraded database only runs what the startup
# migration path runs. This gate installs the PREVIOUS published release with the real installer,
# gives it data through the public API, upgrades it with the real installer, and then requires:
#   - /health reports the candidate version (and source revision, when CANDIDATE_SHA is given);
#   - every seeded record (targets, standing authorizations, a completed Scan, findings, a device,
#     a schedule, a discovery run, a Hunt record) is still readable and unchanged;
#   - targeted writes succeed: POST /discovery for a person-added apex, PATCH /targets/{id},
#     authorization revoke and re-create, a manual finding, a schedule update, a Hunt cancel, and
#     a new passive Scan that runs to completion;
#   - every GET operation in the running API's OpenAPI document answers without a 5xx or a hang,
#     once with the seeded identifiers and once with an unknown identifier.
# Any failure exits 1 and names the route with an excerpt of the response body.
#
# Usage (needs Docker with Compose v2, curl, jq and python3; runs on a plain Ubuntu VM):
#   # previous stable -> the candidate built from this tree (CI):
#   CANDIDATE_IMAGE_LOCK=release-image-lock.env CANDIDATE_SHA=<40-hex> scripts/upgrade_path_smoke.sh
#   # one published release -> another (no build needed), e.g. to reproduce an upgrade defect:
#   BASELINE_VERSION=2.8.1 CANDIDATE_VERSION=2.8.2 scripts/upgrade_path_smoke.sh
#
# Inputs:
#   BASELINE_VERSION      release to install first (default: install/STABLE_VERSION)
#   CANDIDATE_IMAGE_LOCK  release-image-lock.env with the candidate's five digests and
#                         RUNTIME_MANIFEST_SHA256; the candidate runtime files are this tree,
#                         installed by this tree's install/index.sh from file:// sources
#   CANDIDATE_VERSION     instead of a lock: a published release, installed from the hosted channel
#   CANDIDATE_SHA         optional exact source revision the upgraded API must report
#   UPGRADE_PATH_RECEIPT  receipt path (default artifacts/upgrade-path/<baseline>-receipt.json)
#   UPGRADE_PATH_INSTALLER_URL  hosted installer (default https://install.shakerscan.com)
#   UPGRADE_PATH_KEEP=1   leave the stack running for inspection
#   UPGRADE_PATH_SKIP     space-separated GET path templates the sweep must not call, for local
#                         investigation only (the release workflow sets none; the receipt lists them)
#   SHAKERSCAN_SMOKE_{API,UI,POSTGRES,REDIS}_PORT  pin a port (default: first free high port)
#
# The stack is its own Compose project on free high ports with its own HOME, so it never touches
# the operator's install, other containers, or the default ports. It is removed with its volumes
# at exit. Scan traffic only reaches a fixture container on the project network; the discovery
# runs queue passive lookups for reserved .test names, never for a real domain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_VERSION="${BASELINE_VERSION:-$(tr -d '[:space:]' < "$ROOT/install/STABLE_VERSION")}"
CANDIDATE_IMAGE_LOCK="${CANDIDATE_IMAGE_LOCK:-}"
CANDIDATE_VERSION="${CANDIDATE_VERSION:-}"
CANDIDATE_SHA="${CANDIDATE_SHA:-}"
INSTALLER_URL="${UPGRADE_PATH_INSTALLER_URL:-https://install.shakerscan.com}"
RECEIPT="${UPGRADE_PATH_RECEIPT:-$ROOT/artifacts/upgrade-path/$BASELINE_VERSION-receipt.json}"
PROBE="$ROOT/scripts/upgrade_path_probe.py"
# The launcher treats these as operator overrides that win over a release image lock; inherited
# from the caller they would run other images than the baseline's and the candidate's locks name.
unset SCANNER_IMAGE API_IMAGE UI_IMAGE SIGNER_IMAGE MODEL_INTAKE_IMAGE SHAKERSCAN_RAW_BASE \
    SHAKERSCAN_RELEASE_ASSET_ROOT SHAKERSCAN_INSTALL_VERSION SCANNER_IMAGE_TAG SCANNER_IMAGE_REPO \
    API_IMAGE_REPO UI_IMAGE_REPO MODEL_INTAKE_SIGNER_IMAGE_REPO MODEL_INTAKE_IMAGE_REPO \
    SCANNER_USE_PREBUILT SCANNER_LOCAL_BUILD SHAKERSCAN_DISABLE_IMAGE_LOCK COMPOSE_FILE

if [ -n "$CANDIDATE_IMAGE_LOCK" ] && [ -n "$CANDIDATE_VERSION" ]; then
    echo "upgrade path: set CANDIDATE_IMAGE_LOCK or CANDIDATE_VERSION, not both" >&2; exit 2
fi
if [ -n "$CANDIDATE_IMAGE_LOCK" ]; then
    [ -s "$CANDIDATE_IMAGE_LOCK" ] || { echo "upgrade path: missing $CANDIDATE_IMAGE_LOCK" >&2; exit 2; }
    CANDIDATE_IMAGE_LOCK="$(cd "$(dirname "$CANDIDATE_IMAGE_LOCK")" && pwd)/$(basename "$CANDIDATE_IMAGE_LOCK")"
    EXPECTED_VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
elif [ -n "$CANDIDATE_VERSION" ]; then
    EXPECTED_VERSION="$CANDIDATE_VERSION"
else
    echo "upgrade path: set CANDIDATE_IMAGE_LOCK (a candidate) or CANDIDATE_VERSION (a published release)" >&2; exit 2
fi
[ "$BASELINE_VERSION" != "$EXPECTED_VERSION" ] || {
    echo "upgrade path: the baseline and the candidate are both $EXPECTED_VERSION" >&2; exit 2; }
for tool in docker curl jq python3; do
    command -v "$tool" > /dev/null || { echo "upgrade path: $tool is required" >&2; exit 2; }
done

SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-upgrade-path.XXXXXX")"
SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd -P)"
SMOKE_HOME="$SMOKE_ROOT/home"
RUNTIME="$SMOKE_HOME/.shakerscan"
BIN_DIR="$SMOKE_HOME/.local/bin"
PROJECT="shakerscan-upgrade-path-$$"
FIXTURE="$PROJECT-fixture"
FIXTURE_HOST="upgrade-fixture"
APEX="upgrade-path.test"
SEED_APEX="upgrade-path-seed.test"
LOG_DIR="$(dirname "$RECEIPT")/logs-$BASELINE_VERSION"
STATE="$LOG_DIR/seed-state.json"
mkdir -p "$LOG_DIR" "$SMOKE_HOME"
TIMINGS=""
STARTED="$(date +%s)"
SKIP_ARGS=()
for template in ${UPGRADE_PATH_SKIP:-}; do SKIP_ARGS+=(--skip "$template"); done

free_port() {
    local port="$1"
    while ! python3 -c 'import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", int(sys.argv[1])))
s.close()' "$port" 2>/dev/null; do
        port=$((port + 1))
        [ "$port" -le 65000 ] || { echo "upgrade path: no free port at or above $1" >&2; exit 1; }
    done
    echo "$port"
}
API_PORT="${SHAKERSCAN_SMOKE_API_PORT:-$(free_port 18180)}"
UI_PORT="${SHAKERSCAN_SMOKE_UI_PORT:-$(free_port 13100)}"
POSTGRES_PORT="${SHAKERSCAN_SMOKE_POSTGRES_PORT:-$(free_port 15532)}"
REDIS_PORT="${SHAKERSCAN_SMOKE_REDIS_PORT:-$(free_port 16479)}"
API="http://127.0.0.1:$API_PORT"
echo "upgrade path: $BASELINE_VERSION -> ${CANDIDATE_VERSION:-candidate $EXPECTED_VERSION}; project $PROJECT api=$API_PORT ui=$UI_PORT"

# Everything the launcher and the installer read from the environment, identical for every call.
stack_env() {
    env HOME="$SMOKE_HOME" SHAKERSCAN_HOME="$RUNTIME" SHAKERSCAN_BIN_DIR="$BIN_DIR" SHELL=/bin/bash \
        COMPOSE_PROJECT_NAME="$PROJECT" WORKERS=1 \
        SHAKERSCAN_API_PORT="$API_PORT" SHAKERSCAN_UI_PORT="$UI_PORT" \
        POSTGRES_PORT="$POSTGRES_PORT" REDIS_PORT="$REDIS_PORT" "$@"
}

elapsed() {
    TIMINGS="$TIMINGS\"$1\": $(( $(date +%s) - $2 )), "
}

diagnose() {
    echo "== docker"; docker version --format 'server {{.Server.Version}}' 2>&1
    echo "== containers"; docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | xargs -r docker inspect \
        --format '{{.Name}}	{{.State.Status}}	{{.Config.Image}}	{{.Image}}' 2>&1
    echo "== api health"; curl -sS -m 10 "$API/health" 2>&1 | head -c 3000; echo
    for service in api worker; do
        echo "== logs $service (errors)"
        docker logs --tail 2000 "$PROJECT-$service-1" 2>&1 | grep -E -A12 'Traceback|ERROR|Error:' | tail -n 200
    done
}

RESULT="fail"
FAILURE=""
write_receipt() {
    local baseline_report="$LOG_DIR/baseline-sweep.json" upgraded_report="$LOG_DIR/upgraded-check.json"
    mkdir -p "$(dirname "$RECEIPT")"
    jq -n --arg baseline "$BASELINE_VERSION" --arg candidate "$EXPECTED_VERSION" \
        --arg candidate_sha "$CANDIDATE_SHA" --arg result "$RESULT" --arg failure "$FAILURE" \
        --arg tested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg mode "$([ -n "$CANDIDATE_IMAGE_LOCK" ] && echo candidate-image-lock || echo published-release)" \
        --argjson seconds "{${TIMINGS%, }}" \
        --argjson baseline_images "$(lock_json "$LOG_DIR/baseline-image-lock.env")" \
        --argjson candidate_images "$(lock_json "$LOG_DIR/candidate-image-lock.env")" \
        --argjson baseline_sweep "$(cat "$baseline_report" 2>/dev/null || echo null)" \
        --argjson upgraded "$(cat "$upgraded_report" 2>/dev/null || echo null)" \
        --rawfile api_exceptions <(cat "$LOG_DIR/api-exceptions.txt" 2>/dev/null || true) '{
      schema_version: "shakerscan-upgrade-path-smoke/v1",
      baseline: {version: $baseline, images: $baseline_images},
      candidate: {version: $candidate, source_sha: $candidate_sha, mode: $mode, images: $candidate_images},
      tested_at: $tested_at, seconds: $seconds, result: $result,
      failure: (if $failure == "" then null else $failure end),
      checks: (($upgraded // {}).checks // {}),
      failures: (($upgraded // {}).failures // []),
      api_exceptions: ($api_exceptions | split("\n") | map(sub("^ +"; "")) | map(select(length > 0))),
      upgraded: $upgraded,
      baseline_sweep: (if $baseline_sweep == null then null else
        {result: $baseline_sweep.result, failures: $baseline_sweep.failures,
         status_counts: $baseline_sweep.sweep.status_counts} end)
    }' > "$RECEIPT" || echo "upgrade path: could not write $RECEIPT" >&2
}

lock_json() {
    if [ -s "$1" ]; then
        jq -Rn '[inputs | select(test("^[A-Z_]+_IMAGE=")) | capture("^(?<k>[A-Z_]+)_IMAGE=(?<v>.*)$")]
                | map({key: (.k | ascii_downcase), value: .v}) | from_entries' < "$1"
    else
        echo null
    fi
}

fail() {
    FAILURE="$*"
    echo "FAIL: $*" >&2
    diagnose > "$LOG_DIR/failure-diagnostics.txt" 2>&1 || true
    exit 1
}

cleanup() {
    local status=$?
    elapsed total "$STARTED"
    [ "$status" -eq 0 ] && RESULT="pass"
    write_receipt
    if [ "${UPGRADE_PATH_KEEP:-0}" = "1" ]; then
        echo "upgrade path: kept project $PROJECT under $SMOKE_ROOT" >&2
        return
    fi
    docker rm -f "$FIXTURE" > /dev/null 2>&1 || true
    if [ -x "$BIN_DIR/shakerscan" ]; then
        stack_env "$BIN_DIR/shakerscan" stop > /dev/null 2>&1 || true
    fi
    if [ -f "$RUNTIME/docker-compose.release.yml" ]; then
        stack_env docker compose --project-name "$PROJECT" --project-directory "$RUNTIME" \
            --env-file "$RUNTIME/.env" -f "$RUNTIME/docker-compose.release.yml" \
            down --volumes --remove-orphans > /dev/null 2>&1 || true
    fi
    # Services from other Compose files (the device worker) are not in the release file's down.
    docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | xargs -r docker rm -f > /dev/null 2>&1 || true
    docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | xargs -r docker volume rm -f > /dev/null 2>&1 || true
    docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" | xargs -r docker network rm > /dev/null 2>&1 || true
    # Workers write scan artifacts into the bind-mounted results tree as root.
    if ! rm -rf "$SMOKE_ROOT" 2>/dev/null && [ -n "${CLEANUP_IMAGE:-}" ]; then
        docker run --rm -v "$SMOKE_ROOT:/smoke" --entrypoint sh "$CLEANUP_IMAGE" \
            -c 'rm -rf /smoke/home/.shakerscan/results' > /dev/null 2>&1 || true
        rm -rf "$SMOKE_ROOT" 2>/dev/null || echo "upgrade path: leftover root-owned files under $SMOKE_ROOT" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
# A runner timeout or a cancelled lab run sends TERM: exit through the cleanup, not around it.
trap 'exit 143' TERM
trap 'exit 130' INT
# A step that fails outside fail() still names itself in the receipt.
trap 'FAILURE="${FAILURE:-line $LINENO: $BASH_COMMAND}"' ERR

wait_healthy() {
    local version="$1"
    for _ in $(seq 1 90); do
        if [ "$(curl -fsS -m 5 "$API/health" 2>/dev/null | jq -r '.scanner_version + " " + .status' 2>/dev/null)" = "$version healthy" ]; then
            return 0
        fi
        sleep 5
    done
    return 1
}

install_with() {
    # $1 = log name; remaining = environment for the installer.
    local name="$1" log="$LOG_DIR/$1.log"; shift
    local started; started="$(date +%s)"
    if ! curl -fsSL --proto '=https' --tlsv1.2 "$INSTALLER_URL" -o "$SMOKE_ROOT/index.sh"; then
        fail "could not download the installer from $INSTALLER_URL"
    fi
    stack_env "$@" SHAKERSCAN_START=0 sh "$SMOKE_ROOT/index.sh" > "$log" 2>&1 || {
        tail -n 40 "$log" >&2; fail "installer failed (see $log)"; }
    elapsed "$name" "$started"
}

start_stack() {
    local log="$LOG_DIR/$1.log" started; started="$(date +%s)"
    stack_env "$BIN_DIR/shakerscan" start -y > "$log" 2>&1 || { tail -n 40 "$log" >&2; fail "start failed (see $log)"; }
    elapsed "$1" "$started"
}

echo "== 1. install $BASELINE_VERSION with the real installer"
install_with install-baseline SHAKERSCAN_INSTALL_VERSION="$BASELINE_VERSION"
[ "$(tr -d '[:space:]' < "$RUNTIME/VERSION")" = "$BASELINE_VERSION" ] || fail "the installer did not install $BASELINE_VERSION"
cp "$RUNTIME/release-image-lock.env" "$LOG_DIR/baseline-image-lock.env"
CLEANUP_IMAGE="$(sed -n 's/^SCANNER_IMAGE=//p' "$RUNTIME/release-image-lock.env")"
start_stack start-baseline
wait_healthy "$BASELINE_VERSION" || fail "$BASELINE_VERSION never reported healthy"

echo "== 2. seed $BASELINE_VERSION through the public API"
# A static fixture on the project network: the Scan never leaves the Compose network.
docker run -d --name "$FIXTURE" --network "${PROJECT}_default" \
    --network-alias "$FIXTURE_HOST" --network-alias "app.$APEX" \
    --entrypoint sh "$CLEANUP_IMAGE" \
    -c 'mkdir -p /tmp/fixture && cd /tmp/fixture && printf "<html><body>upgrade path fixture</body></html>" > index.html && exec python3 -m http.server 8000' \
    > /dev/null || fail "could not start the fixture"
started="$(date +%s)"
python3 "$PROBE" seed --api "$API" --state "$STATE" --fixture "$FIXTURE_HOST" --apex "$APEX" \
    --seed-apex "$SEED_APEX" || fail "seeding $BASELINE_VERSION failed"
elapsed seed "$started"
# The previous release's own answers, for context in the receipt: a 5xx here is a defect the
# candidate inherited, not one the upgrade introduced. It does not decide the gate.
python3 "$PROBE" sweep --api "$API" --state "$STATE" --report "$LOG_DIR/baseline-sweep.json" ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"} \
    > "$LOG_DIR/baseline-sweep.log" 2>&1 || echo "upgrade path: note: $BASELINE_VERSION itself answers some GETs with 5xx (see the receipt)"

echo "== 3. upgrade to ${CANDIDATE_VERSION:-the candidate} with the real installer"
# The fixture is not a Compose service: detached, it cannot hold the project network if the
# candidate's Compose file recreates it.
docker network disconnect "${PROJECT}_default" "$FIXTURE" > /dev/null || fail "could not detach the fixture"
if [ -n "$CANDIDATE_IMAGE_LOCK" ]; then
    # This tree's installer, reading this tree and the candidate's lock from file:// sources:
    # the same downloads, manifest verification and owned-file pruning as a hosted upgrade.
    assets="$SMOKE_ROOT/release-assets/v$EXPECTED_VERSION"
    mkdir -p "$assets"
    cp "$CANDIDATE_IMAGE_LOCK" "$assets/release-image-lock.env"
    cp "$ROOT/install/index.sh" "$SMOKE_ROOT/candidate-index.sh"
    started="$(date +%s)"
    stack_env SHAKERSCAN_RAW_BASE="file://$ROOT" SHAKERSCAN_RELEASE_ASSET_ROOT="file://$SMOKE_ROOT/release-assets" \
        SHAKERSCAN_START=0 sh "$SMOKE_ROOT/candidate-index.sh" > "$LOG_DIR/install-candidate.log" 2>&1 || {
        tail -n 40 "$LOG_DIR/install-candidate.log" >&2; fail "the candidate installer failed"; }
    elapsed install-candidate "$started"
else
    install_with install-candidate SHAKERSCAN_INSTALL_VERSION="$CANDIDATE_VERSION"
fi
[ "$(tr -d '[:space:]' < "$RUNTIME/VERSION")" = "$EXPECTED_VERSION" ] || fail "the upgrade did not install $EXPECTED_VERSION"
cp "$RUNTIME/release-image-lock.env" "$LOG_DIR/candidate-image-lock.env"
start_stack start-candidate
wait_healthy "$EXPECTED_VERSION" || fail "the upgraded stack never reported $EXPECTED_VERSION healthy"
docker network connect --alias "$FIXTURE_HOST" --alias "app.$APEX" "${PROJECT}_default" "$FIXTURE" > /dev/null || \
    fail "could not reattach the fixture"
# Every ShakerScan container of the project runs one of the candidate's locked digests, and the
# api, ui and worker are among them; postgres, redis and the proxy are not release images.
# `docker ps` prints a digest-pinned reference as the bare repository on some Docker versions
# (GitHub's runners), so the comparison is by image ID: the ID each container runs must be the ID
# of a locked reference, and the reference it was created from must not be a mutable tag.
locked_ids="$(sed -n 's/^[A-Z_]*_IMAGE=//p' "$RUNTIME/release-image-lock.env" | while read -r ref; do
    docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || echo "missing:$ref"; done)"
grep -q '^missing:' <<< "$locked_ids" && fail "a locked image is not present locally: $(grep '^missing:' <<< "$locked_ids" | head -n 1)"
running=""
for container in $(docker ps -q --filter "label=com.docker.compose.project=$PROJECT"); do
    read -r name service ref id <<< "$(docker inspect --format \
        '{{.Name}} {{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{.Image}}' "$container")"
    name="${name#/}"
    running="$running$service $name $ref $id"$'\n'
    case "$ref" in
        shakerscan/*|*/shakerscan/*)
            grep -qxF "$id" <<< "$locked_ids" || fail "$name ($service) runs $ref ($id), not a candidate digest"
            case "${ref##*/}" in *:*) case "$ref" in *@sha256:*) ;; *) fail "$name ($service) was created from the tag $ref" ;; esac ;; esac
            ;;
    esac
done
printf '%s' "$running" > "$LOG_DIR/candidate-containers.txt"
for service in api ui worker; do
    grep -q "^$service " <<< "$running" || fail "the upgraded stack has no running $service"
done

echo "== 4. check the upgraded stack"
started="$(date +%s)"
CHECK_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check_args=(--api "$API" --state "$STATE" --report "$LOG_DIR/upgraded-check.json" --expect-version "$EXPECTED_VERSION"
    --baseline-sweep "$LOG_DIR/baseline-sweep.json" ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"})
[ -z "$CANDIDATE_SHA" ] || check_args+=(--expect-sha "$CANDIDATE_SHA")
# This tree is the candidate only in lock mode; then every GET in its committed public contract
# must be served and swept.
if [ -n "$CANDIDATE_IMAGE_LOCK" ]; then
    check_args+=(--public-manifest "$ROOT/docs/generated/public-openapi-manifest.json")
fi
if ! python3 "$PROBE" check "${check_args[@]}"; then
    elapsed check "$started"
    # A 500 body says only "Internal Server Error"; the API log names the cause.
    causes="$(docker logs --since "$CHECK_SINCE" "$PROJECT-api-1" 2>&1 \
        | grep -E '^[A-Za-z_][A-Za-z0-9_.]*(Error|Exception): ' | sort | uniq -c | sort -rn | head -n 10 || true)"
    printf '%s\n' "$causes" > "$LOG_DIR/api-exceptions.txt"
    [ -z "$causes" ] || printf 'API exceptions during the check:\n%s\n' "$causes" >&2
    fail "the upgraded stack failed: $(jq -r '.failures | join(" | ")' "$LOG_DIR/upgraded-check.json" | head -c 4000)"
fi
elapsed check "$started"
echo "Upgrade path smoke passed: $BASELINE_VERSION -> $EXPECTED_VERSION; receipt: $RECEIPT"
