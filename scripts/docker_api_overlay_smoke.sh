#!/usr/bin/env bash
# Behavioral acceptance for the single-pass scanner/API image architecture.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKER_IMAGE="${1:-${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}}"
API_IMAGE="${2:-shakerscan-api-overlay-smoke:$$}"
KEEP_IMAGE="${SHAKERSCAN_KEEP_SMOKE_IMAGE:-0}"

cleanup() {
    if [ "$KEEP_IMAGE" != "1" ]; then
        docker image rm -f "$API_IMAGE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

docker image inspect "$WORKER_IMAGE" >/dev/null
docker build \
    --build-arg "SCANNER_RUNTIME_IMAGE=$WORKER_IMAGE" \
    -f "$ROOT_DIR/scanner/Dockerfile.api" \
    -t "$API_IMAGE" \
    "$ROOT_DIR"

worker_layers="$(docker image inspect "$WORKER_IMAGE" --format '{{json .RootFS.Layers}}')"
api_layers="$(docker image inspect "$API_IMAGE" --format '{{json .RootFS.Layers}}')"
jq -en --argjson worker "$worker_layers" --argjson api "$api_layers" '
    ($api | length) == (($worker | length) + 1) and
    $api[0:($worker | length)] == $worker
' >/dev/null

worker_manifest="$(docker run --rm --entrypoint sh "$WORKER_IMAGE" -ceu 'cat /opt/shakerscan/release-manifest.json')"
api_manifest="$(docker run --rm --entrypoint sh "$API_IMAGE" -ceu 'cat /opt/shakerscan/release-manifest.json')"
if [ "$worker_manifest" != "$api_manifest" ]; then
    echo "API overlay changed the scanner release identity" >&2
    exit 1
fi

docker run --rm --entrypoint sh "$WORKER_IMAGE" -ceu '
    if command -v docker >/dev/null 2>&1; then
        echo "worker image must not contain Docker" >&2
        exit 1
    fi
'
docker run --rm --entrypoint docker "$API_IMAGE" --version | grep -F 'Docker version 27.5.1, build 9f9e405'
docker run --rm --entrypoint sh "$API_IMAGE" -ceu '
    if docker buildx version >/dev/null 2>&1; then
        echo "runtime API must not carry Buildx" >&2
        exit 1
    fi
'

worker_size="$(docker image inspect "$WORKER_IMAGE" --format '{{.Size}}')"
api_size="$(docker image inspect "$API_IMAGE" --format '{{.Size}}')"
delta_bytes=$((api_size - worker_size))
if [ "$delta_bytes" -le 0 ] || [ "$delta_bytes" -gt $((64 * 1024 * 1024)) ]; then
    echo "API overlay size delta ${delta_bytes} is outside the expected 1-64 MiB boundary" >&2
    exit 1
fi

printf '{"schema_version":"shakerscan-api-overlay-smoke/v1","status":"PASS","worker_image":"%s","api_image":"%s","overlay_bytes":%s}\n' \
    "$WORKER_IMAGE" "$API_IMAGE" "$delta_bytes"
