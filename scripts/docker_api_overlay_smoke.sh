#!/usr/bin/env bash
# Behavioral acceptance for the scanner-derived, slim API image architecture.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKER_IMAGE="${1:-${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}}"
API_IMAGE="${2:-shakerscan-api-overlay-smoke:$$}"
KEEP_IMAGE="${SHAKERSCAN_KEEP_SMOKE_IMAGE:-0}"
PREBUILT_API="${SHAKERSCAN_API_OVERLAY_PREBUILT:-0}"

cleanup() {
    if [ "$PREBUILT_API" != "1" ] && [ "$KEEP_IMAGE" != "1" ]; then
        docker image rm -f "$API_IMAGE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

docker image inspect "$WORKER_IMAGE" >/dev/null
if [ "$PREBUILT_API" = "1" ]; then
    # Candidate acceptance must inspect the exact already-built product image;
    # rebuilding a throwaway overlay would not prove the accepted API digest.
    docker image inspect "$API_IMAGE" >/dev/null
else
    docker build \
        --build-arg "SCANNER_RUNTIME_IMAGE=$WORKER_IMAGE" \
        -f "$ROOT_DIR/scanner/Dockerfile.api" \
        -t "$API_IMAGE" \
        "$ROOT_DIR"
fi

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
    test "$(id -u)" != 0
    test ! -e /opt/tools
    if docker buildx version >/dev/null 2>&1; then
        echo "runtime API must not carry Buildx" >&2
        exit 1
    fi
    for binary in nmap masscan hydra medusa nikto dirb gobuster dnsrecon; do
        if command -v "$binary" >/dev/null 2>&1; then
            echo "runtime API unexpectedly contains $binary" >&2
            exit 1
        fi
    done
'

worker_size="$(docker image inspect "$WORKER_IMAGE" --format '{{.Size}}')"
api_size="$(docker image inspect "$API_IMAGE" --format '{{.Size}}')"
saved_bytes=$((worker_size - api_size))
if [ "$saved_bytes" -le 0 ]; then
    echo "slim API image (${api_size}) is not smaller than worker (${worker_size})" >&2
    exit 1
fi

printf '{"schema_version":"shakerscan-api-boundary-smoke/v1","status":"PASS","worker_image":"%s","api_image":"%s","saved_bytes":%s}\n' \
    "$WORKER_IMAGE" "$API_IMAGE" "$saved_bytes"
