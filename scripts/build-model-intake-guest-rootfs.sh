#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT_DIR/results/model-intake-runner/rootfs.ext4}"
IMAGE="${MODEL_INTAKE_GUEST_IMAGE:-shakerscan-model-intake-guest:local}"
PLATFORM="${MODEL_INTAKE_GUEST_PLATFORM:-linux/amd64}"
ROOTFS_MAX_BYTES="${MODEL_INTAKE_GUEST_ROOTFS_MAX_BYTES:-8589934592}"
TEMP_DIR="$(mktemp -d)"
CONTAINER_ID=""

cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

command -v docker >/dev/null
command -v mkfs.ext4 >/dev/null
mkdir -p "$(dirname "$OUTPUT")"

docker buildx build --platform "$PLATFORM" --load -f "$ROOT_DIR/runner/guest/Dockerfile" -t "$IMAGE" "$ROOT_DIR"
CONTAINER_ID="$(docker create --platform "$PLATFORM" "$IMAGE")"
mkdir "$TEMP_DIR/rootfs"
docker export "$CONTAINER_ID" | tar -C "$TEMP_DIR/rootfs" -xf -

payload_bytes="$(du -sb "$TEMP_DIR/rootfs" | awk '{print $1}')"
image_bytes=$((payload_bytes * 13 / 10 + 268435456))
image_bytes=$(((image_bytes + 4095) / 4096 * 4096))
if (( image_bytes > ROOTFS_MAX_BYTES )); then
    echo "Guest rootfs exceeds MODEL_INTAKE_GUEST_ROOTFS_MAX_BYTES" >&2
    exit 1
fi
truncate -s "$image_bytes" "$OUTPUT"
mkfs.ext4 -q -F -d "$TEMP_DIR/rootfs" "$OUTPUT"
sha256sum "$OUTPUT"
