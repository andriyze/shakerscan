#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-installer-upgrade.XXXXXX")"
trap 'rm -rf -- "$SMOKE_ROOT"' EXIT

version="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
assets="$SMOKE_ROOT/assets/v$version"
mkdir -p "$assets" "$SMOKE_ROOT/bin"
manifest_sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$REPO_ROOT/install/MANIFEST.sha256")"
printf '%s\n' \
  "SCANNER_IMAGE=shakerscan/shakerscan-scanner@sha256:$(printf '1%.0s' {1..64})" \
  "API_IMAGE=shakerscan/shakerscan-api@sha256:$(printf '2%.0s' {1..64})" \
  "UI_IMAGE=shakerscan/shakerscan-ui@sha256:$(printf '3%.0s' {1..64})" \
  "SIGNER_IMAGE=shakerscan/shakerscan-model-intake-signer@sha256:$(printf '4%.0s' {1..64})" \
  "MODEL_INTAKE_IMAGE=shakerscan/shakerscan-model-intake@sha256:$(printf '5%.0s' {1..64})" \
  "RUNTIME_MANIFEST_SHA256=$manifest_sha" > "$assets/release-image-lock.env"

cat > "$SMOKE_ROOT/bin/docker" <<'SH'
#!/bin/sh
if [ "${1:-}" = "ps" ]; then
    [ -n "${STUB_DOCKER_WORKING_DIR:-}" ] && printf '%s\n' "$STUB_DOCKER_WORKING_DIR"
    exit 0
fi
if [ "${1:-}" = "volume" ] && [ "${2:-}" = "inspect" ]; then
    [ "${STUB_DOCKER_VOLUME_EXISTS:-0}" = "1" ]
    exit
fi
exit 0
SH
chmod +x "$SMOKE_ROOT/bin/docker"

install_from_checkout() {
    local home="$1"
    shift
    env -u SHAKERSCAN_HOME \
        HOME="$home" \
        PATH="$SMOKE_ROOT/bin:$PATH" \
        SHAKERSCAN_BIN_DIR="$home/.local/bin" \
        SHAKERSCAN_RAW_BASE="file://$REPO_ROOT" \
        SHAKERSCAN_RELEASE_ASSET_ROOT="file://$SMOKE_ROOT/assets" \
        SHAKERSCAN_START=0 \
        "$@" sh "$REPO_ROOT/install/index.sh"
}

# A pre-manifest installation whose Compose label points at the current directory upgrades in place.
owned_home="$SMOKE_ROOT/owned-home"
mkdir -p "$owned_home/.shakerscan"
install_from_checkout "$owned_home" \
    STUB_DOCKER_WORKING_DIR="$owned_home/.shakerscan" STUB_DOCKER_VOLUME_EXISTS=1 >/dev/null
test "$(tr -d '[:space:]' < "$owned_home/.shakerscan/.shakerscan-local-build")" = prebuilt

# A different working directory owns the project: the default install must fail before download.
foreign_home="$SMOKE_ROOT/foreign-home"
foreign_owner="$SMOKE_ROOT/existing-runtime"
mkdir -p "$foreign_home" "$foreign_owner"
set +e
foreign_output="$(install_from_checkout "$foreign_home" \
    STUB_DOCKER_WORKING_DIR="$foreign_owner" STUB_DOCKER_VOLUME_EXISTS=1 2>&1)"
foreign_status=$?
set -e
test "$foreign_status" -ne 0
grep -F "SHAKERSCAN_HOME=$foreign_owner sh -c 'curl -fsSL https://install.shakerscan.com | sh'" \
    <<<"$foreign_output" >/dev/null
test ! -e "$foreign_home/.shakerscan/scanner.sh"

# Installing over a source checkout replaces its local marker atomically and keeps the digest lock.
source_runtime="$SMOKE_ROOT/source-runtime"
source_bin="$SMOKE_ROOT/source-bin"
mkdir -p "$source_runtime/scanner" "$source_runtime/ui" "$source_bin"
touch "$source_runtime/docker-compose.yml" "$source_runtime/scanner/Dockerfile" \
    "$source_runtime/scanner/Dockerfile.api" "$source_runtime/ui/Dockerfile"
printf 'local\n' > "$source_runtime/.shakerscan-local-build"
SHAKERSCAN_HOME="$source_runtime" \
SHAKERSCAN_BIN_DIR="$source_bin" \
SHAKERSCAN_RAW_BASE="file://$REPO_ROOT" \
SHAKERSCAN_RELEASE_ASSET_ROOT="file://$SMOKE_ROOT/assets" \
SHAKERSCAN_START=0 \
PATH="$SMOKE_ROOT/bin:$PATH" \
sh "$REPO_ROOT/install/index.sh" >/dev/null
test "$(tr -d '[:space:]' < "$source_runtime/.shakerscan-local-build")" = prebuilt
grep -F 'MODEL_INTAKE_IMAGE)' "$source_bin/shakerscan" >/dev/null
grep -F 'release-image-lock.env' "$source_bin/shakerscan" >/dev/null

echo "Installer upgrade smoke passed"
