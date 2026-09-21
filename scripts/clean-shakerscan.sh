#!/usr/bin/env bash
# ShakerScan clean uninstall / reinstall helper for macOS and Linux.
# Removes only resources owned by the selected ShakerScan installation.
set -euo pipefail

INSTALL_DIR="${SHAKERSCAN_HOME:-$HOME/.shakerscan}"
CONFIG_DIR="${SHAKERSCAN_CONFIG_DIR:-$HOME/.config/shakerscan}"
BIN_DIR="${SHAKERSCAN_BIN_DIR:-$HOME/.local/bin}"
PROJECT="${COMPOSE_PROJECT_NAME:-shakerscan}"
YES=0
PURGE_CLIENT=1
PURGE_IMAGES=0

usage() {
  cat <<'EOF'
Usage: clean-shakerscan.sh [options]

Completely removes local ShakerScan runtime data so the host can be cleanly
reinstalled. macOS and Linux are supported.

Options:
  --home PATH       ShakerScan runtime directory (default: ~/.shakerscan)
  --project NAME    Compose project name (default: shakerscan)
  --keep-client     Keep ~/.config/shakerscan and the launcher
  --images          Also remove ShakerScan Docker images (not needed to reinstall)
  -y, --yes         Skip the destructive confirmation
  -h, --help        Show this help

This removes PostgreSQL, Redis, local MinIO/Caddy volumes, results/evidence,
runtime configuration, backups inside the runtime, fleet state, and the runtime
directory itself. External S3/object storage and backups outside the runtime are
not deleted.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home) [ "$#" -ge 2 ] || { echo "Error: --home needs a path" >&2; exit 2; }; INSTALL_DIR="$2"; shift 2 ;;
    --project) [ "$#" -ge 2 ] || { echo "Error: --project needs a name" >&2; exit 2; }; PROJECT="$2"; shift 2 ;;
    --keep-client) PURGE_CLIENT=0; shift ;;
    --images) PURGE_IMAGES=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$INSTALL_DIR" in
  ""|"/"|"$HOME") echo "Refusing unsafe runtime path: $INSTALL_DIR" >&2; exit 2 ;;
esac

echo "ShakerScan clean reinstall"
echo "  Runtime: $INSTALL_DIR"
echo "  Compose project: $PROJECT"
echo "  Client config: $([ "$PURGE_CLIENT" -eq 1 ] && printf 'remove' || printf 'keep')"
echo "  Docker images: $([ "$PURGE_IMAGES" -eq 1 ] && printf 'remove' || printf 'keep')"
echo
echo "WARNING: scan history, findings, evidence, database, queues, local object"
echo "storage, credentials, backups inside the runtime, and fleet state will be deleted."
echo "External object storage and backups outside this directory are NOT deleted."
if [ "$YES" -ne 1 ]; then
  printf 'Type DELETE SHAKERSCAN to continue: '
  IFS= read -r answer
  [ "$answer" = "DELETE SHAKERSCAN" ] || { echo "Cancelled."; exit 0; }
fi

compose=()
if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then compose=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then compose=(docker-compose)
  fi
fi

compose_file=""
for f in docker-compose.release.yml docker-compose.yml; do
  [ -f "$INSTALL_DIR/$f" ] && { compose_file="$INSTALL_DIR/$f"; break; }
done

if [ "${#compose[@]}" -gt 0 ] && [ -n "$compose_file" ]; then
  args=("${compose[@]}" --project-directory "$INSTALL_DIR" --project-name "$PROJECT" -f "$compose_file")
  [ -f "$INSTALL_DIR/.env" ] && args+=(--env-file "$INSTALL_DIR/.env")
  echo "Stopping ShakerScan and deleting Compose volumes..."
  # Include optional profiles so stopped MinIO/Caddy/fleet resources are in scope.
  "${args[@]}" --profile '*' down --volumes --remove-orphans || {
    echo "Warning: Compose cleanup did not complete; checking labeled resources." >&2
  }
elif command -v docker >/dev/null 2>&1; then
  echo "Runtime Compose file not found; cleaning resources by Compose project label..."
fi

# Compose can miss resources from an old/changed compose file. Labels are safer
# than name globs and avoid touching unrelated Docker workloads.
if command -v docker >/dev/null 2>&1; then
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)"
  [ -z "$ids" ] || docker rm -f $ids >/dev/null
  vols="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)"
  [ -z "$vols" ] || docker volume rm $vols >/dev/null
  nets="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null || true)"
  [ -z "$nets" ] || docker network rm $nets >/dev/null 2>&1 || true

  if [ "$PURGE_IMAGES" -eq 1 ]; then
    echo "Removing ShakerScan images..."
    image_ids="$(docker images --format '{{.Repository}} {{.ID}}' 2>/dev/null |
      awk '$1 ~ /(^|\/)shakerscan([\/-]|$)/ || $1 ~ /^shakerscan-/ {print $2}' | sort -u)"
    [ -z "$image_ids" ] || docker image rm $image_ids >/dev/null 2>&1 || true
  fi
fi

# Optional Linux host integrations are outside Compose. Disable them only when
# present; never fail a normal/macOS uninstall because systemd/WireGuard is absent.
if [ "$(uname -s)" = "Linux" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    for unit in shakerscan-model-intake-runner.service shakerscan-fleet-reconcile.timer shakerscan-fleet-reconcile.service; do
      systemctl list-unit-files "$unit" >/dev/null 2>&1 &&
        sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
  fi
  # Host-level runner files are ShakerScan-owned. Fleet WireGuard is removed only
  # when its exact ShakerScan config exists.
  [ ! -e /etc/systemd/system/shakerscan-model-intake-runner.service ] ||
    sudo rm -f /etc/systemd/system/shakerscan-model-intake-runner.service
  [ ! -d /etc/shakerscan ] || sudo rm -rf /etc/shakerscan
  [ ! -d /opt/shakerscan ] || sudo rm -rf /opt/shakerscan
  [ ! -d /var/lib/shakerscan ] || sudo rm -rf /var/lib/shakerscan
  if [ -f /etc/wireguard/shakerscan.conf ]; then
    command -v wg-quick >/dev/null 2>&1 && sudo wg-quick down shakerscan >/dev/null 2>&1 || true
    sudo rm -f /etc/wireguard/shakerscan.conf
  fi
  command -v systemctl >/dev/null 2>&1 && sudo systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "Removing runtime directory..."
rm -rf -- "$INSTALL_DIR"

if [ "$PURGE_CLIENT" -eq 1 ]; then
  rm -rf -- "$CONFIG_DIR"
  # Remove only a launcher that is recognizably ShakerScan-owned.
  launcher="$BIN_DIR/shakerscan"
  if [ -f "$launcher" ] && (grep -q 'shakerscan' "$launcher" 2>/dev/null || [ -L "$launcher" ]); then
    rm -f -- "$launcher"
  fi
fi

echo
echo "ShakerScan cleanup complete."
echo "Docker itself and unrelated Docker resources were left untouched."
echo "You can now perform a clean ShakerScan install."
