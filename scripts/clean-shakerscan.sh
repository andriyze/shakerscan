#!/usr/bin/env bash
# Local ShakerScan cleanup. Bash 3.2 compatible; no Compose/.env evaluation.
set -euo pipefail

INSTALL_DIR="${SHAKERSCAN_HOME-$HOME/.shakerscan}"
CONFIG_DIR="${SHAKERSCAN_CONFIG_DIR-$HOME/.config/shakerscan}"
BIN_DIR="${SHAKERSCAN_BIN_DIR-$HOME/.local/bin}"
PROJECT="${COMPOSE_PROJECT_NAME-shakerscan}"
YES=0 DRY_RUN=0 PURGE_CLIENT=1 PURGE_IMAGES=0 SUDO_DOCKER=0 PURGE_AGENT=0
PHASE=preflight

usage() {
  cat <<'EOF'
Usage: clean-shakerscan.sh [options]

Remove a local ShakerScan runtime and its project-labeled Docker resources.
macOS and Linux are supported. Preview with --dry-run before deleting data.

Options:
  --home PATH       Runtime directory (default: ~/.shakerscan)
  --project NAME    Compose project (default: shakerscan or COMPOSE_PROJECT_NAME)
  --keep-client     Keep the saved client profile, its records and launcher
  --agent-workspace Also remove the default agent workspace (it may hold your work)
  --images          Also remove first-party image references used by this project
  --sudo-docker     Use sudo for Docker only, on the same local Docker socket
  --dry-run         Validate and display the plan without deleting anything
  -y, --yes         Skip confirmation, never validation
  -h, --help        Show help

Deletes project containers, labeled volumes (including PostgreSQL/Redis/MinIO),
networks, and the verified runtime, including its evidence, secrets and backups.
Client cleanup removes only config.json, token, the client's agent-workspace
records (*.json under its state directory) and this runtime's launcher; other
client-directory files and package-manager-owned commands are retained. The
default agent workspace is kept unless --agent-workspace is given.
External storage, external volumes, host-wide /etc, /opt, /var/lib integrations,
systemd/WireGuard configuration and backups outside the runtime are NOT removed.
Run as the installation owner. Docker must be reachable; a failed inventory is
not an empty inventory. Local files are retained if Docker cleanup fails.
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
on_exit() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    case "$PHASE" in
      preflight) echo 'Cleanup aborted before removal; local files are unchanged.' >&2 ;;
      docker) echo 'Docker cleanup incomplete; some resources may be gone, but local runtime and client files were retained. Fix Docker access and retry.' >&2 ;;
      local) echo 'Local cleanup incomplete; inspect the reported paths before reinstalling. No rollback was performed.' >&2 ;;
    esac
  fi
}
trap on_exit EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --home|--project)
      [ "$#" -ge 2 ] || die "$1 requires a value"
      if [ "$1" = --home ]; then INSTALL_DIR=$2; else PROJECT=$2; fi
      shift 2 ;;
    --keep-client) PURGE_CLIENT=0; shift ;;
    --agent-workspace) PURGE_AGENT=1; shift ;;
    --images) PURGE_IMAGES=1; shift ;;
    --sudo-docker) SUDO_DOCKER=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done

# Resolve trailing slashes, dot components and parent symlinks portably. Missing
# leaves are supported for repeat cleanup, but never a dangling symlink or file.
canonical_dir() {
  local path=$1 suffix='' leaf base
  [ -n "$path" ] || die 'Directory must not be empty'
  [[ ! "$path" =~ [[:cntrl:]] ]] || die 'Control characters in directory path'
  case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
  while [ "$path" != / ] && [ "${path%/}" != "$path" ]; do path=${path%/}; done
  while [ ! -d "$path" ]; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || die "Not a directory: $path"
    leaf=${path##*/}
    case "$leaf" in ''|.|..) die "Cannot resolve directory: $1" ;; esac
    suffix="/$leaf$suffix"
    path=${path%/*}; [ -n "$path" ] || path=/
  done
  base=$(cd -P -- "$path" && pwd -P) || die "Cannot resolve directory: $1"
  base="${base%/}$suffix"
  printf '%s\n' "${base:-/}"
}

HOME_CANON=$(canonical_dir "$HOME")
[ -d "$HOME_CANON" ] || die 'HOME is not an existing directory'
[ -z "${SUDO_USER:-}" ] || die 'Run as the installation owner; use --sudo-docker instead of sudo for the entire script'
[[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die 'Invalid Compose project name'

safe_dir() {
  local path=$1 protected resolved
  case "$path" in
    /|/bin|/sbin|/usr|/usr/bin|/usr/sbin|/usr/lib|/usr/local|/usr/local/bin|/etc|/opt|/var|/var/lib|/var/run|/var/tmp|/var/log|/run|/tmp|/private|/private/tmp|/private/var|/private/var/tmp|/private/var/log|/private/etc|/home|/Users|/root|/System|/Library|/Applications|/Volumes|/mnt|/media)
      die "Refusing unsafe directory: $path" ;;
  esac
  case "$HOME_CANON/" in "$path/"*) die "Refusing HOME or its ancestor: $path" ;; esac
  for protected in .config .local .local/bin Desktop Documents Downloads Library; do
    resolved=$(canonical_dir "$HOME_CANON/$protected")
    [ "$path" != "$resolved" ] || die "Refusing shared user directory: $path"
  done
}

# The client's state (workspace records) and data (default agent workspace) directories, resolved
# as the client resolves them: SHAKERSCAN_STATE_DIR/SHAKERSCAN_DATA_DIR, then XDG_STATE_HOME/
# XDG_DATA_HOME (absolute only), then beside SHAKERSCAN_CONFIG_DIR (<dir>.state, <dir>.data),
# then ~/.local/state/shakerscan and ~/.local/share/shakerscan.
client_dir() {
  local explicit=$1 xdg=$2 suffix=$3 fallback=$4 value config
  value=${!explicit-}
  if [ -n "$value" ]; then
    case "$value" in /*) printf '%s\n' "$value"; return 0 ;; esac
    die "$explicit must be an absolute path"
  fi
  value=${!xdg-}
  case "$value" in /*) printf '%s/shakerscan\n' "${value%/}"; return 0 ;; esac
  if [ -n "${SHAKERSCAN_CONFIG_DIR-}" ]; then
    config=$SHAKERSCAN_CONFIG_DIR
    while [ "${config%/}" != "$config" ]; do config=${config%/}; done
    case "$config" in /?*) ;; *) die "SHAKERSCAN_CONFIG_DIR has no usable sibling; set $explicit" ;; esac
    printf '%s.%s\n' "$config" "$suffix"; return 0
  fi
  printf '%s/%s\n' "$HOME" "$fallback"
}
STATE_DIR=$(client_dir SHAKERSCAN_STATE_DIR XDG_STATE_HOME state .local/state/shakerscan)
DATA_DIR=$(client_dir SHAKERSCAN_DATA_DIR XDG_DATA_HOME data .local/share/shakerscan)

RAW_INSTALL=$INSTALL_DIR RAW_CONFIG=$CONFIG_DIR RAW_BIN=$BIN_DIR RAW_STATE=$STATE_DIR RAW_DATA=$DATA_DIR
INSTALL_DIR=$(canonical_dir "$RAW_INSTALL")
safe_dir "$INSTALL_DIR"
CONFIG_DIR=$(canonical_dir "$RAW_CONFIG")
BIN_DIR=$(canonical_dir "$RAW_BIN")
STATE_DIR=$(canonical_dir "$RAW_STATE")
DATA_DIR=$(canonical_dir "$RAW_DATA")
# The default agent workspace now, and where client 0.8.1 kept it (inside the configuration).
AGENT_DIRS=("$DATA_DIR/agent" "$CONFIG_DIR/agent")
RECORD_DIRS=("$STATE_DIR/workspaces" "$CONFIG_DIR/workspaces")

# A client directory the cleanup reads or removes from: never a link, never shared, never the
# runtime's parent, owned by the current user.
check_client_dir() {
  local raw=$1 canon=$2 what=$3
  [ "$(canonical_dir "$raw")" = "$canon" ] || die "$what path changed during cleanup"
  while [ "$raw" != / ] && [ "${raw%/}" != "$raw" ]; do raw=${raw%/}; done
  [ ! -L "$raw" ] || die "$what directory must not be a symlink: $raw"
  safe_dir "$canon"
  case "$INSTALL_DIR/" in "$canon/"*) die "$what directory must not contain the runtime" ;; esac
  if [ -d "$canon" ]; then [ -O "$canon" ] || die "$what directory is not owned by the current user"; fi
}

check_agent_workspace() {
  local dir=$1
  [ -e "$dir" ] || [ -L "$dir" ] || return 0
  [ ! -L "$dir" ] && [ -d "$dir" ] || die "Agent workspace is not a plain directory: $dir"
  [ -O "$dir" ] || die "Agent workspace is not owned by the current user: $dir"
  [ -f "$dir/AGENTS.md" ] && [ ! -L "$dir/AGENTS.md" ] &&
    head -n 1 "$dir/AGENTS.md" | grep -Eq '^# (Connected ShakerScan instance|Remote ShakerScan engine)$' ||
    die "Not a recognized ShakerScan agent workspace: $dir (drop --agent-workspace to keep it)"
}

validate_paths() {
  local compose candidate
  [ "$(canonical_dir "$RAW_INSTALL")" = "$INSTALL_DIR" ] || die 'Runtime path changed during cleanup'
  # Refuse a symlink as the deletion root even if its destination is marked.
  candidate=$RAW_INSTALL
  while [ "$candidate" != / ] && [ "${candidate%/}" != "$candidate" ]; do candidate=${candidate%/}; done
  [ ! -L "$candidate" ] || die 'Runtime must not be a symlink; name its real directory explicitly'
  safe_dir "$INSTALL_DIR"
  if [ -d "$INSTALL_DIR" ]; then
    [ -O "$INSTALL_DIR" ] || die 'Runtime is not owned by the current user'
    [ -f "$INSTALL_DIR/scanner.sh" ] && [ ! -L "$INSTALL_DIR/scanner.sh" ] &&
      grep -Fq 'ShakerScan - CLI Management Tool' "$INSTALL_DIR/scanner.sh" ||
      die "Not a recognized ShakerScan runtime: $INSTALL_DIR (missing launcher marker)"
    compose=''
    for candidate in docker-compose.release.yml docker-compose.yml; do
      if [ -f "$INSTALL_DIR/$candidate" ] && [ ! -L "$INSTALL_DIR/$candidate" ] &&
          grep -qi shakerscan "$INSTALL_DIR/$candidate"; then compose=$candidate; break; fi
    done
    [ -n "$compose" ] || die 'Runtime lacks a recognized ShakerScan Compose file'
  fi
  if [ "$PURGE_CLIENT" -eq 1 ]; then
    [ "$(canonical_dir "$RAW_CONFIG")" = "$CONFIG_DIR" ] || die 'Client path changed during cleanup'
    [ "$(canonical_dir "$RAW_BIN")" = "$BIN_DIR" ] || die 'Launcher directory changed during cleanup'
    safe_dir "$CONFIG_DIR"
    case "$INSTALL_DIR/" in "$CONFIG_DIR/"*) die 'Client directory must not contain the runtime' ;; esac
    if [ -d "$CONFIG_DIR" ]; then
      [ -O "$CONFIG_DIR" ] || die 'Client directory is not owned by the current user'
      if [ -e "$CONFIG_DIR/config.json" ] || [ -L "$CONFIG_DIR/config.json" ]; then
        [ -f "$CONFIG_DIR/config.json" ] && [ ! -L "$CONFIG_DIR/config.json" ] &&
          grep -Eq '"url"[[:space:]]*:[[:space:]]*"https?://' "$CONFIG_DIR/config.json" ||
          die 'Client profile is not recognized; use --keep-client to retain it'
      elif [ -e "$CONFIG_DIR/token" ] || [ -L "$CONFIG_DIR/token" ]; then
        die 'Cannot attribute token without config.json; use --keep-client'
      fi
      [ ! -d "$CONFIG_DIR/token" ] || die 'Client token is a directory; refusing removal'
    fi
    check_client_dir "$RAW_STATE" "$STATE_DIR" 'Client state'
    check_client_dir "$RAW_DATA" "$DATA_DIR" 'Client data'
    if [ "$PURGE_AGENT" -eq 1 ]; then
      for dir in "${AGENT_DIRS[@]}"; do check_agent_workspace "$dir"; done
    fi
  else
    case "$CONFIG_DIR/" in "$INSTALL_DIR/"*) die '--keep-client cannot preserve a client directory inside the deleted runtime' ;; esac
    case "$BIN_DIR/" in "$INSTALL_DIR/"*) die '--keep-client cannot preserve a launcher directory inside the deleted runtime' ;; esac
  fi
}
validate_paths

command -v docker >/dev/null 2>&1 || die 'Docker is unavailable. Install/start Docker and retry; no local files will be removed'
# Resolve in the owner's context, then pin the endpoint even when sudo is used.
if [ -n "${DOCKER_CONTEXT:-}" ] || [ -z "${DOCKER_HOST:-}" ]; then
  context=${DOCKER_CONTEXT:-$(docker context show)}
  DOCKER_ENDPOINT=$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}') || die 'Cannot inspect Docker context'
else
  DOCKER_ENDPOINT=$DOCKER_HOST
fi
case "$DOCKER_ENDPOINT" in unix:///*) ;; *) die 'This is a local cleanup helper; select a local Unix-socket Docker context' ;; esac
[[ ! "$DOCKER_ENDPOINT" =~ [[:cntrl:]] ]] || die 'Invalid Docker endpoint'
docker_cmd=(docker)
if [ "$SUDO_DOCKER" -eq 1 ]; then
  command -v sudo >/dev/null 2>&1 || die 'sudo is unavailable'
  docker_cmd=(sudo -- docker)
fi
docker_call() (
  unset DOCKER_CONTEXT DOCKER_HOST
  "${docker_cmd[@]}" --host "$DOCKER_ENDPOINT" "$@"
)
DAEMON_ID=$(docker_call info --format '{{.ID}}') || die 'Docker is unreachable. Start Docker or use --sudo-docker for a local socket permission error'
[ -n "$DAEMON_ID" ] || die 'Docker returned no daemon identity'
LABEL="label=com.docker.compose.project=$PROJECT"
inventory() {
  CONTAINERS=$(docker_call ps -aq --no-trunc --filter "$LABEL") || die 'Cannot list project containers'
  VOLUMES=$(docker_call volume ls -q --filter "$LABEL") || die 'Cannot list project volumes'
  NETWORKS=$(docker_call network ls -q --no-trunc --filter "$LABEL") || die 'Cannot list project networks'
}
inventory
IMAGES=''
while IFS= read -r id; do
  [ -n "$id" ] || continue
  workdir=$(docker_call inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id") || die 'Cannot inspect project ownership'
  if [ -n "$workdir" ] && [ "$workdir" != '<no value>' ]; then
    [ "$(canonical_dir "$workdir")" = "$INSTALL_DIR" ] || die "Project $PROJECT belongs to a different runtime: $workdir"
  fi
  if [ "$PURGE_IMAGES" -eq 1 ]; then
    image=$(docker_call inspect --format '{{.Config.Image}}' "$id") || die 'Cannot inspect project image'
    case "$image" in shakerscan/shakerscan-*|shakerscan-*) IMAGES="$IMAGES$image"$'\n' ;; esac
  fi
done <<< "$CONTAINERS"
IMAGES=$(printf '%s' "$IMAGES" | sort -u)

printf 'ShakerScan cleanup plan\n  Runtime: %s\n  Docker: %s\n  Compose project: %s\n' "$INSTALL_DIR" "$DOCKER_ENDPOINT" "$PROJECT"
printf '  Containers:\n%s\n  Volumes:\n%s\n  Networks:\n%s\n' "${CONTAINERS:-(none)}" "${VOLUMES:-(none)}" "${NETWORKS:-(none)}"
if [ "$PURGE_CLIENT" -eq 1 ]; then
  printf '  Client files: %s/{config.json,token}\n  Owned launcher only: %s/shakerscan\n' "$CONFIG_DIR" "$BIN_DIR"
  printf '  Agent workspace records: %s/*.json, %s/*.json\n' "${RECORD_DIRS[0]}" "${RECORD_DIRS[1]}"
  if [ "$PURGE_AGENT" -eq 1 ]; then
    printf '  Agent workspaces (recursively): %s, %s\n' "${AGENT_DIRS[0]}" "${AGENT_DIRS[1]}"
  else
    printf '  Agent workspaces: kept (%s; --agent-workspace removes them)\n' "${AGENT_DIRS[0]}"
  fi
else echo '  Client files and launcher: kept'; fi
if [ "$PURGE_IMAGES" -eq 1 ]; then printf '  Project first-party image references:\n%s\n' "${IMAGES:-(none)}"; else echo '  Docker images: kept'; fi
echo 'Host-wide integrations, external volumes/storage and backups outside the runtime are retained.'
echo 'WARNING: selected database, credentials, scan history, evidence and runtime backups will be deleted.'
[ "$DRY_RUN" -eq 0 ] || { echo 'Dry run complete. Nothing was removed.'; exit 0; }
if [ "$YES" -ne 1 ]; then
  printf 'Type DELETE SHAKERSCAN to continue: '
  if ! IFS= read -r answer || [ "$answer" != 'DELETE SHAKERSCAN' ]; then echo 'Cancelled. Nothing was removed.'; exit 0; fi
fi
validate_paths
[ "$(docker_call info --format '{{.ID}}')" = "$DAEMON_ID" ] || die 'Docker daemon changed; rerun the preview'
# Re-inventory after confirmation; a new resource needs a fresh operator preview.
old_containers=$CONTAINERS old_volumes=$VOLUMES old_networks=$NETWORKS
inventory
[ "$CONTAINERS" = "$old_containers" ] && [ "$VOLUMES" = "$old_volumes" ] && [ "$NETWORKS" = "$old_networks" ] || die 'Project resources changed during confirmation; rerun cleanup'

PHASE=docker
# No Compose interpolation/password is necessary. Only exact project-label
# inventory is removed, never a global prune or external/unlabeled volume.
for kind in containers volumes networks images; do
  case "$kind" in
    containers) values=$CONTAINERS; command_args=(rm -f) ;;
    volumes) values=$VOLUMES; command_args=(volume rm) ;;
    networks) values=$NETWORKS; command_args=(network rm) ;;
    images) values=$IMAGES; command_args=(image rm) ;;
  esac
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    docker_call "${command_args[@]}" "$id" || die "Failed removing $kind: $id"
  done <<< "$values"
done
inventory
[ -z "$CONTAINERS$VOLUMES$NETWORKS" ] || die 'Project resources remain after deletion; local files were retained'
[ "$(docker_call info --format '{{.ID}}')" = "$DAEMON_ID" ] || die 'Cannot verify the same Docker daemon after removal'
validate_paths

PHASE=local
# Client config is deliberately NOT recursively removed. Unknown files survive.
if [ "$PURGE_CLIENT" -eq 1 ]; then
  # Records: plain *.json files only (a link is never followed or removed through), then the
  # directories if they are empty.
  for dir in "${RECORD_DIRS[@]}"; do
    [ -d "$dir" ] && [ ! -L "$dir" ] || continue
    for sub in "$dir/superseded" "$dir"; do
      [ -d "$sub" ] && [ ! -L "$sub" ] || continue
      for record in "$sub"/*.json; do
        if [ -f "$record" ] && [ ! -L "$record" ]; then
          rm -f -- "$record" || die "Cannot remove workspace record: $record"
        fi
      done
      if ! rmdir -- "$sub"; then echo "Retained record directory (other files or permissions): $sub"; fi
    done
  done
  for dir in "${AGENT_DIRS[@]}"; do
    [ -e "$dir" ] || [ -L "$dir" ] || continue
    if [ "$PURGE_AGENT" -eq 1 ] && [ -d "$dir" ] && [ ! -L "$dir" ]; then
      rm -rf -- "$dir" || die "Cannot remove agent workspace: $dir"
    else
      echo "Kept agent workspace (it may hold your work; --agent-workspace removes it): $dir"
    fi
  done
  for dir in "$STATE_DIR" "$DATA_DIR"; do
    if [ -d "$dir" ] && [ ! -L "$dir" ] && ! rmdir -- "$dir"; then
      echo "Retained client directory (other files or permissions): $dir"
    fi
  done
  for name in config.json token; do
    rm -f -- "$CONFIG_DIR/$name" || die "Cannot remove client file: $name"
  done
  if [ -d "$CONFIG_DIR" ]; then
    if ! rmdir -- "$CONFIG_DIR"; then echo "Retained client directory (other files or permissions): $CONFIG_DIR"; fi
  fi
  launcher="$BIN_DIR/shakerscan"
  if [ -f "$launcher" ] && [ ! -L "$launcher" ] &&
      grep -Fq "exec \"$INSTALL_DIR/scanner.sh\" \"\$@\"" "$launcher"; then
    rm -f -- "$launcher" || die 'Cannot remove owned launcher'
  elif [ -e "$launcher" ] || [ -L "$launcher" ]; then
    echo "Kept launcher not attributed to this runtime: $launcher"
  fi
fi
rm -rf -- "$INSTALL_DIR" || die 'Cannot remove runtime; check ownership and permissions'
[ ! -e "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || die 'Runtime remains after removal'
PHASE=done
echo 'ShakerScan local runtime cleanup complete; selected Docker resources were verified absent.'
