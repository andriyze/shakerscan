#!/bin/bash
# ShakerScan - CLI Management Tool
# Usage: ./scanner.sh [command] [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default workers
WORKERS=${WORKERS:-auto}
DEFAULT_PREBUILT_IMAGE_TAG="${DEFAULT_PREBUILT_IMAGE_TAG:-latest}"
ASSUME_YES=0
CONFIRM_ACTIVE=0
REMOTE_ACCESS=0
FOLLOW=""
ARGS=()
DOCKER_COMPOSE_CMD=()
COMPOSE_FILE_ARGS=()
DOCKER_NEEDS_SUDO=0
PLATFORM=""
PLATFORM_VERSION=""
PLATFORM_ID=""
PLATFORM_ID_LIKE=""
PLATFORM_NAME=""
PLATFORM_CODENAME=""
PLATFORM_UBUNTU_CODENAME=""
PLATFORM_WSL=0
USE_PREBUILT=1
PREBUILT_COMPOSE_FILE="docker-compose.release.yml"
IMAGE_TAG_OVERRIDE=""
LOCAL_BUILD_MARKER="$SCRIPT_DIR/.shakerscan-local-build"
BUILD_RECEIPT_FILE="$SCRIPT_DIR/.shakerscan-build-receipt.json"
BUILD_RECEIPT_ACTIVE=0
BUILD_RECEIPT_OPERATION=""
BUILD_RECEIPT_PHASE="not_started"
BUILD_RECEIPT_STARTED_AT=""
BUILD_RECEIPT_SCOPE="all"
RUNTIME_MODE_EXPLICIT=0

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

first_tailscale_ipv4() {
    if command_exists tailscale; then
        tailscale ip -4 2>/dev/null | head -n 1
    fi
}

format_url_host() {
    local host="$1"
    case "$host" in
        *:*) echo "[$host]" ;;
        *) echo "$host" ;;
    esac
}

public_access_host() {
    local host="${SHAKERSCAN_PUBLIC_HOST:-${SHAKERSCAN_BIND_HOST:-localhost}}"
    case "$host" in
        ""|127.0.0.1|0.0.0.0)
            host="localhost"
            ;;
    esac
    echo "$host"
}

read_dotenv_value() {
    local key="$1"
    [ -f "$SCRIPT_DIR/.env" ] || return 0
    awk -F= -v key="$key" '$1 == key { value = substr($0, index($0, "=") + 1) } END { print value }' "$SCRIPT_DIR/.env" |
        sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

load_access_env() {
    local value

    # Record whether the user set BIND/PUBLIC host in their shell *before* we
    # pull defaults out of .env, so configure_access_mode can distinguish a
    # user override from a cached value that may be stale (e.g. Tailscale IP
    # change after reboot).
    if [ -n "${SHAKERSCAN_BIND_HOST:-}" ]; then
        export SHAKERSCAN_BIND_HOST_EXPLICIT=1
    fi
    if [ -n "${SHAKERSCAN_PUBLIC_HOST:-}" ]; then
        export SHAKERSCAN_PUBLIC_HOST_EXPLICIT=1
    fi

    if [ -z "${SHAKERSCAN_BIND_HOST:-}" ]; then
        value="$(read_dotenv_value SHAKERSCAN_BIND_HOST)"
        if [ -n "$value" ]; then
            export SHAKERSCAN_BIND_HOST="$value"
        fi
    fi

    if [ -z "${SHAKERSCAN_PUBLIC_HOST:-}" ]; then
        value="$(read_dotenv_value SHAKERSCAN_PUBLIC_HOST)"
        if [ -n "$value" ]; then
            export SHAKERSCAN_PUBLIC_HOST="$value"
        fi
    fi
}

write_dotenv_value() {
    local key="$1"
    local value="$2"
    local file="$SCRIPT_DIR/.env"
    local tmp="${file}.tmp.$$"

    touch "$file"
    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        $0 ~ "^" key "=" {
            print key "=" value
            done = 1
            next
        }
        { print }
        END {
            if (!done) {
                print key "=" value
            }
        }
    ' "$file" > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$file"
}

generate_datastore_secret() {
    if command_exists openssl; then
        openssl rand -hex 32
        return
    fi
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

postgres_data_volume_exists() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"

    command_exists docker || return 1
    docker volume inspect "${project}_postgres-data" > /dev/null 2>&1
}

ensure_runtime_datastore_credentials() {
    local current_postgres current_redis next_postgres next_redis ready_attempt
    local persist_postgres=1

    touch "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    current_postgres="${POSTGRES_PASSWORD:-$(read_dotenv_value POSTGRES_PASSWORD)}"
    current_redis="${REDIS_PASSWORD:-$(read_dotenv_value REDIS_PASSWORD)}"
    if { [ "${#current_postgres}" -ge 32 ] && ! [[ "$current_postgres" =~ ^[A-Za-z0-9._~-]+$ ]]; } || \
       { [ "${#current_redis}" -ge 32 ] && ! [[ "$current_redis" =~ ^[A-Za-z0-9._~-]+$ ]]; }; then
        echo -e "${RED}Error: datastore passwords must use URL-safe letters, numbers, dot, underscore, tilde, or hyphen.${NC}" >&2
        return 1
    fi
    next_postgres="$current_postgres"
    next_redis="$current_redis"
    if [ "${#next_postgres}" -lt 32 ]; then
        next_postgres="$(generate_datastore_secret)"
    fi
    if [ "${#next_redis}" -lt 32 ]; then
        next_redis="$(generate_datastore_secret)"
    fi
    if [ "${#next_postgres}" -lt 32 ] || [ "${#next_redis}" -lt 32 ]; then
        echo -e "${RED}Error: could not generate strong datastore credentials.${NC}" >&2
        return 1
    fi

    # Compose files fail closed without these values.
    export POSTGRES_PASSWORD="$next_postgres"
    export REDIS_PASSWORD="$next_redis"

    # Redis keeps no durable copy of its credential: the server reads
    # --requirepass from this value every time it starts, so a freshly
    # generated password is always safe to persist. Persist it independently
    # of the PostgreSQL rotation below, otherwise a build/rebuild on a new
    # install exports a password it never records and leaves .env without
    # REDIS_PASSWORD, which makes a plain `docker compose up` fail closed.
    if [ "$next_redis" != "$current_redis" ]; then
        write_dotenv_value REDIS_PASSWORD "$next_redis"
    fi

    # PostgreSQL does keep a durable role password, so a changed value is only
    # true once the role has been rotated (start/restart) or once the cluster
    # is initialized from it. A brand-new install has no data volume yet, so
    # the value we generated here is exactly what initdb will use and must be
    # recorded now. An existing volume from an older weak-default install
    # keeps the previous fail-closed behavior: export for this command, and
    # persist only after the ALTER ROLE below succeeds.
    if [ "$next_postgres" != "$current_postgres" ]; then
        if postgres_data_volume_exists; then
            case "${COMMAND:-}" in
                start|restart)
                    compose up -d postgres > /dev/null
                    ready_attempt=0
                    until compose exec -T postgres pg_isready -U scanner > /dev/null 2>&1; do
                        ready_attempt=$((ready_attempt + 1))
                        if [ "$ready_attempt" -ge 30 ]; then
                            echo -e "${RED}Error: PostgreSQL did not become ready for credential rotation.${NC}" >&2
                            return 1
                        fi
                        sleep 1
                    done
                    if ! printf "ALTER ROLE scanner PASSWORD '%s';\n" "$next_postgres" | \
                        compose exec -T postgres psql -U scanner -d scanner -v ON_ERROR_STOP=1 > /dev/null; then
                        echo -e "${RED}Error: could not rotate the existing PostgreSQL credential.${NC}" >&2
                        return 1
                    fi
                    ;;
                *)
                    persist_postgres=0
                    ;;
            esac
        fi
    fi

    if [ "$persist_postgres" -eq 1 ]; then
        write_dotenv_value POSTGRES_PASSWORD "$next_postgres"
    fi
    chmod 600 "$SCRIPT_DIR/.env"
}

ensure_model_intake_operator_credential() {
    local current_token next_token

    touch "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    current_token="${MODEL_INTAKE_OPERATOR_TOKEN:-$(read_dotenv_value MODEL_INTAKE_OPERATOR_TOKEN)}"
    next_token="$current_token"
    if [ "${#next_token}" -lt 32 ]; then
        next_token="$(generate_datastore_secret)"
    fi
    if [ "${#next_token}" -lt 32 ]; then
        echo -e "${RED}Error: could not generate a strong Model Intake operator credential.${NC}" >&2
        return 1
    fi

    export MODEL_INTAKE_OPERATOR_TOKEN="$next_token"
    write_dotenv_value MODEL_INTAKE_OPERATOR_TOKEN "$next_token"
    chmod 600 "$SCRIPT_DIR/.env"
}

ensure_model_intake_local_session_secret() {
    local current_secret next_secret

    touch "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    current_secret="${MODEL_INTAKE_LOCAL_SESSION_SECRET:-$(read_dotenv_value MODEL_INTAKE_LOCAL_SESSION_SECRET)}"
    next_secret="$current_secret"
    if [ "${#next_secret}" -lt 32 ]; then
        next_secret="$(generate_datastore_secret)"
    fi
    if [ "${#next_secret}" -lt 32 ]; then
        echo -e "${RED}Error: could not generate a strong local Model Intake session secret.${NC}" >&2
        return 1
    fi

    export MODEL_INTAKE_LOCAL_SESSION_SECRET="$next_secret"
    write_dotenv_value MODEL_INTAKE_LOCAL_SESSION_SECRET "$next_secret"
    chmod 600 "$SCRIPT_DIR/.env"
}

ensure_model_intake_signer_credentials() {
    local current_token current_database_password next_token next_database_password

    touch "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    current_token="${MODEL_INTAKE_SIGNER_INTERNAL_TOKEN:-$(read_dotenv_value MODEL_INTAKE_SIGNER_INTERNAL_TOKEN)}"
    current_database_password="${MODEL_INTAKE_SIGNER_DATABASE_PASSWORD:-$(read_dotenv_value MODEL_INTAKE_SIGNER_DATABASE_PASSWORD)}"
    next_token="$current_token"
    next_database_password="$current_database_password"
    if [ "${#next_token}" -lt 32 ]; then
        next_token="$(generate_datastore_secret)"
    fi
    if [ "${#next_database_password}" -lt 32 ]; then
        next_database_password="$(generate_datastore_secret)"
    fi
    if [ "${#next_token}" -lt 32 ] || [ "${#next_database_password}" -lt 32 ]; then
        echo -e "${RED}Error: could not generate strong Model Intake signer credentials.${NC}" >&2
        return 1
    fi
    if ! [[ "$next_database_password" =~ ^[A-Za-z0-9._~-]+$ ]]; then
        echo -e "${RED}Error: Model Intake signer database password must be URL-safe.${NC}" >&2
        return 1
    fi

    export MODEL_INTAKE_SIGNER_INTERNAL_TOKEN="$next_token"
    export MODEL_INTAKE_SIGNER_DATABASE_PASSWORD="$next_database_password"
    write_dotenv_value MODEL_INTAKE_SIGNER_INTERNAL_TOKEN "$next_token"
    write_dotenv_value MODEL_INTAKE_SIGNER_DATABASE_PASSWORD "$next_database_password"
    chmod 600 "$SCRIPT_DIR/.env"
}

persist_remote_access_env() {
    if [ "$REMOTE_ACCESS" -ne 1 ]; then
        return 0
    fi

    write_dotenv_value SHAKERSCAN_BIND_HOST "${SHAKERSCAN_BIND_HOST:-}"
    write_dotenv_value SHAKERSCAN_PUBLIC_HOST "${SHAKERSCAN_PUBLIC_HOST:-$(public_access_host)}"
}

configure_access_mode() {
    local tailscale_ip
    local cached_bind="${SHAKERSCAN_BIND_HOST:-}"
    local explicit_shell_bind="${SHAKERSCAN_BIND_HOST_EXPLICIT:-0}"

    if [ "$REMOTE_ACCESS" -eq 1 ]; then
        # Always re-resolve the Tailscale IP at start time so a reboot or
        # interface change doesn't leave the persisted .env value pointing at
        # an address that no longer exists. The .env cache is only honored
        # when no live tailscale IPv4 is available (offline fallback).
        tailscale_ip="$(first_tailscale_ipv4)"
        if [ -n "$tailscale_ip" ]; then
            if [ -n "$cached_bind" ] && [ "$cached_bind" != "$tailscale_ip" ] && [ "$explicit_shell_bind" != "1" ]; then
                echo "[remote] Tailscale IP changed: ${cached_bind} → ${tailscale_ip}"
            fi
            export SHAKERSCAN_BIND_HOST="$tailscale_ip"
            # Refresh display/browser URLs when they were tracking BIND_HOST or
            # still contain a local-only sentinel from an earlier start. Keep a
            # real operator-supplied DNS name intact.
            case "${SHAKERSCAN_PUBLIC_HOST:-}" in
                ""|localhost|127.0.0.1|0.0.0.0|"$cached_bind")
                    export SHAKERSCAN_PUBLIC_HOST="$tailscale_ip"
                    ;;
            esac
        elif [ -n "$cached_bind" ]; then
            echo "[remote] No live Tailscale IPv4; reusing ${cached_bind} from environment/.env"
            export SHAKERSCAN_PUBLIC_HOST="${SHAKERSCAN_PUBLIC_HOST:-$cached_bind}"
        else
            echo -e "${RED}Error: --remote could not find a Tailscale IPv4 address.${NC}"
            echo "Start Tailscale on this host, or use:"
            echo "  SHAKERSCAN_BIND_HOST=0.0.0.0 SHAKERSCAN_PUBLIC_HOST=<server-ip-or-dns> ./scanner.sh start --remote"
            return 1
        fi
    else
        export SHAKERSCAN_BIND_HOST="${SHAKERSCAN_BIND_HOST:-127.0.0.1}"
    fi

    # Fleet operator traffic may use token-authenticated HTTP only when the
    # host has positively matched the bind address to its live Tailscale IPv4.
    # Recompute this on every invocation so a stale .env value fails closed.
    if [ -z "$tailscale_ip" ]; then
        tailscale_ip="$(first_tailscale_ipv4)"
    fi
    if [ -n "$tailscale_ip" ] && [ "${SHAKERSCAN_BIND_HOST:-}" = "$tailscale_ip" ]; then
        export SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT=tailscale
    elif [ "${SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT:-}" = "tailscale" ]; then
        unset SHAKERSCAN_TRUSTED_REMOTE_TRANSPORT
    fi

    export SHAKERSCAN_PUBLIC_API_URL="${SHAKERSCAN_PUBLIC_API_URL:-http://$(format_url_host "$(public_access_host)"):${SHAKERSCAN_API_PORT:-8080}}"
}

docker_info_available() {
    local direct_error=""
    DOCKER_NEEDS_SUDO=0
    DOCKER_INFO_ERROR=""

    if direct_error="$(docker info 2>&1 >/dev/null)"; then
        return 0
    fi

    if command_exists sudo && sudo -n docker info > /dev/null 2>&1; then
        DOCKER_NEEDS_SUDO=1
        return 0
    fi

    DOCKER_INFO_ERROR="$direct_error"
    return 1
}

docker_access_denied() {
    case "${DOCKER_INFO_ERROR:-}" in
        *"permission denied"*|*"Permission denied"*|*"access denied"*|*"Access denied"*|*"operation not permitted"*|*"Operation not permitted"*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

has_docker_compose_v2() {
    command_exists docker && docker compose version > /dev/null 2>&1
}

has_docker_compose_v1() {
    command_exists docker-compose
}

has_docker_compose() {
    has_docker_compose_v2 || has_docker_compose_v1
}

resolve_compose_command() {
    if [ ${#DOCKER_COMPOSE_CMD[@]} -gt 0 ]; then
        return 0
    fi

    if [ "$DOCKER_NEEDS_SUDO" -eq 1 ]; then
        if command_exists sudo && command_exists docker && sudo -n docker compose version > /dev/null 2>&1; then
            DOCKER_COMPOSE_CMD=(sudo docker compose)
            return 0
        fi

        if command_exists sudo && command_exists docker-compose && sudo -n docker-compose version > /dev/null 2>&1; then
            DOCKER_COMPOSE_CMD=(sudo docker-compose)
            return 0
        fi
    fi

    if has_docker_compose_v2; then
        DOCKER_COMPOSE_CMD=(docker compose)
        return 0
    fi

    if has_docker_compose_v1; then
        DOCKER_COMPOSE_CMD=(docker-compose)
        return 0
    fi

    return 1
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

update_compose_file_args() {
    if [ "$USE_PREBUILT" -eq 1 ]; then
        COMPOSE_FILE_ARGS=(-f "$PREBUILT_COMPOSE_FILE")
    else
        COMPOSE_FILE_ARGS=(-f docker-compose.yml)
    fi
}

compose() {
    if ! resolve_compose_command; then
        echo -e "${RED}Error: Docker Compose is not installed${NC}"
        return 1
    fi

    "${DOCKER_COMPOSE_CMD[@]}" "${COMPOSE_FILE_ARGS[@]}" "$@"
}

compose_up() {
    # Both runtime modes resolve their application images before startup:
    # release mode pulls the pinned set, while source mode builds the exact
    # checkout through build_local_images. Never let `up` independently choose
    # to pull or rebuild an application image.
    compose up --no-build "$@"
}

pull_prebuilt_images() {
    if [ "$USE_PREBUILT" -ne 1 ]; then
        return 0
    fi

    if ! is_truthy "${SHAKERSCAN_PULL_IMAGES:-1}"; then
        echo "Skipping prebuilt image pull because SHAKERSCAN_PULL_IMAGES=0"
        return 0
    fi

    echo -e "${BLUE}Pulling prebuilt Docker images...${NC}"
    if ! compose pull api worker ui model-intake-signer; then
        local image
        for image in \
            "${API_IMAGE_REPO}:${SCANNER_IMAGE_TAG}" \
            "${SCANNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}" \
            "${UI_IMAGE_REPO}:${SCANNER_IMAGE_TAG}" \
            "${MODEL_INTAKE_SIGNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"; do
            if ! docker image inspect "$image" >/dev/null 2>&1; then
                echo -e "${RED}Error: image pull failed and $image is not cached.${NC}" >&2
                echo "Check Docker Hub/network access and run './scanner.sh start' again." >&2
                return 1
            fi
        done
        echo -e "${YELLOW}Image pull failed; using the complete cached ${SCANNER_IMAGE_TAG} image set.${NC}"
        echo "Startup will still verify UI, API, and worker build identity before reporting ready."
    fi
}

compose_run() {
    compose run "$@"
}

api_base_url() {
    echo "http://$(format_url_host "$(public_access_host)"):${SHAKERSCAN_API_PORT:-8080}"
}

ui_base_url() {
    echo "http://$(format_url_host "$(public_access_host)"):${SHAKERSCAN_UI_PORT:-3000}"
}

probe_access_host() {
    local host="${SHAKERSCAN_BIND_HOST:-127.0.0.1}"
    case "$host" in
        ""|0.0.0.0) host="127.0.0.1" ;;
    esac
    echo "$host"
}

api_probe_url() {
    echo "http://$(format_url_host "$(probe_access_host)"):${SHAKERSCAN_API_PORT:-8080}"
}

ui_probe_url() {
    echo "http://$(format_url_host "$(probe_access_host)"):${SHAKERSCAN_UI_PORT:-3000}"
}

run_with_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return $?
    fi

    if command_exists sudo; then
        sudo "$@"
        return $?
    fi

    echo -e "${RED}Error: sudo is required to install dependencies${NC}"
    return 1
}

detect_platform() {
    PLATFORM="unsupported"
    PLATFORM_VERSION=""
    PLATFORM_ID=""
    PLATFORM_ID_LIKE=""
    PLATFORM_NAME=""
    PLATFORM_CODENAME=""
    PLATFORM_UBUNTU_CODENAME=""
    PLATFORM_WSL=0

    case "$(uname -s)" in
        Darwin)
            PLATFORM="macos"
            PLATFORM_VERSION="$(sw_vers -productVersion 2>/dev/null || echo "")"
            PLATFORM_ID="macos"
            PLATFORM_NAME="macOS"
            ;;
        Linux)
            PLATFORM="linux"
            if [ -f /etc/os-release ]; then
                # shellcheck disable=SC1091
                source /etc/os-release
                PLATFORM_ID="${ID:-linux}"
                PLATFORM_ID_LIKE="${ID_LIKE:-}"
                PLATFORM_NAME="${NAME:-Linux}"
                PLATFORM_VERSION="${VERSION_ID:-}"
                PLATFORM_CODENAME="${VERSION_CODENAME:-}"
                PLATFORM_UBUNTU_CODENAME="${UBUNTU_CODENAME:-}"
            else
                PLATFORM_ID="linux"
                PLATFORM_NAME="Linux"
                PLATFORM_VERSION="unknown"
            fi
            if [ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi "microsoft" /proc/version 2>/dev/null; then
                PLATFORM_WSL=1
            fi
            ;;
    esac
}

linux_id_matches() {
    local needle="$1"
    local id_like

    [ "$PLATFORM_ID" = "$needle" ] && return 0
    for id_like in $PLATFORM_ID_LIKE; do
        [ "$id_like" = "$needle" ] && return 0
    done

    return 1
}

platform_label() {
    if [ "$PLATFORM" = "macos" ]; then
        echo "macOS ${PLATFORM_VERSION:-}"
    elif [ "$PLATFORM" = "linux" ]; then
        if [ "$PLATFORM_WSL" -eq 1 ]; then
            echo "${PLATFORM_NAME:-Linux} ${PLATFORM_VERSION:-} (WSL)"
        else
            echo "${PLATFORM_NAME:-Linux} ${PLATFORM_VERSION:-}"
        fi
    else
        echo "unsupported"
    fi
}

detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists zypper; then
        echo "zypper"
    elif command_exists apk; then
        echo "apk"
    else
        echo ""
    fi
}

apt_has_package() {
    apt-cache show "$1" > /dev/null 2>&1
}

dnf_has_package() {
    local manager="$1"
    local package="$2"
    "$manager" list --available "$package" > /dev/null 2>&1
}

current_login_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER:-}" != "root" ]; then
        echo "$SUDO_USER"
    elif [ "$(id -u)" -ne 0 ]; then
        id -un
    else
        echo ""
    fi
}

start_docker_daemon_linux() {
    if ! command_exists docker; then
        return 0
    fi

    if command_exists systemctl; then
        run_with_sudo systemctl enable docker > /dev/null 2>&1 || true
        run_with_sudo systemctl start docker > /dev/null 2>&1 || true
    fi

    if ! docker_info_available && command_exists service; then
        run_with_sudo service docker start > /dev/null 2>&1 || true
    fi

    if ! docker_info_available && command_exists rc-service; then
        run_with_sudo rc-update add docker default > /dev/null 2>&1 || true
        run_with_sudo rc-service docker start > /dev/null 2>&1 || true
    fi
}

add_user_to_docker_group_if_needed() {
    local docker_user

    if ! command_exists getent || ! getent group docker > /dev/null 2>&1; then
        return 0
    fi

    docker_user="$(current_login_user)"
    if [ -z "$docker_user" ]; then
        return 0
    fi

    if ! id -nG "$docker_user" | grep -qw docker; then
        if command_exists usermod && run_with_sudo usermod -aG docker "$docker_user"; then
            echo -e "${YELLOW}$docker_user was added to the docker group. Log out/in or run 'newgrp docker' for permission changes.${NC}"
        elif command_exists addgroup && run_with_sudo addgroup "$docker_user" docker; then
            echo -e "${YELLOW}$docker_user was added to the docker group. Log out/in or run 'newgrp docker' for permission changes.${NC}"
        else
            echo -e "${YELLOW}Could not add $docker_user to the docker group automatically.${NC}"
            echo "You may need to run: sudo usermod -aG docker $docker_user"
        fi
    fi
}

install_packages_if_missing_apt() {
    local packages=()

    command_exists curl || packages+=("curl")
    command_exists jq || packages+=("jq")
    command_exists python3 || packages+=("python3")

    if [ ${#packages[@]} -gt 0 ]; then
        run_with_sudo apt-get update
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo apt-get install -y "${packages[@]}"
    fi
}

apt_docker_repo_family() {
    if [ "$PLATFORM_ID" = "ubuntu" ] || linux_id_matches ubuntu || [ -n "$PLATFORM_UBUNTU_CODENAME" ]; then
        echo "ubuntu"
    elif [ "$PLATFORM_ID" = "debian" ] || [ "$PLATFORM_ID" = "raspbian" ]; then
        echo "debian"
    else
        echo ""
    fi
}

apt_docker_repo_codename() {
    local family="$1"

    if [ "$family" = "ubuntu" ]; then
        echo "${PLATFORM_UBUNTU_CODENAME:-${PLATFORM_CODENAME:-}}"
    else
        echo "${PLATFORM_CODENAME:-}"
    fi
}

configure_docker_apt_repository() {
    local family
    local codename
    local repo_url
    local arch
    local temp_sources

    family="$(apt_docker_repo_family)"
    if [ -z "$family" ]; then
        return 1
    fi

    codename="$(apt_docker_repo_codename "$family")"
    if [ -z "$codename" ]; then
        echo -e "${YELLOW}Could not determine the $family codename for Docker's apt repository.${NC}"
        return 1
    fi

    repo_url="https://download.docker.com/linux/$family"
    echo -e "${GREEN}Configuring Docker apt repository for $family ($codename)...${NC}"

    run_with_sudo apt-get update
    run_with_sudo apt-get install -y ca-certificates curl
    run_with_sudo install -m 0755 -d /etc/apt/keyrings
    run_with_sudo curl -fsSL "$repo_url/gpg" -o /etc/apt/keyrings/docker.asc
    run_with_sudo chmod a+r /etc/apt/keyrings/docker.asc

    arch="$(dpkg --print-architecture)"
    temp_sources="$(mktemp)"
    {
        echo "Types: deb"
        echo "URIs: $repo_url"
        echo "Suites: $codename"
        echo "Components: stable"
        echo "Architectures: $arch"
        echo "Signed-By: /etc/apt/keyrings/docker.asc"
    } > "$temp_sources"
    run_with_sudo install -m 0644 "$temp_sources" /etc/apt/sources.list.d/docker.sources
    rm -f "$temp_sources"

    if ! run_with_sudo apt-get update; then
        echo -e "${YELLOW}Docker apt repository did not work for this release; removing it and trying distro packages.${NC}"
        run_with_sudo rm -f /etc/apt/sources.list.d/docker.sources || true
        return 1
    fi
}

install_docker_from_apt_repository() {
    local packages=()

    if ! command_exists docker; then
        packages+=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin")
    fi

    if ! has_docker_compose; then
        packages+=("docker-compose-plugin")
    fi

    if [ ${#packages[@]} -eq 0 ]; then
        return 0
    fi

    configure_docker_apt_repository || return 1
    echo -e "${GREEN}Installing Docker packages: ${packages[*]}${NC}"
    run_with_sudo apt-get install -y "${packages[@]}"
}

install_docker_from_apt_distro_packages() {
    local packages=()
    local compose_pkg=""

    run_with_sudo apt-get update

    if ! command_exists docker; then
        if apt_has_package docker.io; then
            packages+=("docker.io")
        elif apt_has_package docker; then
            packages+=("docker")
        else
            echo -e "${RED}Error: Could not find a Docker Engine package in apt repositories.${NC}"
            return 1
        fi
    fi

    if ! has_docker_compose; then
        if apt_has_package docker-compose-v2; then
            compose_pkg="docker-compose-v2"
        elif apt_has_package docker-compose-plugin; then
            compose_pkg="docker-compose-plugin"
        elif apt_has_package docker-compose; then
            compose_pkg="docker-compose"
        fi

        if [ -n "$compose_pkg" ]; then
            packages+=("$compose_pkg")
        else
            echo -e "${RED}Error: Could not find a Docker Compose package in apt repositories.${NC}"
            return 1
        fi
    fi

    if [ ${#packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo apt-get install -y "${packages[@]}"
    fi
}

install_dependencies_apt() {
    install_packages_if_missing_apt

    if ! command_exists docker || ! has_docker_compose; then
        if ! install_docker_from_apt_repository; then
            echo -e "${YELLOW}Falling back to distro Docker packages from apt.${NC}"
            install_docker_from_apt_distro_packages
        fi
    fi
}

dnf_docker_repo_url() {
    if [ "$PLATFORM_ID" = "fedora" ]; then
        echo "https://download.docker.com/linux/fedora/docker-ce.repo"
    elif [ "$PLATFORM_ID" = "rhel" ] || [ "$PLATFORM_ID" = "redhat" ]; then
        echo "https://download.docker.com/linux/rhel/docker-ce.repo"
    elif linux_id_matches rhel || linux_id_matches centos || [ "$PLATFORM_ID" = "rocky" ] || [ "$PLATFORM_ID" = "almalinux" ] || [ "$PLATFORM_ID" = "ol" ]; then
        echo "https://download.docker.com/linux/centos/docker-ce.repo"
    elif linux_id_matches fedora; then
        echo "https://download.docker.com/linux/fedora/docker-ce.repo"
    else
        echo ""
    fi
}

configure_docker_dnf_repository() {
    local manager="$1"
    local repo_url

    repo_url="$(dnf_docker_repo_url)"
    if [ -z "$repo_url" ]; then
        return 1
    fi

    echo -e "${GREEN}Configuring Docker rpm repository...${NC}"
    if [ "$manager" = "dnf" ]; then
        run_with_sudo dnf -y install dnf-plugins-core || true
    elif [ "$manager" = "yum" ]; then
        run_with_sudo yum -y install yum-utils || true
    fi

    run_with_sudo install -m 0755 -d /etc/yum.repos.d
    run_with_sudo curl -fsSL "$repo_url" -o /etc/yum.repos.d/docker-ce.repo
}

install_docker_from_dnf_repository() {
    local manager="$1"
    local packages=()

    if ! command_exists docker; then
        packages+=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin")
    fi

    if ! has_docker_compose; then
        packages+=("docker-compose-plugin")
    fi

    if [ ${#packages[@]} -eq 0 ]; then
        return 0
    fi

    configure_docker_dnf_repository "$manager" || return 1
    echo -e "${GREEN}Installing Docker packages: ${packages[*]}${NC}"
    if ! run_with_sudo "$manager" -y install "${packages[@]}"; then
        run_with_sudo rm -f /etc/yum.repos.d/docker-ce.repo || true
        return 1
    fi
}

install_docker_from_dnf_distro_packages() {
    local manager="$1"
    local packages=()
    local compose_pkg=""

    if ! command_exists docker; then
        if dnf_has_package "$manager" moby-engine; then
            packages+=("moby-engine")
        elif dnf_has_package "$manager" docker; then
            packages+=("docker")
        else
            echo -e "${RED}Error: Could not find a Docker Engine package in $manager repositories.${NC}"
            return 1
        fi
    fi

    if ! has_docker_compose; then
        if dnf_has_package "$manager" docker-compose-plugin; then
            compose_pkg="docker-compose-plugin"
        elif dnf_has_package "$manager" docker-compose; then
            compose_pkg="docker-compose"
        fi

        if [ -n "$compose_pkg" ]; then
            packages+=("$compose_pkg")
        else
            echo -e "${RED}Error: Could not find a Docker Compose package in $manager repositories.${NC}"
            return 1
        fi
    fi

    if [ ${#packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo "$manager" -y install "${packages[@]}"
    fi
}

install_dependencies_dnf() {
    local manager="$1"
    local base_packages=()

    command_exists curl || base_packages+=("curl")
    command_exists jq || base_packages+=("jq")
    command_exists python3 || base_packages+=("python3")

    if [ ${#base_packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${base_packages[*]}${NC}"
        run_with_sudo "$manager" -y install "${base_packages[@]}"
    fi

    if ! command_exists docker || ! has_docker_compose; then
        if ! install_docker_from_dnf_repository "$manager"; then
            echo -e "${YELLOW}Falling back to distro Docker packages from $manager.${NC}"
            install_docker_from_dnf_distro_packages "$manager"
        fi
    fi
}

install_dependencies_pacman() {
    local packages=()

    command_exists docker || packages+=("docker")
    has_docker_compose || packages+=("docker-compose")
    command_exists curl || packages+=("curl")
    command_exists jq || packages+=("jq")
    command_exists python3 || packages+=("python")

    if [ ${#packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo pacman -Sy --needed --noconfirm "${packages[@]}"
    fi
}

install_dependencies_zypper() {
    local packages=()

    command_exists docker || packages+=("docker")
    has_docker_compose || packages+=("docker-compose")
    command_exists curl || packages+=("curl")
    command_exists jq || packages+=("jq")
    command_exists python3 || packages+=("python3")

    if [ ${#packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo zypper --non-interactive install "${packages[@]}"
    fi
}

install_dependencies_apk() {
    local packages=()

    command_exists docker || packages+=("docker")
    has_docker_compose || packages+=("docker-cli-compose")
    command_exists curl || packages+=("curl")
    command_exists jq || packages+=("jq")
    command_exists python3 || packages+=("python3")

    if [ ${#packages[@]} -gt 0 ]; then
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo apk add "${packages[@]}"
    fi
}

install_dependencies_linux() {
    local package_manager

    echo "Detected: $(platform_label)"
    package_manager="$(detect_package_manager)"

    if [ "$PLATFORM_WSL" -eq 1 ]; then
        case "$package_manager" in
            apt)
                install_packages_if_missing_apt
                ;;
            dnf|yum)
                local base_packages=()
                command_exists curl || base_packages+=("curl")
                command_exists jq || base_packages+=("jq")
                command_exists python3 || base_packages+=("python3")
                if [ ${#base_packages[@]} -gt 0 ]; then
                    run_with_sudo "$package_manager" -y install "${base_packages[@]}"
                fi
                ;;
        esac

        if command_exists docker && has_docker_compose && docker_info_available; then
            return 0
        fi

        echo -e "${YELLOW}WSL detected. Use Docker Desktop for Windows with WSL integration enabled.${NC}"
        echo "After Docker Desktop is running, re-run: ./scanner.sh start"
        return 1
    fi

    case "$package_manager" in
        apt)
            install_dependencies_apt
            ;;
        dnf|yum)
            install_dependencies_dnf "$package_manager"
            ;;
        pacman)
            install_dependencies_pacman
            ;;
        zypper)
            install_dependencies_zypper
            ;;
        apk)
            install_dependencies_apk
            ;;
        *)
            echo -e "${RED}Automatic install is not supported for this Linux package manager.${NC}"
            echo "Install manually: Docker Engine + Docker Compose + curl + jq + Python 3"
            return 1
            ;;
    esac

    start_docker_daemon_linux
    add_user_to_docker_group_if_needed

    if command_exists docker && ! docker_info_available; then
        echo -e "${YELLOW}Docker installed, but the daemon is not reachable yet.${NC}"
        echo "If you were just added to the docker group, log out/in or run 'newgrp docker'."
    fi
}

ensure_homebrew_in_path() {
    if [ -x /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
}

install_homebrew_if_missing() {
    if command_exists brew; then
        ensure_homebrew_in_path
        return 0
    fi

    echo -e "${YELLOW}Homebrew not found. Installing Homebrew...${NC}"
    local curl_bin=""
    if [ -x /usr/bin/curl ]; then
        curl_bin="/usr/bin/curl"
    elif command_exists curl; then
        curl_bin="$(command -v curl)"
    else
        echo -e "${RED}Error: curl is required to install Homebrew on macOS${NC}"
        return 1
    fi

    NONINTERACTIVE=1 /bin/bash -c "$("$curl_bin" -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ensure_homebrew_in_path

    if ! command_exists brew; then
        echo -e "${RED}Error: Homebrew installation failed${NC}"
        return 1
    fi
}

install_dependencies_macos() {
    install_homebrew_if_missing

    if ! command_exists docker; then
        echo -e "${GREEN}Installing Docker Desktop...${NC}"
        if brew info --cask docker > /dev/null 2>&1; then
            brew install --cask docker
        else
            brew install --cask docker-desktop
        fi
    fi

    if ! has_docker_compose; then
        echo -e "${GREEN}Installing Docker Compose...${NC}"
        # Fallback for environments that do not provide the v2 plugin.
        brew install docker-compose
    fi

    if ! command_exists jq; then
        echo -e "${GREEN}Installing jq...${NC}"
        brew install jq
    fi

    if ! command_exists curl; then
        echo -e "${GREEN}Installing curl...${NC}"
        brew install curl
    fi

    if ! command_exists python3; then
        echo -e "${GREEN}Installing Python 3 for host-side MCP and legacy research adapters...${NC}"
        brew install python
    fi

    if command_exists docker && ! docker info > /dev/null 2>&1; then
        echo -e "${YELLOW}Docker daemon is not running. Launching Docker Desktop...${NC}"
        open -a Docker > /dev/null 2>&1 || true
    fi
}

install_dependencies() {
    detect_platform
    echo -e "${BLUE}Installing missing scanner dependencies...${NC}"

    case "$PLATFORM" in
        linux)
            install_dependencies_linux
            ;;
        macos)
            install_dependencies_macos
            ;;
        *)
            echo -e "${RED}Automatic install is supported on macOS and Linux hosts with apt, dnf/yum, pacman, zypper, or apk.${NC}"
            echo "Install manually: Docker Engine + Docker Compose + curl + jq + Python 3"
            return 1
            ;;
    esac

    # Reset compose command cache in case compose became available after install.
    DOCKER_COMPOSE_CMD=()
}

command_needs_docker_runtime() {
    case "$1" in
        start|stop|restart|status|scale|logs|gungnir|devices|build|rebuild|reset|shell)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

command_needs_curl() {
    local cmd="$1"
    local subcmd="$2"

    case "$cmd" in
        start|restart|status)
            return 0
            ;;
        gungnir)
            [ "${subcmd:-status}" = "status" ]
            return $?
            ;;
        devices)
            [ "${subcmd:-status}" = "status" ]
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

command_needs_jq() {
    command_needs_curl "$1" "$2"
}

command_needs_python() {
    case "$1" in
        scan|scan-full|scan-smart|mcp|research|report-rebuild)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

collect_missing_dependencies() {
    local cmd="$1"
    local subcmd="$2"
    local missing=()

    if command_needs_docker_runtime "$cmd"; then
        command_exists docker || missing+=("docker")
        has_docker_compose || missing+=("docker-compose")
    fi

    if command_needs_curl "$cmd" "$subcmd"; then
        command_exists curl || missing+=("curl")
    fi

    if command_needs_jq "$cmd" "$subcmd"; then
        command_exists jq || missing+=("jq")
    fi

    if command_needs_python "$cmd"; then
        command_exists python3 || missing+=("python3")
    fi

    echo "${missing[*]}"
}

confirm_install_missing() {
    if [ "$ASSUME_YES" -eq 1 ] || [ "${SCANNER_AUTO_INSTALL_DEPS:-0}" = "1" ]; then
        return 0
    fi

    if [ ! -t 0 ]; then
        return 1
    fi

    read -r -p "Install missing dependencies now? (y/N): " CONFIRM_INSTALL
    case "$CONFIRM_INSTALL" in
        y|Y|yes|YES)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

ensure_command_dependencies() {
    local cmd="$1"
    local subcmd="$2"
    local missing

    missing="$(collect_missing_dependencies "$cmd" "$subcmd")"
    if [ -n "$missing" ]; then
        echo -e "${YELLOW}Missing dependencies: $missing${NC}"

        if ! confirm_install_missing; then
            echo "Run './scanner.sh install-deps' to install prerequisites."
            return 1
        fi

        install_dependencies
        missing="$(collect_missing_dependencies "$cmd" "$subcmd")"
        if [ -n "$missing" ]; then
            echo -e "${RED}Error: Missing dependencies after install: $missing${NC}"
            return 1
        fi
    fi

    if command_needs_docker_runtime "$cmd"; then
        if ! docker_info_available; then
            if docker_access_denied; then
                echo -e "${RED}Error: Docker is running, but this user cannot access the Docker daemon.${NC}"
                echo "Details: ${DOCKER_INFO_ERROR}"
                echo "Fix Docker socket access (or Docker group membership on Linux), then retry."
                return 1
            fi
            detect_platform
            if [ "$PLATFORM" = "linux" ] && [ "$PLATFORM_WSL" -ne 1 ]; then
                echo -e "${YELLOW}Docker daemon is not running. Attempting to start Docker...${NC}"
                start_docker_daemon_linux
            elif [ "$PLATFORM" = "macos" ]; then
                echo -e "${YELLOW}Docker daemon is not running. Launching Docker Desktop...${NC}"
                open -a Docker > /dev/null 2>&1 || true
            fi
        fi

        if ! wait_for_docker_daemon 120; then
            echo -e "${RED}Error: Docker daemon is not running${NC}"
            if [ "$PLATFORM" = "macos" ]; then
                echo "Open Docker Desktop and wait until it is ready."
            elif [ "$PLATFORM" = "linux" ] && [ "$PLATFORM_WSL" -eq 1 ]; then
                echo "Open Docker Desktop for Windows and enable integration for this WSL distro."
            elif [ "$PLATFORM" = "linux" ]; then
                echo "Try: sudo systemctl start docker"
                echo "If Docker was just installed, log out/in or run 'newgrp docker' for group permissions."
            fi
            return 1
        fi
        DOCKER_COMPOSE_CMD=()

        if ! resolve_compose_command; then
            echo -e "${RED}Error: Docker Compose is not available${NC}"
            return 1
        fi

        # The source Compose contract uses service-level pull_policy to ensure
        # synthetic local application tags are never resolved from a registry.
        # Legacy docker-compose v1 does not implement that contract. Curl
        # installs use the release Compose file and retain the existing fallback.
        if [ "$USE_PREBUILT" -ne 1 ] && ! has_docker_compose_v2; then
            echo -e "${RED}Error: local source builds require Docker Compose v2.${NC}"
            echo "Install the Docker Compose plugin, then rerun './scanner.sh start --local'."
            return 1
        fi
    fi

    return 0
}

get_build_version() {
    if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        local commit
        commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        # Docker COPY and the source bind mounts include untracked runtime modules too.
        if [ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
            commit="${commit}-dirty"
        fi
        echo "$commit"
    else
        echo "dev"
    fi
}

get_release_version() {
    if [ -f "$SCRIPT_DIR/VERSION" ]; then
        local version
        version="$(head -n 1 "$SCRIPT_DIR/VERSION" | tr -d '[:space:]')"
        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi

    echo "dev"
}

set_build_env() {
    local local_commit
    local release_version
    local image_tag
    local_commit=$(get_build_version)
    release_version=$(get_release_version)
    image_tag="${SCANNER_IMAGE_TAG:-$DEFAULT_PREBUILT_IMAGE_TAG}"

    export SCANNER_RELEASE_VERSION="$release_version"
    export BUILD_GIT_COMMIT="$local_commit"
    export SHAKERSCAN_RUNTIME_DIR="$SCRIPT_DIR"
    # Docker Desktop bridge traffic can be excluded by a host VPN even while
    # the host itself has working egress. BuildKit host networking follows the
    # host route on macOS; this affects dependency-fetching build steps only,
    # never the network namespace of a running ShakerScan service. Operators
    # can override the choice explicitly when their Docker setup differs.
    if [ -z "${SHAKERSCAN_BUILD_NETWORK:-}" ]; then
        if [ "${PLATFORM:-}" = "macos" ]; then
            export SHAKERSCAN_BUILD_NETWORK="host"
        else
            export SHAKERSCAN_BUILD_NETWORK="default"
        fi
    fi
    if [ -d "$SCRIPT_DIR/.git" ]; then
        export SHAKERSCAN_INSTALL_KIND="source_checkout"
    else
        export SHAKERSCAN_INSTALL_KIND="curl_install"
    fi

    if [ "$USE_PREBUILT" -eq 1 ]; then
        export SCANNER_VERSION="$image_tag"
        export GIT_COMMIT="${SCANNER_IMAGE_COMMIT:-image:${image_tag}}"
        export NEXT_PUBLIC_APP_VERSION="$image_tag"
    else
        export SCANNER_VERSION="$local_commit"
        export GIT_COMMIT="$local_commit"
        export NEXT_PUBLIC_APP_VERSION="$local_commit"
    fi
}

has_local_source_tree() {
    [ -f "$SCRIPT_DIR/docker-compose.yml" ] && \
        [ -f "$SCRIPT_DIR/scanner/Dockerfile" ] && \
        [ -f "$SCRIPT_DIR/scanner/Dockerfile.api" ] && \
        [ -f "$SCRIPT_DIR/ui/Dockerfile" ]
}

configure_runtime_mode() {
    local command="$1"
    local persisted_mode=""
    local release_version

    release_version="$(get_release_version)"

    if [ -n "${SCANNER_USE_PREBUILT:-}" ]; then
        RUNTIME_MODE_EXPLICIT=1
        if is_truthy "${SCANNER_USE_PREBUILT}"; then
            USE_PREBUILT=1
        else
            USE_PREBUILT=0
        fi
    fi

    if is_truthy "${SCANNER_LOCAL_BUILD:-0}"; then
        RUNTIME_MODE_EXPLICIT=1
        USE_PREBUILT=0
    fi

    if [ -n "$IMAGE_TAG_OVERRIDE" ]; then
        export SCANNER_IMAGE_TAG="$IMAGE_TAG_OVERRIDE"
    fi

    export SCANNER_IMAGE_REPO="${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}"
    export API_IMAGE_REPO="${API_IMAGE_REPO:-shakerscan/shakerscan-api}"
    export UI_IMAGE_REPO="${UI_IMAGE_REPO:-shakerscan/shakerscan-ui}"
    export MODEL_INTAKE_SIGNER_IMAGE_REPO="${MODEL_INTAKE_SIGNER_IMAGE_REPO:-shakerscan/shakerscan-model-intake-signer}"
    export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shakerscan}"
    # The source Compose file consumes this exact image identity. Keeping the
    # build and sandbox retag on one explicit contract avoids guessing a tag
    # synthesized independently from the build configuration.
    export SCANNER_LOCAL_WORKER_IMAGE="${SCANNER_LOCAL_WORKER_IMAGE:-${COMPOSE_PROJECT_NAME}-worker:local}"
    export SCANNER_RELEASE_VERSION="$release_version"
    if [ -z "${SCANNER_IMAGE_TAG:-}" ]; then
        if [ -n "$release_version" ] && [ "$release_version" != "dev" ]; then
            export SCANNER_IMAGE_TAG="$release_version"
        else
            export SCANNER_IMAGE_TAG="$DEFAULT_PREBUILT_IMAGE_TAG"
        fi
    else
        export SCANNER_IMAGE_TAG
    fi

    if [ -f "$LOCAL_BUILD_MARKER" ]; then
        persisted_mode="$(head -n 1 "$LOCAL_BUILD_MARKER" 2>/dev/null | tr -d '[:space:]')"
    fi

    if [ "$RUNTIME_MODE_EXPLICIT" -eq 0 ]; then
        case "$persisted_mode" in
            local)
                # Never let stale runtime state turn a source-less curl install
                # into a local build that it cannot perform.
                if has_local_source_tree; then
                    USE_PREBUILT=0
                else
                    USE_PREBUILT=1
                fi
                ;;
            prebuilt) USE_PREBUILT=1 ;;
            *)
                # A full source tree defaults to local builds. Curl installs
                # intentionally omit these files and therefore stay prebuilt.
                if has_local_source_tree; then
                    USE_PREBUILT=0
                fi
                ;;
        esac
    fi

    case "$command" in
        build|rebuild)
            USE_PREBUILT=0
            ;;
    esac

    if [ "$USE_PREBUILT" -eq 1 ] && [ ! -f "$SCRIPT_DIR/$PREBUILT_COMPOSE_FILE" ]; then
        echo -e "${YELLOW}Prebuilt override file missing ($PREBUILT_COMPOSE_FILE). Falling back to local build mode.${NC}"
        USE_PREBUILT=0
    fi

    update_compose_file_args
}

record_runtime_mode() {
    local mode="$1"
    local tmp="${LOCAL_BUILD_MARKER}.tmp.$$"

    case "$mode" in
        local|prebuilt) ;;
        *)
            echo -e "${RED}Error: invalid runtime mode '$mode'${NC}" >&2
            return 1
            ;;
    esac

    printf '%s\n' "$mode" > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$LOCAL_BUILD_MARKER"
}

total_memory_gb() {
    local kb
    local bytes

    if command_exists getconf; then
        local pages
        local page_size
        pages="$(getconf _PHYS_PAGES 2>/dev/null || echo "")"
        page_size="$(getconf PAGE_SIZE 2>/dev/null || echo "")"
        if [[ "$pages" =~ ^[0-9]+$ ]] && [[ "$page_size" =~ ^[0-9]+$ ]]; then
            echo $(( (pages * page_size + 1073741823) / 1073741824 ))
            return 0
        fi
    fi

    if [ -r /proc/meminfo ]; then
        kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")"
        if [[ "$kb" =~ ^[0-9]+$ ]]; then
            echo $(( (kb + 1048575) / 1048576 ))
            return 0
        fi
    fi

    if command_exists sysctl; then
        bytes="$(sysctl -n hw.memsize 2>/dev/null || echo "")"
        if [[ "$bytes" =~ ^[0-9]+$ ]]; then
            echo $(( (bytes + 1073741823) / 1073741824 ))
            return 0
        fi
    fi

    echo 0
}

runtime_memory_gb() {
    local bytes
    local host_memory_gb

    # Docker Desktop and VM-backed engines can expose substantially less memory
    # than the host. Size the fleet against the memory the containers can
    # actually use, then fall back to host RAM when Docker cannot report it.
    if command_exists docker; then
        bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "")"
        if [[ "$bytes" =~ ^[0-9]+$ ]] && [ "$bytes" -gt 0 ]; then
            # Round down so the startup fleet never spends a fractional GB that
            # the API's Docker-memory calculation correctly leaves unavailable.
            echo $(( bytes / 1073741824 ))
            return 0
        fi
    fi

    host_memory_gb="$(total_memory_gb)"
    echo "${host_memory_gb:-0}"
}

auto_workers_for_memory_gb() {
    local memory_gb="${1:-0}"
    local platform_reserve_gb="${SHAKERSCAN_PLATFORM_MEMORY_RESERVE_GB:-7}"
    local per_worker_gb="${SHAKERSCAN_PER_WORKER_MEM_GB:-1}"
    local auto_worker_max="${SHAKERSCAN_AUTO_WORKER_MAX:-}"
    local workers

    # A developer laptop gains little from launching a server-sized fleet at every
    # restart. Docker Desktop often exposes most of a large Mac's RAM, which used to
    # turn the memory formula into 16-20 Python workers and made migrations/imports
    # needlessly noisy. Linux servers keep the existing capacity-based ceiling; Mac
    # operators can still opt in to more workers with --workers or this environment
    # override.
    if [ -z "$auto_worker_max" ]; then
        if [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]; then
            auto_worker_max=5
        else
            auto_worker_max=20
        fi
    fi
    if ! [[ "$auto_worker_max" =~ ^[0-9]+$ ]] || [ "$auto_worker_max" -lt 1 ]; then
        auto_worker_max=20
    fi
    [ "$auto_worker_max" -gt 20 ] && auto_worker_max=20

    if ! [[ "$memory_gb" =~ ^[0-9]+$ ]] || [ "$memory_gb" -le 0 ]; then
        echo 5
        return 0
    fi
    if ! [[ "$platform_reserve_gb" =~ ^[0-9]+$ ]]; then
        platform_reserve_gb=7
    fi
    if ! [[ "$per_worker_gb" =~ ^[0-9]+$ ]] || [ "$per_worker_gb" -lt 1 ]; then
        per_worker_gb=1
    fi

    # Very small installations cannot safely carry five scanner processes.
    # Normal sub-16GB installations get a predictable five-worker fleet.
    if [ "$memory_gb" -lt 8 ]; then
        workers=$((memory_gb - 3))
        [ "$workers" -lt 1 ] && workers=1
    elif [ "$memory_gb" -lt 16 ]; then
        workers=5
    else
        # Reserve memory for Docker/the OS plus PostgreSQL, Redis, API and UI,
        # then spend the remaining budget at roughly 1GB per scanner worker.
        workers=$(( (memory_gb - platform_reserve_gb) / per_worker_gb ))
        [ "$workers" -lt 5 ] && workers=5
    fi

    [ "$workers" -gt "$auto_worker_max" ] && workers="$auto_worker_max"
    echo "$workers"
}

resolve_start_workers() {
    local memory_gb

    if [ "$WORKERS" != "auto" ]; then
        if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ] || [ "$WORKERS" -gt 20 ]; then
            echo -e "${RED}Error: workers must be auto or a number between 1 and 20${NC}" >&2
            return 1
        fi
        echo "$WORKERS"
        return 0
    fi

    memory_gb="$(runtime_memory_gb)"
    auto_workers_for_memory_gb "$memory_gb"
}

# Set a directory's mode, tolerating one a container already owns.
# A mode we cannot set is only fatal if the directory is also unusable, and that
# surfaces as a real error where it is used rather than as a dead CLI.
ensure_directory_mode() {
    local path="$1"
    local mode="$2"
    [ -d "$path" ] || return 0
    if ! chmod "$mode" "$path" 2>/dev/null; then
        if [ ! -w "$path" ] && [ ! -O "$path" ]; then
            echo -e "${YELLOW}Note: $path is owned by another user (usually the container runtime); leaving its permissions unchanged.${NC}" >&2
        fi
    fi
    return 0
}

prepare_runtime_files() {
    detect_platform
    export SHAKERSCAN_HOST_PLATFORM="$PLATFORM"
    write_dotenv_value SHAKERSCAN_HOST_PLATFORM "$SHAKERSCAN_HOST_PLATFORM"
    local sandbox_uid sandbox_gid
    sandbox_uid="$(id -u)"
    sandbox_gid="$(id -g)"
    # Root-run Linux installs still execute the isolated service as the image's
    # unprivileged scanner account. Non-root and Docker Desktop installs use the
    # host operator identity so the bind mount never needs world-write access.
    if [ "$sandbox_uid" = "0" ]; then
        sandbox_uid=10001
        sandbox_gid=10001
    elif [ -d results/model-intake-sandbox ] && [ ! -L results/model-intake-sandbox ]; then
        # Preserve the durable private-queue identity across an upgrade launched
        # by a different host account (notably old root-run installs using 10001).
        local existing_sandbox_uid existing_sandbox_gid
        existing_sandbox_uid="$(stat -c '%u' results/model-intake-sandbox 2>/dev/null || stat -f '%u' results/model-intake-sandbox 2>/dev/null || true)"
        existing_sandbox_gid="$(stat -c '%g' results/model-intake-sandbox 2>/dev/null || stat -f '%g' results/model-intake-sandbox 2>/dev/null || true)"
        if [ -n "$existing_sandbox_uid" ] && [ "$existing_sandbox_uid" != "0" ]; then
            sandbox_uid="$existing_sandbox_uid"
            sandbox_gid="$existing_sandbox_gid"
        fi
    fi
    export MODEL_INTAKE_SANDBOX_UID="$sandbox_uid"
    export MODEL_INTAKE_SANDBOX_GID="$sandbox_gid"
    write_dotenv_value MODEL_INTAKE_SANDBOX_UID "$MODEL_INTAKE_SANDBOX_UID"
    write_dotenv_value MODEL_INTAKE_SANDBOX_GID "$MODEL_INTAKE_SANDBOX_GID"
    mkdir -p results
    mkdir -p results/model-intake-quarantine results/model-intake-sandbox
    mkdir -p .shakerscan-model-intake-runner-stage
    # These directories only need their mode set when this user created them.
    # The Model Intake worker runs as root and takes ownership of the quarantine
    # tree as soon as it stores its first artifact, after which chmod from the
    # host user fails -- and an unguarded failure here aborted every later
    # scanner.sh invocation, including start, restart, and rebuild.
    ensure_directory_mode results/model-intake-quarantine 755
    if [ "$(id -u)" = "0" ]; then
        chown "$MODEL_INTAKE_SANDBOX_UID:$MODEL_INTAKE_SANDBOX_GID" results/model-intake-sandbox
    fi
    ensure_directory_mode results/model-intake-sandbox 700
    # Only the API stages trusted runner inputs here. Workers never mount this
    # directory, so model-controlled scan output cannot replace a staged guest.
    ensure_directory_mode .shakerscan-model-intake-runner-stage 700
    mkdir -p .shakerscan-fleet
    ensure_directory_mode .shakerscan-fleet 700
    ensure_runtime_datastore_credentials
    ensure_model_intake_operator_credential
    ensure_model_intake_local_session_secret
    ensure_model_intake_signer_credentials

    if [ "$USE_PREBUILT" -eq 1 ]; then
        mkdir -p db

        if [ ! -f "$SCRIPT_DIR/$PREBUILT_COMPOSE_FILE" ]; then
            echo -e "${RED}Error: $PREBUILT_COMPOSE_FILE is missing.${NC}"
            echo "Re-run the installer or clone the repository again."
            return 1
        fi

        if [ ! -f "$SCRIPT_DIR/db/init.sql" ]; then
            echo -e "${RED}Error: db/init.sql is missing.${NC}"
            echo "Re-run the installer or clone the repository again."
            return 1
        fi
    elif [ ! -f "$SCRIPT_DIR/scanner/Dockerfile" ] || \
         [ ! -f "$SCRIPT_DIR/scanner/Dockerfile.api" ] || \
         [ ! -f "$SCRIPT_DIR/ui/Dockerfile" ]; then
        echo -e "${RED}Error: local build mode requires a full source checkout.${NC}"
        echo "Run from a clone of https://github.com/andriyze/shakerscan.git or omit --local to use Docker Hub images."
        return 1
    fi
}

wait_for_docker_daemon() {
    local timeout="${1:-120}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if docker_info_available; then
            return 0
        fi
        if docker_access_denied; then
            echo -e "${RED}Error: Docker is running, but this user cannot access the Docker daemon.${NC}"
            echo "Details: ${DOCKER_INFO_ERROR}"
            return 1
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        if [ $((elapsed % 10)) -eq 0 ]; then
            echo "Waiting for Docker daemon... ${elapsed}s"
        fi
    done

    return 1
}

wait_for_url() {
    local label="$1"
    local url="$2"
    local timeout="${3:-120}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if curl -fsS "$url" > /dev/null 2>&1; then
            echo -e "${GREEN}$label is ready${NC}"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    echo -e "${YELLOW}$label did not become ready within ${timeout}s.${NC}"
    return 1
}

build_versions_match() {
    local left="${1%-dirty}"
    local right="${2%-dirty}"
    local shared
    [ -n "$left" ] && [ -n "$right" ] || return 1
    [ "$left" = "$right" ] && return 0
    [[ "$left" =~ ^[0-9a-fA-F]+$ ]] && [[ "$right" =~ ^[0-9a-fA-F]+$ ]] || return 1
    if [ "${#left}" -lt "${#right}" ]; then
        shared="${right:0:${#left}}"
        [ "${#left}" -ge 7 ] && [ "$left" = "$shared" ]
    else
        shared="${left:0:${#right}}"
        [ "${#right}" -ge 7 ] && [ "$right" = "$shared" ]
    fi
}

verify_running_build_identity() {
    local expected="${SCANNER_VERSION:-}"
    local api_json ui_json api_version ui_version worker_version
    local elapsed=0 timeout="${SHAKERSCAN_BUILD_IDENTITY_TIMEOUT:-90}"

    while [ "$elapsed" -lt "$timeout" ]; do
        api_json="$(curl -fsS "$(api_probe_url)/health" 2>/dev/null || true)"
        ui_json="$(curl -fsS "$(ui_probe_url)/api/build-identity" 2>/dev/null || true)"
        api_version="$(printf '%s' "$api_json" | jq -r '.scanner_version // empty' 2>/dev/null || true)"
        ui_version="$(printf '%s' "$ui_json" | jq -r '.ui_version // empty' 2>/dev/null || true)"
        worker_version="$(printf '%s' "$api_json" | jq -r '.worker_build.scanner_version // empty' 2>/dev/null || true)"

        if build_versions_match "$expected" "$api_version" \
            && build_versions_match "$expected" "$ui_version" \
            && [ "$(printf '%s' "$api_json" | jq -r '.worker_build.available == true and .worker_build.fleet_uniform == true and (.worker_build.stale_count // 0) == 0 and (.worker_build.pending_count // 0) == 0' 2>/dev/null || true)" = "true" ] \
            && build_versions_match "$expected" "$worker_version"; then
            echo -e "${GREEN}Build identity verified: UI, API, and workers are $expected${NC}"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    echo -e "${RED}Error: the running ShakerScan components do not share one build identity.${NC}" >&2
    echo "  expected: ${expected:-unknown}" >&2
    echo "  UI:      ${ui_version:-unavailable}" >&2
    echo "  API:     ${api_version:-unavailable}" >&2
    echo "  workers: ${worker_version:-unavailable}" >&2
    echo "Startup failed closed. Re-run './scanner.sh start' after correcting image or worker pull failures." >&2
    return 1
}

verify_specialized_worker_identity() {
    local expect_agent="${1:-0}"
    local expect_device="${2:-0}"
    local health agent_status device_status elapsed=0
    local timeout="${SHAKERSCAN_BUILD_IDENTITY_TIMEOUT:-90}"

    [ "$expect_agent" -gt 0 ] || [ "$expect_device" -gt 0 ] || return 0
    while [ "$elapsed" -lt "$timeout" ]; do
        health="$(curl -fsS "$(api_probe_url)/health" 2>/dev/null || true)"
        agent_status="$(printf '%s' "$health" | jq -r '.agent_tool_worker.status // empty' 2>/dev/null || true)"
        device_status="$(printf '%s' "$health" | jq -r '.device_worker.status // empty' 2>/dev/null || true)"
        if { [ "$expect_agent" -lt 1 ] || [ "$agent_status" = "ready" ]; } \
            && { [ "$expect_device" -lt 1 ] || [ "$device_status" = "ready" ]; }; then
            echo -e "${GREEN}Specialized worker identity verified${NC}"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo -e "${RED}Error: specialized worker build identity did not converge.${NC}" >&2
    echo "  agent scanner: ${agent_status:-unavailable}" >&2
    echo "  device worker: ${device_status:-not requested}" >&2
    return 1
}

confirm_active_testing() {
    local scan_name="$1"
    local target="$2"

    if [ "$CONFIRM_ACTIVE" -eq 1 ]; then
        return 0
    fi

    echo -e "${YELLOW}Warning: $scan_name includes active vulnerability probes against $target.${NC}"
    if [ ! -t 0 ]; then
        echo "Re-run with --confirm-active after confirming you own or are authorized to test this target."
        return 1
    fi

    read -r -p "Confirm you have authorization to actively test this target? Type 'yes': " CONFIRM_SCAN
    [ "$CONFIRM_SCAN" = "yes" ]
}

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     ShakerScan - Open Source Edition   ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    print_banner
    echo "Usage: ./scanner.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  start              Start all services (API, workers, UI)"
    echo "  stop               Stop all services"
    echo "  restart            Restart all services"
    echo "  reload             Reload edited source in local-build mode + verify parity"
    echo "  status             Show services, queue, workers, and access URLs"
    echo "  scale <N>          Scale to N workers (1-20)"
    echo "  logs [service]     View logs (api, worker, ui, postgres, redis)"
    echo "                       worker aggregates all shakerscan-worker* containers"
    echo "  scan <target>      Submit the deterministic DAST Scan"
    echo "  hunt <cmd>         Start or drive one canonical Hunt"
    echo "  credentials <cmd>  Create, rotate, or admission-test encrypted profiles"
    echo "  collections <cmd>  Upload, bind, or select request collections"
    echo "  evidence export    Export content-free evidence manifests or bundles"
    echo "  report-rebuild <bundle>  Rebuild a deterministic report fully offline"
    echo "  install-deps       Install missing prerequisites"
    echo "  doctor             Check local prerequisites and common startup issues"
    echo "  env                Show PATH, launcher, and runtime guidance"
    echo "  agent [name]       Start Codex, Claude, or OpenCode in this runtime dir"
    echo "  mcp                Start the read-only Command Arsenal MCP stdio adapter"
    echo "  research <id> [N]  Run up to N bounded Codex decisions for a research episode"
    echo "  gungnir <cmd>      CT monitor: start, stop, status, logs"
    echo "  devices <cmd>      Opt-in device worker: start, stop, restart, status, logs"
    echo "  fleet init [...]   Initialize a WireGuard or outbound-HTTPS broker fleet"
    echo "  fleet preflight    Validate fleet prerequisites without changing state"
    echo "  fleet join-token   Mint a bounded ready-to-paste worker join command"
    echo "  fleet revoke-join-token  Revoke unused enrollment-token capacity"
    echo "  fleet reconcile    Reconcile registered workers into local WireGuard state"
    echo "  fleet accept       Run physical multi-node acceptance checks"
    echo "  join <url> [...]   Join this Linux host as a worker-only fleet node"
    echo "  model-intake-runner status   Report microVM (Firecracker/KVM) host capability"
    echo "  model-intake-runner install  Opt-in install of the Model Intake microVM tier (root)"
    echo "  build              Build Docker images"
    echo "  rebuild [opts]     Rebuild Docker images (cached by default)"
    echo "                       --no-cache  Full rebuild (slow, 10-20 min)"
    echo "                       scanner     Rebuild scanner/worker only"
    echo "                       ui          Rebuild UI only"
    echo "  backup [dir]       Back up PostgreSQL, results, config, and release metadata"
    echo "  reset              Reset database (WARNING: deletes all data)"
    echo "  shell              Open shell in scanner container"
    echo ""
    echo "Deprecated compatibility aliases (sunset 2026-12-31):"
    echo "  scan-full <target> Translates to 'scan --budget-profile thorough --active-testing'"
    echo "  scan-smart <target> Translates to the same deterministic Scan contract"
    echo ""
    echo "Options:"
    echo "  -w, --workers N    Number of workers (default: $WORKERS)"
    echo "  -f, --follow       Follow logs"
    echo "  -y, --yes          Auto-confirm dependency installation"
    echo "  --local            Force local Docker build instead of prebuilt images"
    echo "  --prebuilt         Force prebuilt Docker Hub images (default for curl installs)"
    echo "  --image-tag TAG    Override Docker image tag (default: latest)"
    echo "  --remote           Bind UI/API to this host's Tailscale IPv4 address"
    echo "  --confirm-active   Confirm authorization when --active-testing is enabled"
    echo "  Scan-specific options are listed by './scanner.sh scan --help'"
    echo "  SHAKERSCAN_BIND_HOST=IP overrides the Docker bind address"
    echo "  SHAKERSCAN_DATA_BIND_HOST=IP separately binds local Redis/Postgres (default: 127.0.0.1)"
    echo "  SHAKERSCAN_PUBLIC_HOST=HOST overrides displayed/browser API host"
    echo "  SHAKERSCAN_PULL_IMAGES=0 skips Docker Hub pulls in prebuilt mode"
    echo ""
    echo "Auto-install support:"
    echo "  macOS; Linux with apt, dnf/yum, pacman, zypper, or apk"
    echo ""
    echo "Examples:"
    echo "  ./scanner.sh start                    # Source checkout: local build; curl install: prebuilt"
    echo "  ./scanner.sh start -y                 # Install prerequisites if missing, then start"
    echo "  ./scanner.sh start --remote           # VPS access over Tailscale"
    echo "  ./scanner.sh env                      # Show PATH and agent launch commands"
    echo "  ./scanner.sh agent codex              # Start an AI agent with local docs loaded"
    echo "  ./scanner.sh research <episode-id> 5  # Drive a bounded research episode"
    echo "  ./scanner.sh fleet init --endpoint fleet.example.com:51820 --public-url https://fleet.example.com"
    echo "  ./scanner.sh fleet init --network broker --public-url https://fleet.example.com"
    echo "  ./scanner.sh fleet join-token --ttl 24h"
    echo "  ./scanner.sh fleet join-token --ttl 1h --max-uses 5 --transport broker"
    echo "  ./scanner.sh start --local            # Build locally and start"
    echo "  ./scanner.sh start -w 10              # Start with 10 workers"
    echo "  ./scanner.sh start --image-tag $(get_release_version)  # Use this release's published tag"
    echo "  ./scanner.sh scale 10                 # Scale to 10 workers"
    echo "  ./scanner.sh scan https://example.com --budget-profile balanced"
    echo "  ./scanner.sh scan https://example.com --budget-profile thorough --active-testing --confirm-active"
    echo "  ./scanner.sh install-deps             # Install dependencies"
    echo "  ./scanner.sh logs worker -f           # Follow worker logs"
    echo ""
    echo "Access:"
    echo "  UI:  $(ui_base_url)"
    echo "  API: $(api_base_url)"
}

start_services() {
    local start_workers
    local requested_workers="${1:-}"

    prepare_runtime_files
    persist_remote_access_env
    if [ -n "$requested_workers" ]; then
        start_workers="$requested_workers"
    else
        start_workers="$(resolve_start_workers)"
    fi
    set_build_env
    echo -e "${GREEN}Starting ShakerScan with $start_workers worker(s)...${NC}"
    if [ "$WORKERS" = "auto" ]; then
        echo "Worker sizing: auto ($(runtime_memory_gb)GB container RAM; ${SHAKERSCAN_PLATFORM_MEMORY_RESERVE_GB:-7}GB platform reserve; ${SHAKERSCAN_PER_WORKER_MEM_GB:-1}GB/worker)"
    fi
    if [ "$USE_PREBUILT" -eq 1 ]; then
        echo "Mode: prebuilt images"
        echo "  api:     ${API_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        echo "  scanner: ${SCANNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        echo "  ui:      ${UI_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        pull_prebuilt_images
    else
        echo "Mode: local build"
        if local_application_images_ready; then
            echo -e "${GREEN}Using the complete application image set from the successful full build receipt.${NC}"
        else
            echo -e "${GREEN}Building application images from this checkout...${NC}"
            build_local_images
            record_runtime_mode local
        fi
    fi
    compose_up -d --scale worker=$start_workers
    echo ""
    wait_for_url "API" "$(api_probe_url)/health" 120
    wait_for_url "UI" "$(ui_probe_url)" 120
    verify_running_build_identity
    verify_specialized_worker_identity \
        "$(running_compose_service_count agent-tool-worker)" \
        "$(running_device_worker_count)"
    if [ "$USE_PREBUILT" -eq 1 ]; then
        record_runtime_mode prebuilt
    fi
    echo -e "${GREEN}Services started.${NC}"
    echo "  UI:  $(ui_base_url)"
    echo "  API: $(api_base_url)"
    echo ""
    echo "Use './scanner.sh status' to check service health"
    echo "Use './scanner.sh logs -f' to follow logs"
}

stop_services() {
    echo -e "${YELLOW}Stopping ShakerScan...${NC}"
    compose down
    remove_scan_worker_containers "Removing API-scaled worker containers left outside Compose..."
    echo -e "${GREEN}Services stopped${NC}"
}

restart_services() {
    local restart_workers
    prepare_runtime_files
    restart_workers="$(restart_worker_count)"
    stop_services
    start_services "$restart_workers"
}

# Reload source into running containers without a full stop/start.
#
# On macOS Docker, single-file bind mounts (scanner.py and the top-level
# scanner modules in docker-compose.yml) do NOT reliably propagate host edits
# to running containers — editor rename-replace leaves the container on a
# stale inode, so scans silently run old code. A graceful `compose restart`
# re-resolves the mounts. This command does that and verifies host<->container
# parity so drift is caught loudly instead of debugged for an hour.
reload_services() {
    if [ "$USE_PREBUILT" -eq 1 ]; then
        echo -e "${RED}Error: reload is only available in local-build mode.${NC}"
        echo "Published images do not mount editable source. Use './scanner.sh restart' to refresh prebuilt services,"
        echo "or switch a source checkout to local mode with './scanner.sh start --local'."
        return 1
    fi

    echo -e "${BLUE}Reloading source into running containers...${NC}"
    compose restart api worker || return 1

    # API-scaled workers (created by the /workers scaler, not compose) are not
    # covered by `compose restart worker`; restart them directly.
    local scaled
    scaled=$(running_scan_worker_containers)
    for w in $scaled; do
        docker restart "$w" >/dev/null 2>&1 || true
    done

    # Preserve opt-in isolation while keeping an already-running device worker
    # on the same live source as the API and ordinary workers.
    if [ "$(running_device_worker_count)" -gt 0 ]; then
        compose --profile devices restart device-worker || return 1
    fi

    # Agent scanner workers mount the same editable API/scanner trees. Restart
    # this isolated lane too, otherwise a reload can leave Deep Hunt executing
    # old broker or accounting code while the API advertises the new contract.
    if [ "$(running_compose_service_count agent-tool-worker)" -gt 0 ]; then
        compose restart agent-tool-worker || return 1
    fi

    # Verify host<->container parity for the single-file-mounted modules.
    local host_sha cont_sha drift=0 worker
    worker=$(running_scan_worker_containers | head -n1)
    if [ -n "$worker" ]; then
        sleep 4
        for f in scanner.py constants.py grading.py findings.py reporting.py signals.py target_context.py; do
            host_sha=$(shasum -a 256 "$SCRIPT_DIR/scanner/$f" 2>/dev/null | awk '{print $1}')
            cont_sha=$(docker exec "$worker" sha256sum "/app/$f" 2>/dev/null | awk '{print $1}')
            if [ -n "$host_sha" ] && [ "$host_sha" != "$cont_sha" ]; then
                echo -e "  ${YELLOW}drift${NC} $f (host $host_sha != container $cont_sha)"
                drift=1
            fi
        done
        if [ "$drift" -eq 0 ]; then
            echo -e "  ${GREEN}ok${NC} container source matches host"
        else
            echo -e "  ${YELLOW}Some modules still differ; try '${NC}./scanner.sh restart${YELLOW}' for a full recreate.${NC}"
        fi
    fi
}

show_status() {
    local broker_state="$SCRIPT_DIR/.shakerscan-fleet/node/state.json"
    local broker_env="$SCRIPT_DIR/.shakerscan-fleet/node/compose.env"
    if [ -f "$broker_state" ] && [ "$(jq -r '.transport // empty' "$broker_state" 2>/dev/null)" = "broker" ]; then
        local node_id control_plane project_name
        node_id="$(jq -r '.node_id // "unknown"' "$broker_state")"
        control_plane="$(jq -r '.control_plane_url // "unknown"' "$broker_state")"
        project_name="$(awk -F= '$1 == "FLEET_COMPOSE_PROJECT_NAME" {print $2}' "$broker_env" 2>/dev/null | tail -1)"
        echo -e "${BLUE}Service Status:${NC}"
        echo -e "Runtime Role: ${GREEN}Fleet broker worker node${NC}"
        echo "  Node ID:       $node_id"
        echo "  Control plane: $control_plane"
        if [ -n "$project_name" ]; then
            echo ""
            docker ps --filter "label=com.docker.compose.project=$project_name" \
                --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
        fi
        echo ""
        echo "Local API/UI: not installed on an outbound-only broker node (expected)"
        return 0
    fi

    local api_url
    api_url="$(api_probe_url)"
    echo -e "${BLUE}Service Status:${NC}"
    compose ps
    echo ""

    # Check API health
    if curl -s "$api_url/health" > /dev/null 2>&1; then
        HEALTH=$(curl -s "$api_url/health")
        echo -e "API Health: ${GREEN}$(echo $HEALTH | jq -r '.status')${NC}"
        echo "  Database: $(echo $HEALTH | jq -r '.database')"
        echo "  Redis: $(echo $HEALTH | jq -r '.redis')"
    else
        echo -e "API Health: ${RED}Not responding${NC}"
    fi

    # Check queue stats
    if curl -s "$api_url/queue/stats" > /dev/null 2>&1; then
        QUEUE=$(curl -s "$api_url/queue/stats")
        echo ""
        echo -e "${BLUE}Queue Status:${NC}"
        echo "  Pending: $(echo $QUEUE | jq -r '.pending')"
        echo "  Running: $(echo $QUEUE | jq -r '.running')"
        echo "  Completed: $(echo $QUEUE | jq -r '.completed')"
    fi

    # Worker fleet truth — read the SAME /workers source the API and benchmark
    # runner use, so CLI status can never disagree with them about how many
    # workers are real and which are running stale code (docs proposed-next-steps §3).
    if curl -s "$api_url/workers" > /dev/null 2>&1; then
        WK=$(curl -s "$api_url/workers")
        echo ""
        echo -e "${BLUE}Worker Fleet:${NC}"
        echo "  Running:  $(echo "$WK" | jq -r '.count')"
        echo "  Current:  $(echo "$WK" | jq -r '.current_count // "?"')  (on expected build $(echo "$WK" | jq -r '.expected_build_fingerprint // "?"'))"
        local stale_n pending_n uniform
        stale_n=$(echo "$WK" | jq -r '.stale_count // 0')
        pending_n=$(echo "$WK" | jq -r '.pending_count // 0')
        uniform=$(echo "$WK" | jq -r '.fleet_uniform')
        if [ "$stale_n" != "0" ]; then
            echo -e "  Stale:    ${RED}$stale_n${NC} running OLD code: $(echo "$WK" | jq -rc '.stale_workers')"
        else
            echo "  Stale:    0"
        fi
        [ "$pending_n" != "0" ] && echo -e "  Pending:  ${YELLOW}$pending_n${NC} (started, not yet registered a build)"
        if [ "$uniform" = "true" ]; then
            echo -e "  Uniform:  ${GREEN}yes — fleet safe to benchmark${NC}"
        else
            echo -e "  Uniform:  ${RED}NO — restart workers before trusting benchmark numbers${NC}"
        fi
    fi

    echo ""
    echo -e "${BLUE}Access:${NC}"
    echo "  UI:  $(ui_base_url)"
    echo "  API: $(api_base_url)"
}

show_logs() {
    SERVICE=$1
    FOLLOW=${2:-""}

    if [ -z "$SERVICE" ]; then
        if [ "$FOLLOW" = "-f" ]; then
            compose logs -f
        else
            compose logs --tail=100
        fi
    else
        if [ "$SERVICE" = "worker" ] || [ "$SERVICE" = "workers" ]; then
            show_worker_logs "$FOLLOW"
            return $?
        fi
        if [ "$FOLLOW" = "-f" ]; then
            compose logs -f $SERVICE
        else
            compose logs --tail=100 $SERVICE
        fi
    fi
}

scan_worker_containers() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    docker ps -a \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.service=worker" \
        --format '{{.Names}}' 2>/dev/null | sort
}

running_scan_worker_containers() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    docker ps \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.service=worker" \
        --format '{{.Names}}' 2>/dev/null | sort
}

running_scan_worker_count() {
    local count
    count=$(running_scan_worker_containers | wc -l | tr -d '[:space:]')
    echo "${count:-0}"
}

restart_worker_count() {
    local resolved
    local running
    resolved="$(resolve_start_workers)"
    running="$(running_scan_worker_count)"
    if [ "$WORKERS" = "auto" ] && [ "${running:-0}" -gt "$resolved" ]; then
        echo "$running"
    else
        echo "$resolved"
    fi
}

remove_scan_worker_containers() {
    local message="${1:-Removing scanner worker containers...}"
    local containers
    local container
    containers="$(scan_worker_containers)"
    if [ -z "$containers" ]; then
        return 0
    fi
    echo -e "${YELLOW}${message}${NC}"
    for container in $containers; do
        docker rm -f "$container" >/dev/null 2>&1 || true
    done
}

worker_log_containers() {
    scan_worker_containers
}

show_worker_logs() {
    local follow_arg="${1:-}"
    local containers
    local container
    local pids=""
    local status=0

    containers="$(worker_log_containers)"
    if [ -z "$containers" ]; then
        echo -e "${YELLOW}No shakerscan-worker containers found; falling back to Compose worker logs.${NC}"
        if [ "$follow_arg" = "-f" ]; then
            compose logs -f worker
        else
            compose logs --tail=100 worker
        fi
        return $?
    fi

    if [ "$follow_arg" = "-f" ]; then
        for container in $containers; do
            (
                docker logs --tail=100 -f "$container" 2>&1 |
                    awk -v name="$container" '{ print "[" name "] " $0; fflush(); }'
            ) &
            pids="$pids $!"
        done
        for pid in $pids; do
            wait "$pid" || status=1
        done
        return "$status"
    fi

    for container in $containers; do
        docker logs --tail=100 "$container" 2>&1 |
            awk -v name="$container" '{ print "[" name "] " $0; fflush(); }'
    done
}

run_v2_scan_cli() {
    local compatibility_alias="${1:-}"
    shift || true
    local cli_args=(
        --api-url "$(api_base_url)"
        --ui-url "$(ui_base_url)"
    )
    if [ "$CONFIRM_ACTIVE" -eq 1 ]; then
        cli_args+=(--confirm-active)
    fi
    if [ -n "$compatibility_alias" ]; then
        cli_args+=(--compatibility-alias "$compatibility_alias")
    fi
    if [ ! -f "$SCRIPT_DIR/scripts/scan_cli.py" ]; then
        echo -e "${RED}Error: the V2 Scan CLI is missing from this runtime.${NC}" >&2
        return 1
    fi
    python3 "$SCRIPT_DIR/scripts/scan_cli.py" "${cli_args[@]}" "$@"
}

run_v2_product_cli() {
    local product="$1"
    shift || true
    if [ ! -f "$SCRIPT_DIR/scripts/v2_cli.py" ]; then
        echo -e "${RED}Error: the V2 product CLI is missing from this runtime.${NC}" >&2
        return 1
    fi
    python3 "$SCRIPT_DIR/scripts/v2_cli.py" \
        --api-url "$(api_base_url)" "$product" "$@"
}


print_scan_help() {
    local command_name="${1:-scan}"
    echo "Usage: ./scanner.sh $command_name <target> [scan options]"
    echo ""
    echo "Scan options:"
    if [ "$command_name" = "scan" ]; then
        echo "  --type TYPE              Deprecated compatibility alias"
    fi
    echo "  --budget-profile P       fast, balanced, or thorough"
    echo "  --active-testing         Enable authorized active checks"
    echo "  --execution MODE         auto, normal, parallel, or coverage"
    echo "  --shards N|auto          Parallel shard count (2-20)"
    echo "  --shard-strategy S       auto, scope, family, coverage, or coverage_family"
    echo "  --endpoint SPEC          Known endpoint; repeat for scope sharding"
    echo "  --coverage-depth D       standard or deep"
    echo "  --auth-state-shards      Expand parallel work across configured auth states"
    echo "  --approval-receipt ID    Stamp a target-bound approval receipt on submission"
    echo "  --require-current-workers Reject active work on stale/unconfirmed workers"
    echo "  --confirm-active         Confirm authorization for active testing"
}

scan_error_detail() {
    local body="$1"
    if jq -e . >/dev/null 2>&1 <<<"$body"; then
        jq -r '
            if (.detail | type) == "object" then
                .detail.message // .detail.error // (.detail | tojson)
            elif .detail != null then .detail
            else .message // .error // (tojson)
            end
        ' <<<"$body"
    else
        printf '%s\n' "$body"
    fi
}

submit_scan() {
    local command_name="$1"
    local scan_type="$2"
    local allow_type_override="$3"
    shift 3

    local target=""
    local budget_profile=""
    local execution="auto"
    local shards=""
    local shard_strategy=""
    local coverage_depth="standard"
    local require_current_workers=0
    local auth_state_shards=0
    local approval_receipt=""
    local endpoint_count=0
    local endpoints='[]'
    local coverage_mode=0
    local active_testing=0
    local legacy_type=0
    local scan_label=""
    local value

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --type|--scan-type)
                if [ "$allow_type_override" -ne 1 ]; then
                    echo -e "${RED}Error: $command_name has a fixed scan type; use 'scan --type ...' instead.${NC}"
                    return 1
                fi
                [ -n "${2:-}" ] || { echo -e "${RED}Error: $1 requires a value${NC}"; return 1; }
                scan_type="$2"
                legacy_type=1
                shift 2
                ;;
            --type=*|--scan-type=*)
                if [ "$allow_type_override" -ne 1 ]; then
                    echo -e "${RED}Error: $command_name has a fixed scan type; use 'scan --type ...' instead.${NC}"
                    return 1
                fi
                scan_type="${1#*=}"
                legacy_type=1
                shift
                ;;
            --active-testing)
                active_testing=1
                shift
                ;;
            --budget-profile)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --budget-profile requires a value${NC}"; return 1; }
                budget_profile="$2"
                shift 2
                ;;
            --budget-profile=*)
                budget_profile="${1#*=}"
                shift
                ;;
            --execution)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --execution requires a value${NC}"; return 1; }
                execution="$2"
                shift 2
                ;;
            --execution=*)
                execution="${1#*=}"
                shift
                ;;
            --shards)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --shards requires a value${NC}"; return 1; }
                shards="$2"
                shift 2
                ;;
            --shards=*)
                shards="${1#*=}"
                shift
                ;;
            --shard-strategy)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --shard-strategy requires a value${NC}"; return 1; }
                shard_strategy="$2"
                shift 2
                ;;
            --shard-strategy=*)
                shard_strategy="${1#*=}"
                shift
                ;;
            --endpoint)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --endpoint requires a value${NC}"; return 1; }
                endpoints="$(jq -c --arg endpoint "$2" '. + [$endpoint]' <<<"$endpoints")"
                endpoint_count=$((endpoint_count + 1))
                shift 2
                ;;
            --endpoint=*)
                value="${1#*=}"
                [ -n "$value" ] || { echo -e "${RED}Error: --endpoint requires a value${NC}"; return 1; }
                endpoints="$(jq -c --arg endpoint "$value" '. + [$endpoint]' <<<"$endpoints")"
                endpoint_count=$((endpoint_count + 1))
                shift
                ;;
            --coverage-depth)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --coverage-depth requires a value${NC}"; return 1; }
                coverage_depth="$2"
                shift 2
                ;;
            --coverage-depth=*)
                coverage_depth="${1#*=}"
                shift
                ;;
            --require-current-workers)
                require_current_workers=1
                shift
                ;;
            --auth-state-shards)
                auth_state_shards=1
                shift
                ;;
            --approval-receipt)
                [ -n "${2:-}" ] || { echo -e "${RED}Error: --approval-receipt requires a value${NC}"; return 1; }
                approval_receipt="$2"
                shift 2
                ;;
            --approval-receipt=*)
                approval_receipt="${1#*=}"
                [ -n "$approval_receipt" ] || { echo -e "${RED}Error: --approval-receipt requires a value${NC}"; return 1; }
                shift
                ;;
            --help|-h)
                print_scan_help "$command_name"
                return 0
                ;;
            --*)
                echo -e "${RED}Error: unknown $command_name option: $1${NC}"
                print_scan_help "$command_name"
                return 1
                ;;
            *)
                if [ -n "$target" ]; then
                    echo -e "${RED}Error: unexpected argument: $1${NC}"
                    print_scan_help "$command_name"
                    return 1
                fi
                target="$1"
                shift
                ;;
        esac
    done

    if [ "$legacy_type" -eq 1 ] || [ "$allow_type_override" -eq 0 ]; then
        case "$scan_type" in
            quick|standard|deep|full|aggressive|smart) ;;
            *) echo -e "${RED}Error: invalid legacy scan type '$scan_type'${NC}"; return 1 ;;
        esac
        case "$scan_type" in full|aggressive|smart) active_testing=1 ;; esac
    fi
    case "$budget_profile" in
        ""|fast|balanced|thorough) ;;
        *) echo -e "${RED}Error: invalid budget profile '$budget_profile'${NC}"; return 1 ;;
    esac
    case "$execution" in
        auto|normal|parallel|coverage) ;;
        *) echo -e "${RED}Error: invalid execution mode '$execution'${NC}"; return 1 ;;
    esac
    case "$shard_strategy" in
        ""|auto|scope|family|coverage|coverage_family) ;;
        *) echo -e "${RED}Error: invalid shard strategy '$shard_strategy'${NC}"; return 1 ;;
    esac
    case "$coverage_depth" in
        standard|deep) ;;
        *) echo -e "${RED}Error: invalid coverage depth '$coverage_depth'${NC}"; return 1 ;;
    esac
    if [ "$execution" = "coverage" ] && [ -n "$shard_strategy" ] && [ "$shard_strategy" != "coverage" ]; then
        echo -e "${RED}Error: --execution coverage fixes the shard strategy to coverage${NC}"
        return 1
    fi
    if [ -n "$shards" ] && [ "$shards" != "auto" ]; then
        if ! [[ "$shards" =~ ^[0-9]+$ ]] || [ "$shards" -lt 2 ] || [ "$shards" -gt 20 ]; then
            echo -e "${RED}Error: shards must be auto or a number between 2 and 20${NC}"
            return 1
        fi
    fi
    if [ -z "$target" ]; then
        echo -e "${RED}Error: please provide a target URL${NC}"
        print_scan_help "$command_name"
        return 1
    fi
    if [ "$execution" != "parallel" ] && [ "$execution" != "coverage" ]; then
        if [ -n "$shards" ] || [ -n "$shard_strategy" ]; then
            echo -e "${RED}Error: --shards and --shard-strategy require --execution parallel or coverage${NC}"
            return 1
        fi
        if [ "$auth_state_shards" -eq 1 ]; then
            echo -e "${RED}Error: --auth-state-shards requires --execution parallel or coverage${NC}"
            return 1
        fi
    fi
    if [ "$shard_strategy" = "scope" ] && [ "$endpoint_count" -lt 2 ]; then
        echo -e "${RED}Error: scope sharding requires at least two --endpoint values${NC}"
        return 1
    fi
    if [ "$execution" = "coverage" ] || [ "$shard_strategy" = "coverage" ] || [ "$shard_strategy" = "coverage_family" ]; then
        coverage_mode=1
    fi
    if [ "$coverage_depth" = "deep" ] && [ "$coverage_mode" -ne 1 ]; then
        echo -e "${RED}Error: --coverage-depth requires Full Coverage execution${NC}"
        return 1
    fi
    if [ "$coverage_depth" = "deep" ]; then
        case "$scan_type" in
            full|aggressive|smart) ;;
            *) echo -e "${RED}Error: deep Full Coverage requires full, aggressive, or smart scan type${NC}"; return 1 ;;
        esac
    fi
    if [ "$shard_strategy" = "family" ] || [ "$shard_strategy" = "coverage_family" ]; then
        case "$scan_type" in
            full|aggressive|smart) ;;
            *) echo -e "${RED}Error: $shard_strategy sharding requires full, aggressive, or smart scan type${NC}"; return 1 ;;
        esac
    fi
    if { [ "$execution" = "parallel" ] || [ "$execution" = "coverage" ]; } \
        && [ "$endpoint_count" -lt 2 ]; then
        case "$scan_type" in
            full|aggressive|smart) ;;
            *)
                echo -e "${RED}Error: parallel discovery/family execution requires full, aggressive, or smart; provide known --endpoint values for passive scope sharding.${NC}"
                return 1
                ;;
        esac
    fi

    if [ "$active_testing" -eq 1 ]; then
        scan_label="Active"
        if ! confirm_active_testing "$scan_label scan" "$target"; then
            echo "Cancelled"
            return 1
        fi
    fi

    local options
    options='{}'
    if [ "$legacy_type" -eq 1 ] || [ "$allow_type_override" -eq 0 ]; then
        options="$(jq -cn --arg scan_type "$scan_type" '{scan_type: $scan_type}')"
    fi
    if [ "$require_current_workers" -eq 1 ]; then
        options="$(jq -c '. + {require_current_workers: true}' <<<"$options")"
    fi
    if [ "$auth_state_shards" -eq 1 ]; then
        options="$(jq -c '. + {auth_state_shards: true}' <<<"$options")"
    fi
    if [ -n "$approval_receipt" ]; then
        options="$(jq -c --arg approval_receipt "$approval_receipt" '. + {approval_receipt_id: $approval_receipt}' <<<"$options")"
    fi
    if [ "$endpoint_count" -gt 0 ]; then
        options="$(jq -c --argjson endpoints "$endpoints" '. + {custom_endpoints: $endpoints}' <<<"$options")"
    fi

    case "$execution" in
        normal)
            options="$(jq -c '. + {parallel: false}' <<<"$options")"
            ;;
        parallel|coverage)
            local resolved_strategy="${shard_strategy:-auto}"
            [ "$execution" = "coverage" ] && resolved_strategy="coverage"
            options="$(jq -c --arg strategy "$resolved_strategy" '. + {parallel: true, shard_strategy: $strategy}' <<<"$options")"
            if [ -n "$shards" ]; then
                if [ "$shards" = "auto" ]; then
                    options="$(jq -c '. + {shards: "auto"}' <<<"$options")"
                else
                    options="$(jq -c --argjson shards "$shards" '. + {shards: $shards}' <<<"$options")"
                fi
            fi
            ;;
    esac

    if [ "$coverage_mode" -eq 1 ]; then
        if [ "$coverage_depth" = "deep" ]; then
            options="$(jq -c '
                . + {
                    budget_profile: "exhaustive",
                    exploit_depth: true,
                    custom_budget: {
                        active_worklist_max: 50000,
                        param_discovery_url_limit: 500,
                        param_discovery_max_params: 100,
                        active_params_per_endpoint: 20,
                        max_findings_per_family: -1,
                        sqli_extract_max: 25,
                        oob_max_findings: 25
                    }
                }
            ' <<<"$options")"
        else
            options="$(jq -c '
                . + {
                    budget_profile: "thorough",
                    custom_budget: {
                        active_worklist_max: 50000,
                        param_discovery_url_limit: 500,
                        param_discovery_max_params: 100
                    }
                }
            ' <<<"$options")"
        fi
    fi

    local payload response http_code body scan_id status
    local resolved_budget="${budget_profile:-balanced}"
    payload="$(jq -cn --arg target "$target" --arg budget "$resolved_budget" --argjson active "$active_testing" --argjson options "$options" --arg approval "$approval_receipt" '{target: $target, budget_profile: $budget, policy: {active_testing: ($active == 1)}, options: $options} + (if $approval == "" then {} else {approval_receipt_id: $approval} end)')"

    echo -e "${GREEN}Submitting Scan ($resolved_budget budget, active testing: $([ "$active_testing" -eq 1 ] && echo on || echo off)): $target${NC}"
    if ! response="$(curl -sS -w $'\n%{http_code}' -X POST "$(api_base_url)/scans" \
        -H "Content-Type: application/json" \
        --data-binary "$payload")"; then
        echo -e "${RED}Error: could not reach the ShakerScan API at $(api_base_url)${NC}"
        return 1
    fi
    http_code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    if ! [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        echo -e "${RED}Scan submission failed (HTTP $http_code): $(scan_error_detail "$body")${NC}"
        return 1
    fi
    if ! jq -e '.scan_id and .status' >/dev/null 2>&1 <<<"$body"; then
        echo -e "${RED}Scan submission returned an invalid response.${NC}"
        scan_error_detail "$body"
        return 1
    fi

    scan_id="$(jq -r '.scan_id' <<<"$body")"
    status="$(jq -r '.status' <<<"$body")"
    echo "Scan ID: $scan_id"
    echo "Status: $status"
    echo ""
    echo "View progress at: $(ui_base_url)/scans/$scan_id"
}

docker_storage_free_kb() {
    local docker_root
    docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    # Docker Desktop keeps this path inside its VM, so the host cannot measure
    # it reliably. The admission gate is authoritative only when the daemon's
    # storage root is visible on this host (normal Linux/VPS installs).
    if [ -z "$docker_root" ] || [ ! -d "$docker_root" ]; then
        return 1
    fi
    df -Pk "$docker_root" 2>/dev/null | awk 'END {print $4}'
}

write_build_receipt() {
    local status="$1"
    local exit_code="${2:-0}"
    local detail="${3:-}"
    local free_kb=""
    local finished_at=""
    local tmp

    [ "$BUILD_RECEIPT_ACTIVE" -eq 1 ] || return 0
    free_kb="$(docker_storage_free_kb 2>/dev/null || true)"
    if [ "$status" != "running" ]; then
        finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    fi
    tmp="${BUILD_RECEIPT_FILE}.tmp.$$"
    if jq -n \
        --arg operation "$BUILD_RECEIPT_OPERATION" \
        --arg scope "$BUILD_RECEIPT_SCOPE" \
        --arg status "$status" \
        --arg phase "$BUILD_RECEIPT_PHASE" \
        --arg started_at "$BUILD_RECEIPT_STARTED_AT" \
        --arg finished_at "$finished_at" \
        --arg source_revision "${GIT_COMMIT:-unknown}" \
        --arg detail "$detail" \
        --argjson exit_code "$exit_code" \
        --argjson free_kb "${free_kb:-null}" \
        '{schema_version:"shakerscan-build-receipt/v1",operation:$operation,scope:$scope,status:$status,phase:$phase,started_at:$started_at,finished_at:(if $finished_at == "" then null else $finished_at end),source_revision:$source_revision,exit_code:$exit_code,free_kb:$free_kb,detail:(if $detail == "" then null else $detail end)}' \
        > "$tmp" 2>/dev/null; then
        mv "$tmp" "$BUILD_RECEIPT_FILE"
    else
        rm -f "$tmp"
    fi
}

begin_build_receipt() {
    BUILD_RECEIPT_ACTIVE=1
    BUILD_RECEIPT_OPERATION="$1"
    BUILD_RECEIPT_SCOPE="${2:-all}"
    BUILD_RECEIPT_PHASE="preflight"
    BUILD_RECEIPT_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    write_build_receipt running 0
}

local_application_images_ready() {
    local worker_image="${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}"
    local sandbox_image="${MODEL_INTAKE_SANDBOX_IMAGE:-shakerscan-model-intake-sandbox:local}"
    local api_image="${COMPOSE_PROJECT_NAME:-shakerscan}-api:latest"
    local ui_image="${COMPOSE_PROJECT_NAME:-shakerscan}-ui:latest"
    local signer_image="${COMPOSE_PROJECT_NAME:-shakerscan}-model-intake-signer:latest"
    local image

    # Only a successful full build is an atomic application image set. A
    # scanner-only or UI-only rebuild deliberately cannot authorize startup of
    # the untouched roles at a new source revision.
    if ! jq -e --arg revision "${GIT_COMMIT:-unknown}" '
        .schema_version == "shakerscan-build-receipt/v1" and
        .status == "completed" and
        .phase == "complete" and
        .scope == "all" and
        .source_revision == $revision
    ' "$BUILD_RECEIPT_FILE" >/dev/null 2>&1; then
        return 1
    fi

    for image in "$worker_image" "$sandbox_image" "$api_image" "$ui_image" "$signer_image"; do
        docker image inspect "$image" >/dev/null 2>&1 || return 1
    done
}

build_failure_guidance() {
    echo -e "${RED}Build failed during phase: ${BUILD_RECEIPT_PHASE}${NC}" >&2
    echo "Receipt: $BUILD_RECEIPT_FILE" >&2
    echo "Safe cleanup (does not remove containers or volumes): docker builder prune -af" >&2
    echo "Also remove unused images: docker image prune -af" >&2
    echo "Disposable host only, after stopping services: docker system prune -af --volumes" >&2
}

fail_build() {
    local exit_code="${1:-1}"
    local detail="${2:-build command failed}"
    write_build_receipt failed "$exit_code" "$detail"
    build_failure_guidance
    return "$exit_code"
}

finish_build_receipt() {
    BUILD_RECEIPT_PHASE="complete"
    write_build_receipt completed 0
    echo -e "${BLUE}Build receipt: ${BUILD_RECEIPT_FILE}${NC}"
}

check_build_storage() {
    local no_cache="$1"
    local scope="$2"
    local free_kb
    local minimum_gb
    local minimum_kb

    if ! free_kb="$(docker_storage_free_kb)"; then
        echo -e "${YELLOW}Docker storage is managed outside the host filesystem; skipping the Linux disk admission check.${NC}"
        return 0
    fi
    if ! [[ "$free_kb" =~ ^[0-9]+$ ]]; then
        BUILD_RECEIPT_PHASE="preflight"
        fail_build 1 "could not measure Docker storage"
        return 1
    fi

    if [ -n "${SHAKERSCAN_BUILD_MIN_FREE_GB:-}" ]; then
        minimum_gb="$SHAKERSCAN_BUILD_MIN_FREE_GB"
    elif [ -z "$no_cache" ]; then
        minimum_gb=4
    elif [ "$scope" = "ui" ]; then
        minimum_gb=4
    elif [ "$scope" = "scanner" ]; then
        minimum_gb=20
    else
        minimum_gb=22
    fi
    if ! [[ "$minimum_gb" =~ ^[0-9]+$ ]] || [ "$minimum_gb" -lt 1 ]; then
        fail_build 2 "SHAKERSCAN_BUILD_MIN_FREE_GB must be a positive integer"
        return 1
    fi
    minimum_kb=$((minimum_gb * 1024 * 1024))
    if [ "$free_kb" -lt "$minimum_kb" ]; then
        fail_build 1 "insufficient Docker storage: $((free_kb / 1024 / 1024)) GiB free; ${minimum_gb} GiB required for ${scope}"
        return 1
    fi
    echo -e "${BLUE}Docker storage preflight: $((free_kb / 1024 / 1024)) GiB free; ${minimum_gb} GiB required.${NC}"
}

run_build_step() {
    local phase="$1"
    shift
    local exit_code

    BUILD_RECEIPT_PHASE="$phase"
    write_build_receipt running 0
    if "$@"; then
        write_build_receipt running 0
        return 0
    else
        exit_code=$?
        fail_build "$exit_code" "command failed in ${phase}"
        return "$exit_code"
    fi
}

build_local_scanner_family() {
    local no_cache="${1:-}"
    local worker_image_id
    local worker_image="${SCANNER_LOCAL_WORKER_IMAGE:-shakerscan-worker:local}"
    local sandbox_image="${MODEL_INTAKE_SANDBOX_IMAGE:-shakerscan-model-intake-sandbox:local}"

    # The worker, Model Intake sandbox, and API share one scanner runtime.
    # Build it once, bind the sandbox tag to that exact image, then build the
    # API's thin Docker-client overlay. Even --no-cache must never compile the
    # scanner/toolchain a second time.
    run_build_step scanner_runtime compose build $no_cache worker
    # The source Compose service builds and tags this exact explicit image.
    # Querying a running worker here can return the retired pre-build ID.
    worker_image_id="$(docker image inspect --format '{{.Id}}' "$worker_image" 2>/dev/null || true)"
    if ! [[ "$worker_image_id" =~ ^(sha256:)?[0-9a-f]{64}$ ]]; then
        fail_build 1 "could not resolve the newly built worker image"
        return 1
    fi
    run_build_step sandbox_alias docker image tag "$worker_image_id" "$sandbox_image"
    run_build_step api_overlay compose build $no_cache api
}

build_local_images() {
    local no_cache="${1:-}"

    build_local_scanner_family "$no_cache"
    run_build_step ui_and_signer compose build $no_cache ui model-intake-signer
}

build_images() {
    prepare_runtime_files
    set_build_env
    begin_build_receipt build all
    check_build_storage "" all
    echo -e "${GREEN}Building Docker images...${NC}"
    build_local_images
    record_runtime_mode local
    finish_build_receipt
    echo -e "${GREEN}Build complete${NC}"
    echo -e "${BLUE}Local-build mode recorded. Use './scanner.sh start' or './scanner.sh restart' to run these local images.${NC}"
}

rebuild_images() {
    prepare_runtime_files
    set_build_env
    local NO_CACHE=""
    local SERVICES=""
    local SERVICE_DESC="all services"
    local BUILD_SCOPE="all"
    local REFRESH_WORKERS=1
    local existing_workers
    local existing_agent_tool_worker
    local existing_device_workers
    local existing_api
    local existing_ui
    local existing_model_intake_signer
    local existing_model_intake_sandbox

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-cache)
                NO_CACHE="--no-cache"
                shift
                ;;
            scanner)
                SERVICES="api worker"
                SERVICE_DESC="scanner services (api, worker)"
                BUILD_SCOPE="scanner"
                REFRESH_WORKERS=1
                shift
                ;;
            ui)
                SERVICES="ui"
                SERVICE_DESC="UI"
                BUILD_SCOPE="ui"
                REFRESH_WORKERS=0
                shift
                ;;
            all)
                SERVICES=""
                SERVICE_DESC="all services"
                REFRESH_WORKERS=1
                shift
                ;;
            *)
                echo -e "${RED}Unknown rebuild option: $1${NC}"
                echo "Usage: ./scanner.sh rebuild [--no-cache] [scanner|ui|all]"
                exit 1
                ;;
        esac
    done

    if [ -n "$NO_CACHE" ]; then
        echo -e "${YELLOW}Rebuilding $SERVICE_DESC (no cache - full rebuild)...${NC}"
    else
        echo -e "${GREEN}Rebuilding $SERVICE_DESC (using cache)...${NC}"
    fi

    begin_build_receipt rebuild "$BUILD_SCOPE"
    if [ "$SERVICES" = "ui" ]; then
        check_build_storage "$NO_CACHE" ui
    elif [ "$SERVICES" = "api worker" ]; then
        check_build_storage "$NO_CACHE" scanner
    else
        check_build_storage "$NO_CACHE" all
    fi

    existing_workers="$(running_scan_worker_count)"
    existing_agent_tool_worker="$(running_compose_service_count agent-tool-worker)"
    existing_device_workers="$(running_device_worker_count)"
    existing_api="$(running_compose_service_count api)"
    existing_ui="$(running_compose_service_count ui)"
    existing_model_intake_signer="$(running_compose_service_count model-intake-signer)"
    existing_model_intake_sandbox="$(running_compose_service_count model-intake-sandbox)"

    if [ "$SERVICES" = "ui" ]; then
        run_build_step ui compose build $NO_CACHE ui
    elif [ "$SERVICES" = "api worker" ]; then
        build_local_scanner_family "$NO_CACHE"
    else
        build_local_scanner_family "$NO_CACHE"
        run_build_step ui_and_signer compose build $NO_CACHE ui model-intake-signer
    fi

    record_runtime_mode local

    if [ "$REFRESH_WORKERS" -eq 1 ]; then
        refresh_workers_after_rebuild "$existing_workers" "$existing_model_intake_sandbox"
        refresh_running_service_after_rebuild agent-tool-worker "$existing_agent_tool_worker"
        refresh_device_worker_after_rebuild "$existing_device_workers"
    fi

    if [ "$SERVICES" = "ui" ]; then
        refresh_running_service_after_rebuild ui "$existing_ui"
    elif [ "$SERVICES" = "api worker" ]; then
        refresh_running_service_after_rebuild api "$existing_api"
    else
        refresh_running_service_after_rebuild api "$existing_api"
        refresh_running_service_after_rebuild ui "$existing_ui"
        refresh_running_service_after_rebuild model-intake-signer "$existing_model_intake_signer"
    fi

    # A full rebuild is an atomic deployment operation when the main stack was already running.
    # Do not report success while any primary execution component still serves the old image.
    if [ -z "$SERVICES" ] \
        && [ "${existing_api:-0}" -gt 0 ] \
        && [ "${existing_ui:-0}" -gt 0 ] \
        && [ "${existing_workers:-0}" -gt 0 ]; then
        wait_for_url "API" "$(api_probe_url)/health" 120
        wait_for_url "UI" "$(ui_probe_url)" 120
        verify_running_build_identity
        verify_specialized_worker_identity "$existing_agent_tool_worker" "$existing_device_workers"
    fi

    finish_build_receipt
    echo -e "${GREEN}Rebuild complete${NC}"
    echo ""
    if [ "$REFRESH_WORKERS" -eq 1 ] && [ "${existing_workers:-0}" -gt 0 ]; then
        echo -e "${BLUE}Local-build mode recorded. Running services were recreated from the rebuilt images.${NC}"
        echo -e "${BLUE}Use scanner.sh rather than raw 'docker compose up' so remote-access trust is re-derived.${NC}"
    else
        echo -e "${BLUE}Local-build mode recorded. Any running rebuilt services were recreated; stopped services remain stopped.${NC}"
        echo -e "${BLUE}Use scanner.sh rather than raw 'docker compose up' so remote-access trust is re-derived.${NC}"
    fi
    if [ "$REFRESH_WORKERS" -eq 1 ] && [ "${existing_device_workers:-0}" -gt 0 ]; then
        echo -e "${BLUE}The running connected-device worker was also recreated from the rebuilt image.${NC}"
    fi
    echo -e "${BLUE}Use './scanner.sh restart --prebuilt' only when you intentionally want Docker Hub images.${NC}"
}

refresh_workers_after_rebuild() {
    local desired_count="${1:-0}"
    local sandbox_running_count="${2:-0}"
    # The sandbox shares the rebuilt worker image tag but is not part of the
    # worker scale set. Recreate it explicitly so it cannot keep executing the
    # pre-rebuild image ID behind the updated tag.
    if [ "$sandbox_running_count" -gt 0 ]; then
        compose up --no-build -d --no-deps --force-recreate model-intake-sandbox
    fi
    if [ "$desired_count" -lt 1 ]; then
        remove_scan_worker_containers "Removing stale stopped worker containers after rebuild..."
        return 0
    fi

    remove_scan_worker_containers "Recreating worker containers from rebuilt image..."
    compose up --no-build -d --force-recreate --scale worker="$desired_count" worker
}

running_compose_service_count() {
    local service="$1"
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    local count
    count="$(docker ps \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.service=$service" \
        --format '{{.Names}}' 2>/dev/null | wc -l | tr -d '[:space:]')"
    echo "${count:-0}"
}

refresh_running_service_after_rebuild() {
    local service="$1"
    local running_count="${2:-0}"
    if [ "$running_count" -lt 1 ]; then
        return 0
    fi
    echo -e "${YELLOW}Recreating $service from rebuilt image...${NC}"
    # Dependencies retain their state and data. Only the service whose image
    # was rebuilt is replaced.
    compose up --no-build -d --no-deps --force-recreate "$service"
}

running_device_worker_count() {
    local project="${COMPOSE_PROJECT_NAME:-shakerscan}"
    local count
    count="$(docker ps \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.service=device-worker" \
        --format '{{.Names}}' 2>/dev/null | wc -l | tr -d '[:space:]')"
    echo "${count:-0}"
}

refresh_device_worker_after_rebuild() {
    local running_count="${1:-0}"
    if [ "$running_count" -lt 1 ]; then
        return 0
    fi
    echo -e "${YELLOW}Recreating connected-device worker from rebuilt image...${NC}"
    compose --profile devices up --no-build -d --force-recreate device-worker
}

reset_database() {
    local start_workers
    start_workers="$(resolve_start_workers)"
    echo -e "${RED}WARNING: This will delete all scan data!${NC}"
    read -p "Are you sure? (yes/no): " CONFIRM
    if [ "$CONFIRM" = "yes" ]; then
        echo "Stopping services..."
        compose down -v
        echo "Starting fresh..."
        compose_up -d --scale worker=$start_workers
        echo -e "${GREEN}Database reset complete${NC}"
    else
        echo "Cancelled"
    fi
}

create_backup() {
    local backup_root="${1:-$SCRIPT_DIR/backups}"
    local timestamp
    local snapshot_dir

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    snapshot_dir="$backup_root/shakerscan-$timestamp"
    if [ -e "$snapshot_dir" ]; then
        echo -e "${RED}Error: backup destination already exists: $snapshot_dir${NC}"
        return 1
    fi

    umask 077
    mkdir -p "$snapshot_dir"
    printf '%s\n' "Backup is incomplete; do not use for restore." > "$snapshot_dir/.incomplete"

    echo "Creating consistent PostgreSQL dump..."
    if ! compose exec -T postgres pg_dump -U scanner -d scanner -Fc > "$snapshot_dir/postgres.dump"; then
        echo -e "${RED}PostgreSQL backup failed. Partial files remain at $snapshot_dir${NC}"
        return 1
    fi

    echo "Archiving result artifacts..."
    if ! tar -C "$SCRIPT_DIR" -czf "$snapshot_dir/results.tar.gz" results; then
        echo -e "${RED}Results backup failed. Partial files remain at $snapshot_dir${NC}"
        return 1
    fi

    [ ! -f "$SCRIPT_DIR/.env" ] || cp "$SCRIPT_DIR/.env" "$snapshot_dir/runtime.env"
    [ ! -f "$SCRIPT_DIR/VERSION" ] || cp "$SCRIPT_DIR/VERSION" "$snapshot_dir/VERSION"
    [ ! -f "$SCRIPT_DIR/docker-compose.release.yml" ] || \
        cp "$SCRIPT_DIR/docker-compose.release.yml" "$snapshot_dir/docker-compose.release.yml"

    {
        printf 'created_at=%s\n' "$timestamp"
        printf 'release_version=%s\n' "$(get_release_version)"
        printf 'image_tag=%s\n' "${SCANNER_IMAGE_TAG:-$DEFAULT_PREBUILT_IMAGE_TAG}"
        printf 'compose_project=%s\n' "${COMPOSE_PROJECT_NAME:-shakerscan}"
    } > "$snapshot_dir/manifest.txt"
    rm "$snapshot_dir/.incomplete"

    echo -e "${GREEN}Backup complete: $snapshot_dir${NC}"
    echo "This directory contains sensitive configuration and scan evidence; store it securely."
}

scale_workers() {
    COUNT=$1
    if [ -z "$COUNT" ]; then
        echo -e "${RED}Error: Please specify number of workers${NC}"
        echo "Usage: ./scanner.sh scale <N>"
        exit 1
    fi

    # Validate count is a number between 1 and 20
    if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 20 ]; then
        echo -e "${RED}Error: Workers must be between 1 and 20${NC}"
        exit 1
    fi

    echo -e "${GREEN}Scaling to $COUNT workers...${NC}"
    compose_up -d --scale worker=$COUNT --no-recreate worker
    echo ""

    # Show current worker count
    RUNNING=$(compose ps worker 2>/dev/null | awk 'NR>1 && $0 ~ /Up|running/ {count++} END {print count+0}' || echo "?")
    echo -e "${GREEN}Workers scaled: $RUNNING running${NC}"
}

open_shell() {
    echo "Opening shell in scanner container..."
    compose_run --rm worker /bin/bash
}

doctor() {
    detect_platform
    echo -e "${BLUE}ShakerScan Doctor${NC}"
    echo "Platform: $(platform_label)"
    echo "Runtime mode: $([ "$USE_PREBUILT" -eq 1 ] && echo prebuilt || echo local-build)"
    echo "Compose project: ${COMPOSE_PROJECT_NAME:-shakerscan}"
    echo ""

    for dep in bash docker curl jq; do
        if command_exists "$dep"; then
            echo -e "  ${GREEN}ok${NC} $dep: $(command -v "$dep")"
        else
            echo -e "  ${YELLOW}missing${NC} $dep"
        fi
    done

    if has_docker_compose; then
        if has_docker_compose_v2; then
            echo -e "  ${GREEN}ok${NC} compose: docker compose"
        else
            echo -e "  ${YELLOW}legacy${NC} compose: docker-compose"
        fi
    else
        echo -e "  ${YELLOW}missing${NC} compose"
    fi

    if docker_info_available; then
        echo -e "  ${GREEN}ok${NC} Docker daemon reachable"
    else
        echo -e "  ${YELLOW}not ready${NC} Docker daemon is not reachable"
    fi

    echo ""
    echo "Expected service URLs:"
    echo "  UI:  $(ui_base_url)"
    echo "  API: $(api_base_url)"

    if [ "$USE_PREBUILT" -eq 1 ]; then
        [ -f "$SCRIPT_DIR/$PREBUILT_COMPOSE_FILE" ] && echo -e "  ${GREEN}ok${NC} $PREBUILT_COMPOSE_FILE" || echo -e "  ${YELLOW}missing${NC} $PREBUILT_COMPOSE_FILE"
        [ -f "$SCRIPT_DIR/db/init.sql" ] && echo -e "  ${GREEN}ok${NC} db/init.sql" || echo -e "  ${YELLOW}missing${NC} db/init.sql"
    fi
}

show_env_help() {
    local default_launcher="$HOME/.local/bin/shakerscan"
    local launcher
    local path_launcher

    if [ -x "$default_launcher" ] && grep -F "exec \"$SCRIPT_DIR/scanner.sh\"" "$default_launcher" >/dev/null 2>&1; then
        launcher="$default_launcher"
    fi

    if [ -z "$launcher" ]; then
        path_launcher="$(command -v shakerscan 2>/dev/null || true)"
        if [ -n "$path_launcher" ] && grep -F "exec \"$SCRIPT_DIR/scanner.sh\"" "$path_launcher" >/dev/null 2>&1; then
            launcher="$path_launcher"
        fi
    fi

    echo -e "${BLUE}ShakerScan Environment${NC}"
    echo "Runtime directory: $SCRIPT_DIR"
    echo "Current UI URL:    $(ui_base_url)"
    echo "Current API URL:   $(api_base_url)"
    echo ""

    if [ -n "$launcher" ]; then
        echo "Launcher:          $launcher"
    else
        echo "Launcher:          not found in PATH"
        echo "Expected path:     $default_launcher"
    fi

    case ":$PATH:" in
        *":$HOME/.local/bin:"*)
            echo "PATH:              $HOME/.local/bin is available"
            ;;
        *)
            echo "PATH:              $HOME/.local/bin is not in the current shell"
            echo "Current shell fix:"
            echo "  export PATH=\"$HOME/.local/bin:\$PATH\""
            ;;
    esac

    echo ""
    echo "AI agent launch:"
    if [ -n "$launcher" ]; then
        echo "  $launcher agent codex"
        echo "  $launcher agent claude"
        echo "  $launcher agent opencode"
    else
        echo "  $SCRIPT_DIR/scanner.sh agent codex"
        echo "  $SCRIPT_DIR/scanner.sh agent claude"
        echo "  $SCRIPT_DIR/scanner.sh agent opencode"
    fi
    echo ""
    echo "Manual equivalent:"
    echo "  cd \"$SCRIPT_DIR\""
    echo "  export SHAKERSCAN_API_BASE=\"$(api_probe_url)\""
    echo "  export SHAKERSCAN_UI_BASE=\"$(ui_base_url)\""
    echo "  codex   # or claude, or opencode"
}

start_agent() {
    local agent="${1:-}"
    local candidates=()

    if [ "$agent" = "-h" ] || [ "$agent" = "--help" ] || [ "$agent" = "help" ]; then
        echo "Usage: $0 agent [codex|claude|opencode]"
        echo "Starts a supported coding agent inside the ShakerScan runtime directory."
        echo "With no name, the first installed supported agent is selected."
        return 0
    fi

    if [ -n "$agent" ]; then
        candidates=("$agent")
    else
        candidates=(codex claude opencode)
    fi

    for agent in "${candidates[@]}"; do
        case "$agent" in
            codex|claude|opencode)
                if command_exists "$agent"; then
                    echo "Starting $agent in $SCRIPT_DIR"
                    echo "This lets the agent read README.md, AGENTS.md, CLAUDE.md, skills/, and .claude/."
                    echo "Research planner: this agent session (no stored AI provider required)."
                    cd "$SCRIPT_DIR"
                    export SHAKERSCAN_AGENT_NAME="$agent"
                    export SHAKERSCAN_RESEARCH_PLANNER_MODE="agent"
                    # Remote mode intentionally may not publish loopback. Give
                    # project hooks and commands the host-reachable API plus the
                    # browser-facing UI URL derived from the persisted access
                    # configuration used by `scanner.sh status`.
                    export SHAKERSCAN_API_BASE="${SHAKERSCAN_API_BASE:-$(api_probe_url)}"
                    export SHAKERSCAN_UI_BASE="${SHAKERSCAN_UI_BASE:-$(ui_base_url)}"
                    exec "$agent"
                fi
                ;;
            *)
                echo -e "${RED}Error: unsupported agent '$agent'. Use codex, claude, or opencode.${NC}"
                return 1
                ;;
        esac
    done

    echo -e "${RED}Error: no supported agent command found.${NC}"
    echo "Install Codex, Claude Code, or OpenCode, then run:"
    echo "  cd \"$SCRIPT_DIR\""
    echo "  codex   # or claude, or opencode"
    return 1
}

gungnir_cmd() {
    SUBCMD=${1:-"status"}

    case $SUBCMD in
        start)
            echo -e "${GREEN}Starting Gungnir CT monitor...${NC}"
            if [ "$USE_PREBUILT" -eq 1 ]; then
                compose --profile gungnir up --no-build -d gungnir-worker
            else
                compose --profile gungnir up -d gungnir-worker
            fi
            echo -e "${GREEN}Gungnir started. Monitoring CT logs for all targets.${NC}"
            echo ""
            echo "Use './scanner.sh gungnir status' to check status"
            echo "Use './scanner.sh gungnir logs' to view logs"
            ;;
        stop)
            echo -e "${YELLOW}Stopping Gungnir CT monitor...${NC}"
            compose stop gungnir-worker
            # Update Redis status
            compose exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" HSET gungnir:status running false' > /dev/null 2>&1 || true
            echo -e "${GREEN}Gungnir stopped${NC}"
            ;;
        status)
            if curl -s "$(api_base_url)/gungnir/status" > /dev/null 2>&1; then
                STATUS=$(curl -s "$(api_base_url)/gungnir/status")
                RUNNING=$(echo $STATUS | jq -r '.running')
                if [ "$RUNNING" = "true" ]; then
                    echo -e "${GREEN}Gungnir CT Monitor: Running${NC}"
                else
                    echo -e "${YELLOW}Gungnir CT Monitor: Stopped${NC}"
                fi
                echo "  Domains monitored: $(echo $STATUS | jq -r '.domains_monitored')"
                echo "  Subdomains found: $(echo $STATUS | jq -r '.subdomains_found')"
                echo "  Session found: $(echo $STATUS | jq -r '.session_found')"
                LAST=$(echo $STATUS | jq -r '.last_discovery')
                if [ "$LAST" != "null" ] && [ -n "$LAST" ]; then
                    echo "  Last discovery: $LAST"
                fi
            else
                echo -e "${YELLOW}Gungnir CT Monitor: Not running${NC}"
                echo "  (API not responding or gungnir never started)"
            fi
            ;;
        logs)
            compose logs --tail=100 gungnir-worker ${FOLLOW:-}
            ;;
        *)
            echo "Usage: ./scanner.sh gungnir {start|stop|status|logs}"
            echo ""
            echo "Commands:"
            echo "  start   Start the CT monitor"
            echo "  stop    Stop the CT monitor"
            echo "  status  Show monitoring status"
            echo "  logs    View gungnir logs (use -f to follow)"
            ;;
    esac
}

devices_cmd() {
    local subcmd=${1:-"status"}

    case "$subcmd" in
        start)
            echo -e "${GREEN}Starting isolated connected-device worker...${NC}"
            # Starting optional capacity must never trigger an implicit source
            # build. Source operators build once with `scanner.sh rebuild`;
            # release operators already have the selected prebuilt image.
            # `--no-build` also keeps enabling device capacity fast and avoids
            # consuming resources used by ordinary Web DAST workers.
            if [ "$USE_PREBUILT" -ne 1 ] && \
               ! docker image inspect "$SCANNER_LOCAL_WORKER_IMAGE" >/dev/null 2>&1; then
                echo -e "${RED}Error: local worker image $SCANNER_LOCAL_WORKER_IMAGE is missing.${NC}" >&2
                echo "Run './scanner.sh build' or './scanner.sh start --local' first." >&2
                return 1
            fi
            compose --profile devices up --no-build -d device-worker
            echo -e "${GREEN}Connected-device worker started${NC}"
            echo "Readiness: $(api_base_url)/devices/readiness"
            ;;
        restart)
            echo -e "${GREEN}Restarting isolated connected-device worker from the selected image...${NC}"
            if [ "$USE_PREBUILT" -ne 1 ] && \
               ! docker image inspect "$SCANNER_LOCAL_WORKER_IMAGE" >/dev/null 2>&1; then
                echo -e "${RED}Error: local worker image $SCANNER_LOCAL_WORKER_IMAGE is missing.${NC}" >&2
                echo "Run './scanner.sh build' or './scanner.sh start --local' first." >&2
                return 1
            fi
            compose --profile devices up --no-build -d --force-recreate device-worker
            echo -e "${GREEN}Connected-device worker restarted${NC}"
            echo "Readiness: $(api_base_url)/devices/readiness"
            ;;
        stop)
            echo -e "${YELLOW}Stopping connected-device worker...${NC}"
            compose --profile devices stop device-worker
            echo -e "${GREEN}Connected-device worker stopped${NC}"
            ;;
        status)
            compose --profile devices ps device-worker
            if curl -fsS "$(api_base_url)/devices/readiness" >/dev/null 2>&1; then
                curl -fsS "$(api_base_url)/devices/readiness" | jq '{enabled,status,reason,worker_count,capable_worker_count,required_worker_tools}'
            fi
            ;;
        logs)
            compose --profile devices logs --tail=100 device-worker ${FOLLOW:-}
            ;;
        *)
            echo "Usage: ./scanner.sh devices {start|stop|restart|status|logs}"
            return 1
            ;;
    esac
}

# Parse arguments
COMMAND=${1:-"help"}
shift || true

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        -w|--workers)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: $1 requires a value${NC}"
                exit 1
            fi
            WORKERS="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW="-f"
            shift
            ;;
        -y|--yes)
            ASSUME_YES=1
            shift
            ;;
        --local)
            USE_PREBUILT=0
            RUNTIME_MODE_EXPLICIT=1
            shift
            ;;
        --local-build)
            if [ "$COMMAND" = "join" ]; then
                # `join --local-build` belongs to the fleet provisioner. Do not
                # consume it as the scanner wrapper's local runtime alias.
                ARGS+=("$1")
            else
                USE_PREBUILT=0
                RUNTIME_MODE_EXPLICIT=1
            fi
            shift
            ;;
        --prebuilt)
            USE_PREBUILT=1
            RUNTIME_MODE_EXPLICIT=1
            shift
            ;;
        --image-tag)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: --image-tag requires a value${NC}"
                exit 1
            fi
            IMAGE_TAG_OVERRIDE="$2"
            shift 2
            ;;
        --remote|--tailscale)
            REMOTE_ACCESS=1
            shift
            ;;
        --bind-host)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: --bind-host requires a value${NC}"
                exit 1
            fi
            export SHAKERSCAN_BIND_HOST="$2"
            shift 2
            ;;
        --public-host)
            if [ -z "${2:-}" ]; then
                echo -e "${RED}Error: --public-host requires a value${NC}"
                exit 1
            fi
            export SHAKERSCAN_PUBLIC_HOST="$2"
            shift 2
            ;;
        --confirm-active)
            CONFIRM_ACTIVE=1
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

load_access_env

if ! configure_access_mode; then
    exit 1
fi

configure_runtime_mode "$COMMAND"

# Help must never mutate state. Commands with their own parser keep their
# detailed help; simple wrapper commands are handled here before dependency
# checks or Docker operations.
COMMAND_HELP_ONLY=0
for arg in "${ARGS[@]}"; do
    if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
        COMMAND_HELP_ONLY=1
        break
    fi
done

if [ "$COMMAND_HELP_ONLY" -eq 1 ]; then
    case "$COMMAND" in
        scan|scan-full|scan-smart|hunt|credentials|collections|evidence|agent|ai|fleet|join|model-intake-runner|report-rebuild)
            # Forward to the command's own help implementation below.
            ;;
        mcp)
            echo "Usage: ./scanner.sh mcp"
            echo "Starts the read-only Command Arsenal MCP stdio adapter."
            exit 0
            ;;
        research)
            echo "Usage: ./scanner.sh research <episode-id> [max-decisions]"
            echo "Runs bounded compatibility research decisions for an existing episode."
            exit 0
            ;;
        gungnir)
            gungnir_cmd --help
            exit 0
            ;;
        devices)
            echo "Usage: ./scanner.sh devices {start|stop|restart|status|logs}"
            exit 0
            ;;
        *)
            print_help
            exit 0
            ;;
    esac
fi

case $COMMAND in
    help|--help|-h|install-deps|doctor|env|agent|ai)
        ;;
    *)
        if [ "$COMMAND_HELP_ONLY" -ne 1 ] && ! ensure_command_dependencies "$COMMAND" "${ARGS[0]}"; then
            exit 1
        fi
        ;;
esac

case $COMMAND in
    start)
        print_banner
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    reload)
        reload_services
        ;;
    status)
        show_status
        ;;
    scale)
        scale_workers "${ARGS[0]}"
        ;;
    logs)
        show_logs "${ARGS[0]}" "$FOLLOW"
        ;;
    scan)
        run_v2_scan_cli "" "${ARGS[@]}"
        ;;
    scan-full)
        run_v2_scan_cli "full" "${ARGS[@]}"
        ;;
    scan-smart)
        run_v2_scan_cli "smart" "${ARGS[@]}"
        ;;
    hunt)
        run_v2_product_cli "hunt" "${ARGS[@]}"
        ;;
    credentials)
        run_v2_product_cli "credentials" "${ARGS[@]}"
        ;;
    collections)
        run_v2_product_cli "collections" "${ARGS[@]}"
        ;;
    evidence)
        run_v2_product_cli "evidence" "${ARGS[@]}"
        ;;
    report-rebuild)
        if [ ! -f "$SCRIPT_DIR/scripts/rebuild_scan_report.py" ]; then
            echo -e "${RED}Error: the offline report builder is missing from this runtime.${NC}" >&2
            exit 1
        fi
        exec python3 "$SCRIPT_DIR/scripts/rebuild_scan_report.py" "${ARGS[@]}"
        ;;
    install-deps)
        install_dependencies
        ;;
    doctor)
        doctor
        ;;
    env)
        show_env_help
        ;;
    agent|ai)
        start_agent "${ARGS[0]}"
        ;;
    mcp)
        if [ ! -f "$SCRIPT_DIR/scripts/shakerscan_mcp.py" ]; then
            echo -e "${RED}Error: the MCP adapter is missing from this runtime.${NC}"
            echo "Re-run the ShakerScan installer to refresh runtime files."
            exit 1
        fi
        # Direct adapter invocation defaults to loopback. This wrapper has
        # already validated and loaded the install's access configuration, so
        # use the actual host-reachable bind and explicitly authorize that
        # configured non-loopback origin when remote mode is active.
        export SHAKERSCAN_API_URL="${SHAKERSCAN_API_URL:-$(api_probe_url)}"
        case "$(probe_access_host)" in
            localhost|127.0.0.1|::1) ;;
            *) export SHAKERSCAN_MCP_ALLOW_REMOTE_API="${SHAKERSCAN_MCP_ALLOW_REMOTE_API:-true}" ;;
        esac
        exec python3 "$SCRIPT_DIR/scripts/shakerscan_mcp.py"
        ;;
    model-intake-runner)
        # Opt-in on purpose: this tier needs root, mutates the host, and costs a
        # multi-gigabyte guest image that most hosts cannot use at all.
        if [ ! -f "$SCRIPT_DIR/scripts/model_intake_runner_cli.py" ]; then
            echo -e "${RED}Error: the Model Intake runner installer is missing from this runtime.${NC}"
            echo "Re-run the ShakerScan installer to refresh runtime files."
            exit 1
        fi
        exec python3 "$SCRIPT_DIR/scripts/model_intake_runner_cli.py" --runtime "$SCRIPT_DIR" "${ARGS[@]}"
        ;;
    fleet)
        if [ "${ARGS[0]:-}" = "accept" ]; then
            if [ ! -f "$SCRIPT_DIR/scripts/fleet_acceptance.py" ]; then
                echo -e "${RED}Error: the fleet acceptance runner is missing from this runtime.${NC}"
                echo "Re-run the ShakerScan installer to refresh runtime files."
                exit 1
            fi
            exec python3 "$SCRIPT_DIR/scripts/fleet_acceptance.py" "${ARGS[@]:1}"
        fi
        if [ ! -f "$SCRIPT_DIR/scripts/fleet_cli.py" ]; then
            echo -e "${RED}Error: the fleet host provisioner is missing from this runtime.${NC}"
            echo "Re-run the ShakerScan installer to refresh runtime files."
            exit 1
        fi
        exec python3 "$SCRIPT_DIR/scripts/fleet_cli.py" --runtime "$SCRIPT_DIR" "${ARGS[@]}"
        ;;
    join)
        if [ ! -f "$SCRIPT_DIR/scripts/fleet_cli.py" ]; then
            echo -e "${RED}Error: the fleet host provisioner is missing from this runtime.${NC}"
            echo "Re-run the ShakerScan installer to refresh runtime files."
            exit 1
        fi
        exec python3 "$SCRIPT_DIR/scripts/fleet_cli.py" --runtime "$SCRIPT_DIR" join "${ARGS[@]}"
        ;;
    research)
        if [ -z "${ARGS[0]:-}" ]; then
            echo "Usage: ./scanner.sh research <episode-id> [max-decisions]"
            exit 1
        fi
        for required_file in \
            "$SCRIPT_DIR/scripts/local_planner_adapter.py" \
            "$SCRIPT_DIR/scripts/planner_evals.py" \
            "$SCRIPT_DIR/api/command_arsenal.py"; do
            if [ ! -f "$required_file" ]; then
                echo -e "${RED}Error: legacy research adapter runtime files are incomplete.${NC}"
                echo "Re-run the ShakerScan installer to refresh runtime files."
                exit 1
            fi
        done
        exec python3 "$SCRIPT_DIR/scripts/local_planner_adapter.py" episode \
            --api-url "$(api_base_url)" \
            --episode-id "${ARGS[0]}" \
            --max-decisions "${ARGS[1]:-5}"
        ;;
    gungnir)
        gungnir_cmd "${ARGS[0]}"
        ;;
    devices)
        devices_cmd "${ARGS[0]}"
        ;;
    build)
        build_images
        ;;
    rebuild)
        rebuild_images "${ARGS[@]}"
        ;;
    backup)
        create_backup "${ARGS[0]}"
        ;;
    reset)
        reset_database
        ;;
    shell)
        open_shell
        ;;
    help|--help|-h)
        print_help
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        print_help
        exit 1
        ;;
esac
