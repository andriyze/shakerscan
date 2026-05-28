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
    mv "$tmp" "$file"
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
            # Only override PUBLIC_HOST when it was tracking BIND_HOST (or empty).
            if [ -z "${SHAKERSCAN_PUBLIC_HOST:-}" ] || [ "${SHAKERSCAN_PUBLIC_HOST:-}" = "$cached_bind" ]; then
                export SHAKERSCAN_PUBLIC_HOST="$tailscale_ip"
            fi
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

    export SHAKERSCAN_PUBLIC_API_URL="${SHAKERSCAN_PUBLIC_API_URL:-http://$(format_url_host "$(public_access_host)"):${SHAKERSCAN_API_PORT:-8080}}"
}

docker_info_available() {
    DOCKER_NEEDS_SUDO=0

    if docker info > /dev/null 2>&1; then
        return 0
    fi

    if command_exists sudo && sudo -n docker info > /dev/null 2>&1; then
        DOCKER_NEEDS_SUDO=1
        return 0
    fi

    return 1
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
    if [ "$USE_PREBUILT" -eq 1 ]; then
        compose up --no-build "$@"
    else
        compose up "$@"
    fi
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
    if ! compose pull api worker ui; then
        echo -e "${YELLOW}Warning: could not pull prebuilt images; continuing with local cache if available.${NC}"
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
            echo "Install manually: Docker Engine + Docker Compose + curl + jq"
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
            echo "Install manually: Docker Engine + Docker Compose + curl + jq"
            return 1
            ;;
    esac

    # Reset compose command cache in case compose became available after install.
    DOCKER_COMPOSE_CMD=()
}

command_needs_docker_runtime() {
    case "$1" in
        start|stop|restart|status|scale|logs|scan|scan-full|scan-smart|gungnir|build|rebuild|reset|shell)
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
        start|restart|status|scan|scan-full|scan-smart)
            return 0
            ;;
        gungnir)
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
    fi

    return 0
}

get_build_version() {
    if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        local commit
        commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
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

configure_runtime_mode() {
    local command="$1"

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
    export UI_IMAGE_REPO="${UI_IMAGE_REPO:-shakerscan/shakerscan-ui}"
    export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-shakerscan}"
    export SCANNER_RELEASE_VERSION="$(get_release_version)"
    export SCANNER_IMAGE_TAG="${SCANNER_IMAGE_TAG:-$DEFAULT_PREBUILT_IMAGE_TAG}"

    case "$command" in
        build|rebuild)
            USE_PREBUILT=0
            ;;
    esac

    if [ "$RUNTIME_MODE_EXPLICIT" -eq 0 ] && [ -f "$LOCAL_BUILD_MARKER" ]; then
        USE_PREBUILT=0
    fi

    if [ "$RUNTIME_MODE_EXPLICIT" -eq 1 ] && [ "$USE_PREBUILT" -eq 1 ]; then
        rm -f "$LOCAL_BUILD_MARKER"
    fi

    if [ "$USE_PREBUILT" -eq 1 ] && [ ! -f "$SCRIPT_DIR/$PREBUILT_COMPOSE_FILE" ]; then
        echo -e "${YELLOW}Prebuilt override file missing ($PREBUILT_COMPOSE_FILE). Falling back to local build mode.${NC}"
        USE_PREBUILT=0
    fi

    update_compose_file_args
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

    memory_gb="$(total_memory_gb)"
    if [ "$memory_gb" -ge 48 ]; then
        echo 5
    elif [ "$memory_gb" -ge 24 ]; then
        echo 3
    elif [ "$memory_gb" -ge 12 ]; then
        echo 2
    else
        echo 1
    fi
}

prepare_runtime_files() {
    mkdir -p results

    if [ "$USE_PREBUILT" -eq 1 ]; then
        mkdir -p db
        touch .env

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
    elif [ ! -f "$SCRIPT_DIR/scanner/Dockerfile" ] || [ ! -f "$SCRIPT_DIR/ui/Dockerfile" ]; then
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
    echo "  status             Show service status"
    echo "  scale <N>          Scale to N workers (1-20)"
    echo "  logs [service]     View logs (api, worker, ui, postgres, redis)"
    echo "  scan <target>      Quick scan a target"
    echo "  scan-full <target> Full assessment scan"
    echo "  scan-smart <target> Smart adaptive scan"
    echo "  install-deps       Install missing prerequisites"
    echo "  doctor             Check local prerequisites and common startup issues"
    echo "  env                Show PATH, launcher, and runtime guidance"
    echo "  agent [name]       Start Codex, Claude, or OpenCode in this runtime dir"
    echo "  gungnir <cmd>      CT monitor: start, stop, status, logs"
    echo "  build              Build Docker images"
    echo "  rebuild [opts]     Rebuild Docker images (cached by default)"
    echo "                       --no-cache  Full rebuild (slow, 10-20 min)"
    echo "                       scanner     Rebuild scanner/worker only"
    echo "                       ui          Rebuild UI only"
    echo "  reset              Reset database (WARNING: deletes all data)"
    echo "  shell              Open shell in scanner container"
    echo ""
    echo "Options:"
    echo "  -w, --workers N    Number of workers (default: $WORKERS)"
    echo "  -f, --follow       Follow logs"
    echo "  -y, --yes          Auto-confirm dependency installation"
    echo "  --local            Force local Docker build instead of prebuilt images"
    echo "  --prebuilt         Force prebuilt Docker Hub images (default for start/restart)"
    echo "  --image-tag TAG    Override Docker image tag (default: latest)"
    echo "  --remote           Bind UI/API to this host's Tailscale IPv4 address"
    echo "  --confirm-active   Confirm authorization for scan-full or scan-smart"
    echo "  --budget-profile P scan-smart only: fast, balanced, thorough, exhaustive"
    echo "  SHAKERSCAN_BIND_HOST=IP overrides the Docker bind address"
    echo "  SHAKERSCAN_PUBLIC_HOST=HOST overrides displayed/browser API host"
    echo "  SHAKERSCAN_PULL_IMAGES=0 skips Docker Hub pulls in prebuilt mode"
    echo ""
    echo "Auto-install support:"
    echo "  macOS; Linux with apt, dnf/yum, pacman, zypper, or apk"
    echo ""
    echo "Examples:"
    echo "  ./scanner.sh start                    # Start with latest prebuilt images"
    echo "  ./scanner.sh start -y                 # Install prerequisites if missing, then start"
    echo "  ./scanner.sh start --remote           # VPS access over Tailscale"
    echo "  ./scanner.sh env                      # Show PATH and agent launch commands"
    echo "  ./scanner.sh agent codex              # Start an AI agent with local docs loaded"
    echo "  ./scanner.sh start --local            # Build locally and start"
    echo "  ./scanner.sh start -w 10              # Start with 10 workers"
    echo "  ./scanner.sh start --image-tag 0.4.2  # Use a specific published tag"
    echo "  ./scanner.sh scale 10                 # Scale to 10 workers"
    echo "  ./scanner.sh scan https://example.com # Quick scan"
    echo "  ./scanner.sh scan-smart https://example.com --budget-profile thorough --confirm-active"
    echo "  ./scanner.sh install-deps             # Install dependencies"
    echo "  ./scanner.sh logs worker -f           # Follow worker logs"
    echo ""
    echo "Access:"
    echo "  UI:  $(ui_base_url)"
    echo "  API: $(api_base_url)"
}

start_services() {
    local start_workers

    prepare_runtime_files
    persist_remote_access_env
    start_workers="$(resolve_start_workers)"
    set_build_env
    echo -e "${GREEN}Starting ShakerScan with $start_workers worker(s)...${NC}"
    if [ "$WORKERS" = "auto" ]; then
        echo "Worker sizing: auto ($(total_memory_gb)GB RAM detected)"
    fi
    if [ "$USE_PREBUILT" -eq 1 ]; then
        echo "Mode: prebuilt images"
        echo "  scanner: ${SCANNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        echo "  ui:      ${UI_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        pull_prebuilt_images
    else
        echo "Mode: local build"
    fi
    compose_up -d --scale worker=$start_workers
    echo ""
    wait_for_url "API" "$(api_base_url)/health" 120 || true
    wait_for_url "UI" "$(ui_base_url)" 120 || true
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
    echo -e "${GREEN}Services stopped${NC}"
}

restart_services() {
    stop_services
    start_services
}

show_status() {
    local api_url
    api_url="$(api_base_url)"
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
        if [ "$FOLLOW" = "-f" ]; then
            compose logs -f $SERVICE
        else
            compose logs --tail=100 $SERVICE
        fi
    fi
}

quick_scan() {
    TARGET=$1
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Please provide a target URL${NC}"
        echo "Usage: ./scanner.sh scan <target>"
        exit 1
    fi

    echo -e "${GREEN}Starting quick scan: $TARGET${NC}"
    RESULT=$(curl -s -X POST "$(api_base_url)/scans" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": {\"quick\": true}}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: $(ui_base_url)/scans"
}

full_scan() {
    TARGET=$1
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Please provide a target URL${NC}"
        echo "Usage: ./scanner.sh scan-full <target>"
        exit 1
    fi

    echo -e "${YELLOW}Starting full assessment: $TARGET${NC}"
    if ! confirm_active_testing "Full assessment" "$TARGET"; then
        echo "Cancelled"
        exit 1
    fi
    echo ""

    RESULT=$(curl -s -X POST "$(api_base_url)/scans" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": {\"quick\": false, \"thorough\": true, \"active\": true}}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: $(ui_base_url)/scans"
}

smart_scan() {
    TARGET=$1
    shift || true
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Please provide a target URL${NC}"
        echo "Usage: ./scanner.sh scan-smart <target> [--budget-profile fast|balanced|thorough|exhaustive]"
        exit 1
    fi
    BUDGET_PROFILE=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --budget-profile)
                BUDGET_PROFILE="${2:-}"
                shift 2
                ;;
            --budget-profile=*)
                BUDGET_PROFILE="${1#*=}"
                shift
                ;;
            *)
                echo -e "${RED}Unknown scan-smart option: $1${NC}"
                echo "Usage: ./scanner.sh scan-smart <target> [--budget-profile fast|balanced|thorough|exhaustive]"
                exit 1
                ;;
        esac
    done

    echo -e "${YELLOW}Starting smart adaptive scan: $TARGET${NC}"
    if ! confirm_active_testing "Smart adaptive scan" "$TARGET"; then
        echo "Cancelled"
        exit 1
    fi
    echo ""

    OPTIONS="{\"scan_type\": \"smart\""
    if [ -n "$BUDGET_PROFILE" ]; then
        OPTIONS="$OPTIONS, \"budget_profile\": \"$BUDGET_PROFILE\""
    fi
    OPTIONS="$OPTIONS}"

    RESULT=$(curl -s -X POST "$(api_base_url)/scans" \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": $OPTIONS}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: $(ui_base_url)/scans"
}

build_images() {
    prepare_runtime_files
    set_build_env
    echo -e "${GREEN}Building Docker images...${NC}"
    compose build
    printf "local\n" > "$LOCAL_BUILD_MARKER"
    echo -e "${GREEN}Build complete${NC}"
    echo -e "${BLUE}Local-build mode recorded. Use './scanner.sh start' or './scanner.sh restart' to run these local images.${NC}"
}

rebuild_images() {
    prepare_runtime_files
    set_build_env
    local NO_CACHE=""
    local SERVICES=""
    local SERVICE_DESC="all services"

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
                shift
                ;;
            ui)
                SERVICES="ui"
                SERVICE_DESC="UI"
                shift
                ;;
            all)
                SERVICES=""
                SERVICE_DESC="all services"
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

    if [ -n "$SERVICES" ]; then
        compose build $NO_CACHE $SERVICES
    else
        compose build $NO_CACHE
    fi

    printf "local\n" > "$LOCAL_BUILD_MARKER"
    echo -e "${GREEN}Rebuild complete${NC}"
    echo ""
    echo -e "${BLUE}Local-build mode recorded. Run './scanner.sh restart' to use the new local images.${NC}"
    echo -e "${BLUE}Use './scanner.sh restart --prebuilt' only when you intentionally want Docker Hub images.${NC}"
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
    echo "Expected local URLs:"
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
    echo "  codex   # or claude, or opencode"
}

start_agent() {
    local agent="${1:-}"
    local candidates=()

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
                    cd "$SCRIPT_DIR"
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
            compose exec -T redis redis-cli HSET gungnir:status running false > /dev/null 2>&1 || true
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
        --local|--local-build)
            USE_PREBUILT=0
            RUNTIME_MODE_EXPLICIT=1
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

# Dependency preflight for command execution
case $COMMAND in
    help|--help|-h|install-deps|doctor|env|agent|ai)
        ;;
    *)
        if ! ensure_command_dependencies "$COMMAND" "${ARGS[0]}"; then
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
        quick_scan "${ARGS[0]}"
        ;;
    scan-full)
        full_scan "${ARGS[0]}"
        ;;
    scan-smart)
        smart_scan "${ARGS[@]}"
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
    gungnir)
        gungnir_cmd "${ARGS[0]}"
        ;;
    build)
        build_images
        ;;
    rebuild)
        rebuild_images "${ARGS[@]}"
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
