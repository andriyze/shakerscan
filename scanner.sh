#!/bin/bash
# Shaker Scan - CLI Management Tool
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
WORKERS=${WORKERS:-5}
ASSUME_YES=0
FOLLOW=""
ARGS=()
DOCKER_COMPOSE_CMD=()
COMPOSE_FILE_ARGS=()
PLATFORM=""
PLATFORM_VERSION=""
USE_PREBUILT=1
PREBUILT_COMPOSE_FILE="docker-compose.prebuilt.yml"
IMAGE_TAG_OVERRIDE=""

command_exists() {
    command -v "$1" > /dev/null 2>&1
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
    COMPOSE_FILE_ARGS=(-f docker-compose.yml)
    if [ "$USE_PREBUILT" -eq 1 ]; then
        COMPOSE_FILE_ARGS+=(-f "$PREBUILT_COMPOSE_FILE")
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

compose_run() {
    compose run "$@"
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

    case "$(uname -s)" in
        Darwin)
            PLATFORM="macos"
            PLATFORM_VERSION="$(sw_vers -productVersion 2>/dev/null || echo "")"
            ;;
        Linux)
            if [ -f /etc/os-release ]; then
                # shellcheck disable=SC1091
                source /etc/os-release
                if [ "$ID" = "ubuntu" ]; then
                    PLATFORM="ubuntu"
                    PLATFORM_VERSION="${VERSION_ID:-}"
                else
                    PLATFORM="linux-other"
                    PLATFORM_VERSION="${ID:-linux}"
                fi
            else
                PLATFORM="linux-other"
                PLATFORM_VERSION="unknown"
            fi
            ;;
    esac
}

apt_has_package() {
    apt-cache show "$1" > /dev/null 2>&1
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

install_dependencies_ubuntu() {
    local packages=()
    local compose_pkg=""
    local added_to_docker_group=0
    local needs_apt_update=0

    if [ "$PLATFORM_VERSION" != "24.04" ]; then
        echo -e "${YELLOW}Note: Ubuntu $PLATFORM_VERSION detected. Installer is optimized for Ubuntu 24.04.${NC}"
    fi

    if ! command_exists docker; then
        packages+=("docker.io")
        needs_apt_update=1
    fi

    if ! command_exists curl; then
        packages+=("curl")
        needs_apt_update=1
    fi

    if ! command_exists jq; then
        packages+=("jq")
        needs_apt_update=1
    fi

    if ! has_docker_compose; then
        needs_apt_update=1
    fi

    if [ "$needs_apt_update" -eq 1 ]; then
        run_with_sudo apt-get update
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
            echo -e "${RED}Error: Could not find a Docker Compose package in apt repositories${NC}"
            return 1
        fi
    fi

    if [ ${#packages[@]} -eq 0 ]; then
        echo -e "${GREEN}All required dependencies are already installed${NC}"
    else
        echo -e "${GREEN}Installing packages: ${packages[*]}${NC}"
        run_with_sudo apt-get install -y "${packages[@]}"
    fi

    if command_exists docker && command_exists systemctl; then
        run_with_sudo systemctl enable docker > /dev/null 2>&1 || true
        run_with_sudo systemctl start docker > /dev/null 2>&1 || true
    fi

    if command_exists docker && command_exists getent && getent group docker > /dev/null 2>&1; then
        if [ "$(id -u)" -ne 0 ] && ! id -nG "$USER" | grep -qw docker; then
            run_with_sudo usermod -aG docker "$USER" || true
            added_to_docker_group=1
        fi
    fi

    if [ "$added_to_docker_group" -eq 1 ]; then
        echo -e "${YELLOW}You were added to the docker group. Log out/in (or run 'newgrp docker') for permission changes.${NC}"
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
        ubuntu)
            install_dependencies_ubuntu
            ;;
        macos)
            install_dependencies_macos
            ;;
        *)
            echo -e "${RED}Automatic install is supported on Ubuntu 24.04 and macOS.${NC}"
            echo "Install manually: Docker + Docker Compose + curl + jq"
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
        status|scan|scan-full|scan-smart)
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
        if ! docker info > /dev/null 2>&1; then
            detect_platform
            if [ "$PLATFORM" = "ubuntu" ] && command_exists systemctl; then
                echo -e "${YELLOW}Docker daemon is not running. Attempting to start Docker...${NC}"
                run_with_sudo systemctl start docker > /dev/null 2>&1 || true
            elif [ "$PLATFORM" = "macos" ]; then
                echo -e "${YELLOW}Docker daemon is not running. Launching Docker Desktop...${NC}"
                open -a Docker > /dev/null 2>&1 || true
            fi
        fi

        if ! docker info > /dev/null 2>&1; then
            echo -e "${RED}Error: Docker daemon is not running${NC}"
            if [ "$PLATFORM" = "macos" ]; then
                echo "Open Docker Desktop and wait until it is ready."
            elif [ "$PLATFORM" = "ubuntu" ]; then
                echo "Try: sudo systemctl start docker"
            fi
            return 1
        fi

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
    image_tag="${SCANNER_IMAGE_TAG:-$release_version}"

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
        if is_truthy "${SCANNER_USE_PREBUILT}"; then
            USE_PREBUILT=1
        else
            USE_PREBUILT=0
        fi
    fi

    if is_truthy "${SCANNER_LOCAL_BUILD:-0}"; then
        USE_PREBUILT=0
    fi

    if [ -n "$IMAGE_TAG_OVERRIDE" ]; then
        export SCANNER_IMAGE_TAG="$IMAGE_TAG_OVERRIDE"
    fi

    export SCANNER_IMAGE_REPO="${SCANNER_IMAGE_REPO:-shakerscan/shakerscan-scanner}"
    export UI_IMAGE_REPO="${UI_IMAGE_REPO:-shakerscan/shakerscan-ui}"
    export SCANNER_RELEASE_VERSION="$(get_release_version)"
    export SCANNER_IMAGE_TAG="${SCANNER_IMAGE_TAG:-$SCANNER_RELEASE_VERSION}"

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

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║     Shaker Scan - Open Source Edition   ║"
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
    echo "  --image-tag TAG    Override Docker image tag (default: VERSION file)"
    echo ""
    echo "Examples:"
    echo "  ./scanner.sh start                    # Start with prebuilt images"
    echo "  ./scanner.sh start --local            # Build locally and start"
    echo "  ./scanner.sh start -w 10              # Start with 10 workers"
    echo "  ./scanner.sh start --image-tag 0.2.0  # Use a specific published tag"
    echo "  ./scanner.sh scale 10                 # Scale to 10 workers"
    echo "  ./scanner.sh scan https://example.com # Quick scan"
    echo "  ./scanner.sh install-deps             # Install dependencies"
    echo "  ./scanner.sh logs worker -f           # Follow worker logs"
    echo ""
    echo "Access:"
    echo "  UI:  http://localhost:3000"
    echo "  API: http://localhost:8080"
}

start_services() {
    set_build_env
    echo -e "${GREEN}Starting Shaker Scan with $WORKERS workers...${NC}"
    if [ "$USE_PREBUILT" -eq 1 ]; then
        echo "Mode: prebuilt images"
        echo "  scanner: ${SCANNER_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
        echo "  ui:      ${UI_IMAGE_REPO}:${SCANNER_IMAGE_TAG}"
    else
        echo "Mode: local build"
    fi
    compose_up -d --scale worker=$WORKERS
    echo ""
    echo -e "${GREEN}Services started!${NC}"
    echo "  UI:  http://localhost:3000"
    echo "  API: http://localhost:8080"
    echo ""
    echo "Use './scanner.sh status' to check service health"
    echo "Use './scanner.sh logs -f' to follow logs"
}

stop_services() {
    echo -e "${YELLOW}Stopping Shaker Scan...${NC}"
    compose down
    echo -e "${GREEN}Services stopped${NC}"
}

restart_services() {
    stop_services
    start_services
}

show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    compose ps
    echo ""

    # Check API health
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        HEALTH=$(curl -s http://localhost:8080/health)
        echo -e "API Health: ${GREEN}$(echo $HEALTH | jq -r '.status')${NC}"
        echo "  Database: $(echo $HEALTH | jq -r '.database')"
        echo "  Redis: $(echo $HEALTH | jq -r '.redis')"
    else
        echo -e "API Health: ${RED}Not responding${NC}"
    fi

    # Check queue stats
    if curl -s http://localhost:8080/queue/stats > /dev/null 2>&1; then
        QUEUE=$(curl -s http://localhost:8080/queue/stats)
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
    RESULT=$(curl -s -X POST http://localhost:8080/scans \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": {\"quick\": true}}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: http://localhost:3000/scans"
}

full_scan() {
    TARGET=$1
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Please provide a target URL${NC}"
        echo "Usage: ./scanner.sh scan-full <target>"
        exit 1
    fi

    echo -e "${YELLOW}Starting full assessment: $TARGET${NC}"
    echo -e "${YELLOW}Warning: This includes active vulnerability testing.${NC}"
    echo ""

    RESULT=$(curl -s -X POST http://localhost:8080/scans \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": {\"quick\": false, \"thorough\": true, \"active\": true}}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: http://localhost:3000/scans"
}

smart_scan() {
    TARGET=$1
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Please provide a target URL${NC}"
        echo "Usage: ./scanner.sh scan-smart <target>"
        exit 1
    fi

    echo -e "${YELLOW}Starting smart adaptive scan: $TARGET${NC}"
    echo -e "${YELLOW}Warning: This includes active vulnerability testing with DBMS-aware attacks.${NC}"
    echo ""

    RESULT=$(curl -s -X POST http://localhost:8080/scans \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$TARGET\", \"options\": {\"scan_type\": \"smart\"}}")

    SCAN_ID=$(echo $RESULT | jq -r '.scan_id')
    echo "Scan ID: $SCAN_ID"
    echo "Status: $(echo $RESULT | jq -r '.status')"
    echo ""
    echo "View progress at: http://localhost:3000/scans"
}

build_images() {
    set_build_env
    echo -e "${GREEN}Building Docker images...${NC}"
    compose build
    echo -e "${GREEN}Build complete${NC}"
}

rebuild_images() {
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

    echo -e "${GREEN}Rebuild complete${NC}"
    echo ""
    echo -e "${BLUE}Run './scanner.sh restart' to use the new images${NC}"
}

reset_database() {
    echo -e "${RED}WARNING: This will delete all scan data!${NC}"
    read -p "Are you sure? (yes/no): " CONFIRM
    if [ "$CONFIRM" = "yes" ]; then
        echo "Stopping services..."
        compose down -v
        echo "Starting fresh..."
        compose_up -d --scale worker=$WORKERS
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
            if curl -s http://localhost:8080/gungnir/status > /dev/null 2>&1; then
                STATUS=$(curl -s http://localhost:8080/gungnir/status)
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
            shift
            ;;
        --prebuilt)
            USE_PREBUILT=1
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
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

configure_runtime_mode "$COMMAND"

# Dependency preflight for command execution
case $COMMAND in
    help|--help|-h|install-deps)
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
        smart_scan "${ARGS[0]}"
        ;;
    install-deps)
        install_dependencies
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
