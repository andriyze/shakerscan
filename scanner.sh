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

set_build_env() {
    local version
    version=$(get_build_version)
    export SCANNER_VERSION="$version"
    export GIT_COMMIT="$version"
    export NEXT_PUBLIC_APP_VERSION="$version"
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
    echo ""
    echo "Examples:"
    echo "  ./scanner.sh start                    # Start with 5 workers (default)"
    echo "  ./scanner.sh start -w 10              # Start with 10 workers"
    echo "  ./scanner.sh scale 10                 # Scale to 10 workers"
    echo "  ./scanner.sh scan https://example.com # Quick scan"
    echo "  ./scanner.sh logs worker -f           # Follow worker logs"
    echo ""
    echo "Access:"
    echo "  UI:  http://localhost:3000"
    echo "  API: http://localhost:8080"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        exit 1
    fi
    if ! docker info &> /dev/null; then
        echo -e "${RED}Error: Docker daemon is not running${NC}"
        exit 1
    fi
}

start_services() {
    set_build_env
    echo -e "${GREEN}Starting Shaker Scan with $WORKERS workers...${NC}"
    docker compose up -d --scale worker=$WORKERS
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
    docker compose down
    echo -e "${GREEN}Services stopped${NC}"
}

restart_services() {
    stop_services
    start_services
}

show_status() {
    echo -e "${BLUE}Service Status:${NC}"
    docker compose ps
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
            docker compose logs -f
        else
            docker compose logs --tail=100
        fi
    else
        if [ "$FOLLOW" = "-f" ]; then
            docker compose logs -f $SERVICE
        else
            docker compose logs --tail=100 $SERVICE
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
    docker compose build
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
        docker compose build $NO_CACHE $SERVICES
    else
        docker compose build $NO_CACHE
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
        docker compose down -v
        echo "Starting fresh..."
        docker compose up -d --scale worker=$WORKERS
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
    docker compose up -d --scale worker=$COUNT --no-recreate worker
    echo ""

    # Show current worker count
    RUNNING=$(docker compose ps worker --format json 2>/dev/null | grep -c '"State":"running"' || echo "?")
    echo -e "${GREEN}Workers scaled: $RUNNING running${NC}"
}

open_shell() {
    echo "Opening shell in scanner container..."
    docker compose run --rm worker /bin/bash
}

gungnir_cmd() {
    SUBCMD=${1:-"status"}

    case $SUBCMD in
        start)
            echo -e "${GREEN}Starting Gungnir CT monitor...${NC}"
            docker compose --profile gungnir up -d gungnir-worker
            echo -e "${GREEN}Gungnir started. Monitoring CT logs for all targets.${NC}"
            echo ""
            echo "Use './scanner.sh gungnir status' to check status"
            echo "Use './scanner.sh gungnir logs' to view logs"
            ;;
        stop)
            echo -e "${YELLOW}Stopping Gungnir CT monitor...${NC}"
            docker compose stop gungnir-worker
            # Update Redis status
            docker compose exec -T redis redis-cli HSET gungnir:status running false > /dev/null 2>&1 || true
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
            docker compose logs --tail=100 gungnir-worker ${FOLLOW:-}
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
            WORKERS="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW="-f"
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Execute command
check_docker

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
