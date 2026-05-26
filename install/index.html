#!/bin/sh
# Hosted bootstrap for https://install.shakerscan.com
# Usage: curl -fsSL https://install.shakerscan.com | sh

set -eu

INSTALL_URL="https://install.shakerscan.com"
REPO_RAW_BASE="${SHAKERSCAN_RAW_BASE:-https://raw.githubusercontent.com/andriyze/shakerscan/main}"
INSTALL_DIR="${SHAKERSCAN_HOME:-$HOME/.shakerscan}"
BIN_DIR="${SHAKERSCAN_BIN_DIR:-$HOME/.local/bin}"
START_AFTER_INSTALL="${SHAKERSCAN_START:-1}"

say() {
    printf '%s\n' "$*"
}

fail() {
    say "Error: $*" >&2
    exit 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

run_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif have sudo; then
        sudo "$@"
    else
        return 1
    fi
}

detect_package_manager() {
    if have apt-get; then
        echo apt
    elif have dnf; then
        echo dnf
    elif have yum; then
        echo yum
    elif have pacman; then
        echo pacman
    elif have zypper; then
        echo zypper
    elif have apk; then
        echo apk
    else
        echo ""
    fi
}

install_bootstrap_deps() {
    missing=""
    for dep in bash curl; do
        if ! have "$dep"; then
            missing="$missing $dep"
        fi
    done

    if [ -z "$missing" ]; then
        return 0
    fi

    manager="$(detect_package_manager)"
    [ -n "$manager" ] || fail "missing required tools:$missing. Install bash and curl, then re-run $INSTALL_URL"

    say "Installing bootstrap tools:$missing"
    case "$manager" in
        apt)
            run_sudo apt-get update
            run_sudo apt-get install -y bash curl ca-certificates
            ;;
        dnf|yum)
            run_sudo "$manager" -y install bash curl ca-certificates
            ;;
        pacman)
            run_sudo pacman -Sy --needed --noconfirm bash curl ca-certificates
            ;;
        zypper)
            run_sudo zypper --non-interactive install bash curl ca-certificates
            ;;
        apk)
            run_sudo apk add bash curl ca-certificates
            ;;
        *)
            fail "unsupported package manager for bootstrap tools: $manager"
            ;;
    esac
}

download() {
    src="$1"
    dst="$2"
    tmp="${dst}.tmp"
    if ! curl -fsSL "$src" -o "$tmp"; then
        rm -f "$tmp"
        fail "failed to download $src"
    fi
    mv "$tmp" "$dst"
}

install_command() {
    mkdir -p "$BIN_DIR"
    launcher="$BIN_DIR/shakerscan"
    cat > "$launcher" <<EOF
#!/bin/sh
exec "$INSTALL_DIR/scanner.sh" "\$@"
EOF
    chmod +x "$launcher"

    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            say ""
            say "Note: $BIN_DIR is not in PATH."
            say "Add this to your shell profile if the 'shakerscan' command is not found:"
            say "  export PATH=\"$BIN_DIR:\$PATH\""
            ;;
    esac
}

say "ShakerScan installer"
say ""
say "Install directory: $INSTALL_DIR"
say "Command path:      $BIN_DIR/shakerscan"
say "Source:            $REPO_RAW_BASE"
say ""

install_bootstrap_deps

mkdir -p "$INSTALL_DIR/db" "$INSTALL_DIR/results"
touch "$INSTALL_DIR/.env"

say "Downloading ShakerScan runtime files..."
download "$REPO_RAW_BASE/scanner.sh" "$INSTALL_DIR/scanner.sh"
download "$REPO_RAW_BASE/docker-compose.release.yml" "$INSTALL_DIR/docker-compose.release.yml"
download "$REPO_RAW_BASE/db/init.sql" "$INSTALL_DIR/db/init.sql"
download "$REPO_RAW_BASE/VERSION" "$INSTALL_DIR/VERSION"
download "$REPO_RAW_BASE/README.md" "$INSTALL_DIR/README.md"
download "$REPO_RAW_BASE/AGENTS.md" "$INSTALL_DIR/AGENTS.md"
download "$REPO_RAW_BASE/CLAUDE.md" "$INSTALL_DIR/CLAUDE.md"
chmod +x "$INSTALL_DIR/scanner.sh"

install_command

say ""
say "Installed ShakerScan."
say ""
say "Use prebuilt Docker Hub images:"
say "  shakerscan start"
say ""
say "Use with AI agents:"
say "  cd \"$INSTALL_DIR\""
say "  codex   # reads AGENTS.md"
say "  claude  # reads CLAUDE.md"
say ""
say "For local source builds:"
say "  git clone https://github.com/andriyze/shakerscan.git"
say "  cd shakerscan"
say "  ./scanner.sh start --local"
say ""

if [ "$START_AFTER_INSTALL" = "1" ]; then
    say "Starting ShakerScan with latest Docker Hub images..."
    cd "$INSTALL_DIR"
    exec bash "$INSTALL_DIR/scanner.sh" start -y
fi
