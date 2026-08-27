#!/bin/sh
# Hosted bootstrap for https://install.shakerscan.com
# Usage: curl -fsSL https://install.shakerscan.com | sh

set -eu

INSTALL_URL="https://install.shakerscan.com"
CHANNEL_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/main"
RELEASE_ASSET_ROOT="${SHAKERSCAN_RELEASE_ASSET_ROOT:-https://github.com/andriyze/shakerscan/releases/download}"
REPO_RAW_BASE="${SHAKERSCAN_RAW_BASE:-}"
# Files this installer owns, so an upgrade can remove what the new version retired.
OWNED_MANIFEST_NAME=".shakerscan-installed-files"
INSTALL_VERSION="${SHAKERSCAN_INSTALL_VERSION:-}"
INSTALL_DIR="${SHAKERSCAN_HOME:-$HOME/.shakerscan}"
BIN_DIR="${SHAKERSCAN_BIN_DIR:-$HOME/.local/bin}"
START_AFTER_INSTALL="${SHAKERSCAN_START:-1}"
REMOTE_ACCESS="${SHAKERSCAN_REMOTE:-0}"
INSTALL_STAGE=""

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
    case "$dst" in
        "$INSTALL_DIR"/*)
            [ -n "$INSTALL_STAGE" ] || fail "installer staging directory is unavailable"
            relative="${dst#"$INSTALL_DIR"/}"
            staged_dst="$INSTALL_STAGE/$relative"
            mkdir -p "$(dirname "$staged_dst")"
            ;;
        *)
            fail "refusing to download outside the installation directory"
            ;;
    esac
    tmp="${staged_dst}.tmp"
    if ! curl -fsSL "$src" -o "$tmp"; then
        rm -f "$tmp"
        fail "failed to download $src"
    fi
    mv "$tmp" "$staged_dst"
    # Record what this version owns. Committing with an overlaying copy left files behind that a
    # later release no longer ships -- an upgrade kept retired command files that then looked
    # installed and supported. Only paths a previous installer wrote are ever removed, so operator
    # data in the same tree (results, .env, backups) is never touched.
    printf '%s\n' "$relative" >> "$INSTALL_STAGE/$OWNED_MANIFEST_NAME"
}

cleanup_install_stage() {
    if [ -n "$INSTALL_STAGE" ] && [ -d "$INSTALL_STAGE" ]; then
        rm -rf -- "$INSTALL_STAGE"
    fi
}

prune_retired_files() {
    # The previous manifest must be read from the copy taken BEFORE the commit: `cp -R` overwrites
    # it with the new one, after which previous and staged are identical and nothing is ever pruned.
    previous="$1"
    staged="$INSTALL_STAGE/$OWNED_MANIFEST_NAME"
    [ -f "$previous" ] || return 0
    [ -f "$staged" ] || return 0
    while IFS= read -r retired_relative; do
        [ -n "$retired_relative" ] || continue
        # Refuse anything that could escape the installation directory, whatever a previous
        # manifest happens to contain.
        case "$retired_relative" in
            /*|*..*) continue ;;
        esac
        if ! grep -Fxq -- "$retired_relative" "$staged"; then
            rm -f -- "$INSTALL_DIR/$retired_relative"
        fi
    done < "$previous"
}

commit_staged_downloads() {
    [ -n "$INSTALL_STAGE" ] && [ -d "$INSTALL_STAGE" ] || \
        fail "installer staging directory is unavailable"
    previous_manifest="$INSTALL_STAGE/.previous-owned-files"
    if [ -f "$INSTALL_DIR/$OWNED_MANIFEST_NAME" ]; then
        cp "$INSTALL_DIR/$OWNED_MANIFEST_NAME" "$previous_manifest"
    fi
    # Put the new version in place first, then remove what it no longer ships: an interrupted
    # commit leaves a complete newer tree plus some stale files, never a tree with holes in it.
    cp -R "$INSTALL_STAGE/." "$INSTALL_DIR/"
    prune_retired_files "$previous_manifest"
    rm -f -- "$INSTALL_DIR/.previous-owned-files"
    cleanup_install_stage
    INSTALL_STAGE=""
}

add_path_to_profile() {
    profile="$1"
    [ -n "$profile" ] || return 0

    if [ -f "$profile" ] && grep -F "# >>> shakerscan path >>>" "$profile" >/dev/null 2>&1 && grep -F "$BIN_DIR" "$profile" >/dev/null 2>&1; then
        return 0
    fi

    mkdir -p "$(dirname "$profile")"
    touch "$profile"
    {
        printf '\n'
        printf '%s\n' '# >>> shakerscan path >>>'
        printf '%s\n' 'case ":$PATH:" in'
        printf '  *":%s:"*) ;;\n' "$BIN_DIR"
        printf '  *) export PATH="%s:$PATH" ;;\n' "$BIN_DIR"
        printf '%s\n' 'esac'
        printf '%s\n' '# <<< shakerscan path <<<'
    } >> "$profile"
    say "Added $BIN_DIR to PATH in $profile"
}

install_path_profiles() {
    shell_name=""
    if [ -n "${SHELL:-}" ]; then
        shell_name="$(basename "$SHELL")"
    fi

    add_path_to_profile "$HOME/.profile"

    case "$shell_name" in
        bash)
            add_path_to_profile "$HOME/.bashrc"
            ;;
        zsh)
            add_path_to_profile "$HOME/.zshrc"
            ;;
        fish)
            fish_profile="$HOME/.config/fish/config.fish"
            if [ ! -f "$fish_profile" ] || ! grep -F "# >>> shakerscan path >>>" "$fish_profile" >/dev/null 2>&1 || ! grep -F "$BIN_DIR" "$fish_profile" >/dev/null 2>&1; then
                mkdir -p "$(dirname "$fish_profile")"
                touch "$fish_profile"
                {
                    printf '\n'
                    printf '%s\n' '# >>> shakerscan path >>>'
                    printf 'fish_add_path "%s"\n' "$BIN_DIR"
                    printf '%s\n' '# <<< shakerscan path <<<'
                } >> "$fish_profile"
                say "Added $BIN_DIR to PATH in $fish_profile"
            fi
            ;;
    esac

    if [ -f "$HOME/.bashrc" ] && [ "$shell_name" != "bash" ]; then
        add_path_to_profile "$HOME/.bashrc"
    fi

    if [ -f "$HOME/.zshrc" ] && [ "$shell_name" != "zsh" ]; then
        add_path_to_profile "$HOME/.zshrc"
    fi
}

PATH_NEEDS_ACTIVATION=0

install_command() {
    release_image_tag="$(tr -d '[:space:]' < "$INSTALL_DIR/VERSION")"
    case "$release_image_tag" in
        ""|*[!A-Za-z0-9._-]*)
            fail "downloaded VERSION is not a safe Docker image tag"
            ;;
    esac
    mkdir -p "$BIN_DIR"
    launcher="$BIN_DIR/shakerscan"
    cat > "$launcher" <<EOF
#!/bin/sh
: "\${SCANNER_IMAGE_TAG:=$release_image_tag}"
export SCANNER_IMAGE_TAG
if [ "\${SHAKERSCAN_DISABLE_IMAGE_LOCK:-0}" != "1" ] && [ -f "$INSTALL_DIR/release-image-lock.env" ]; then
    while IFS='=' read -r key value; do
        case "\$key" in
            SCANNER_IMAGE|API_IMAGE|UI_IMAGE|SIGNER_IMAGE)
                case "\$value" in
                    *@sha256:????????????????????????????????????????????????????????????????) export "\$key=\$value" ;;
                    *) printf 'Invalid release image lock for %s\n' "\$key" >&2; exit 1 ;;
                esac
                ;;
            ''|'#'*) ;;
            *) printf 'Unsupported release image lock key: %s\n' "\$key" >&2; exit 1 ;;
        esac
    done < "$INSTALL_DIR/release-image-lock.env"
fi
exec "$INSTALL_DIR/scanner.sh" "\$@"
EOF
    chmod +x "$launcher"

    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            PATH_NEEDS_ACTIVATION=1
            install_path_profiles
            ;;
    esac
}

# Prefer the bare shakerscan command only when it resolves to this install's
# launcher; otherwise fall back to the absolute path so copied commands work.
sk() {
    resolved="$(command -v shakerscan 2>/dev/null || true)"
    if [ "$resolved" = "$BIN_DIR/shakerscan" ]; then
        printf 'shakerscan'
    else
        printf '%s' "$BIN_DIR/shakerscan"
    fi
}

print_path_activation() {
    [ "$PATH_NEEDS_ACTIVATION" = "1" ] || return 0
    say "Activate the 'shakerscan' command in THIS terminal (new shells already have it):"
    say "  export PATH=\"$BIN_DIR:\$PATH\""
    say ""
}

print_next_steps() {
    say ""
    say "--------------------------------------------------------------"
    say "  ShakerScan is ready. Two ways to use it:"
    say "--------------------------------------------------------------"
    say ""
    print_path_activation
    say "1) Drive it with an AI agent (recommended) - just ask in plain English:"
    say "     $(sk) agent        # auto-detects codex, claude, or opencode"
    say ""
    say "   Then try asking:"
    say "     \"Scan https://example.com and summarize the findings\""
    say "     \"Show me active critical and high findings\""
    say "     \"Run a Deep Hunt on my authorized staging target\""
    say "     \"Red team my chatbot API with AI Gate smoke tests\""
    say ""
    say "2) Or run it yourself from the CLI:"
    say "     $(sk) scan https://example.com   # quick scan"
    say "     $(sk) status                     # what's running + UI/API URLs"
    say "     $(sk) stop                       # stop everything"
    say ""
    if [ "$REMOTE_ACCESS" = "1" ]; then
        say "   Remote mode is on - open the UI from your laptop using the URL printed above."
    else
        say "   Open the web UI in your browser:  http://localhost:3000"
        say "   (On a remote server? Re-run with:  $(sk) start --remote)"
    fi
    say ""
    say "Optional: for AI semantic judging, add AI_API_KEY to $INSTALL_DIR/.env"
    say "Docs & more commands:  $(sk) env   |   $INSTALL_DIR/README.md"
    say ""
}

install_bootstrap_deps

# The stable install channel advances only after every release image exists.
# Runtime files are then downloaded from the matching immutable tag, avoiding
# both unpublished-image windows and main-vs-image source skew. A custom raw
# base remains an explicit development/testing escape hatch.
if [ -z "$REPO_RAW_BASE" ]; then
    if [ -n "$INSTALL_VERSION" ]; then
        if ! printf '%s' "$INSTALL_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
            fail "SHAKERSCAN_INSTALL_VERSION must be a release version such as 0.8.18"
        fi
        REPO_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/v${INSTALL_VERSION}"
    else
        stable_raw="$(curl -fsSL "$CHANNEL_RAW_BASE/install/STABLE_VERSION")" || \
            fail "failed to resolve the stable ShakerScan release channel"
        stable_version="$(printf '%s' "$stable_raw" | tr -d '[:space:]')"
        case "$stable_version" in
            ""|*[!0-9A-Za-z._-]*) fail "stable release channel returned an unsafe version" ;;
        esac
        REPO_RAW_BASE="https://raw.githubusercontent.com/andriyze/shakerscan/v${stable_version}"
        # This file carries THIS revision's file manifest, which does not describe another
        # release's tree: pointing it at an older tag makes it request files that do not exist
        # there. When the channel selects a version, hand over to that version's own installer --
        # the same handover install/bootstrap.sh performs -- so the manifest and the tree always
        # come from one revision. SHAKERSCAN_RAW_BASE is the recursion guard: the delegated
        # installer sees it set and installs instead of resolving again.
        delegate="$(mktemp "${TMPDIR:-/tmp}/shakerscan-installer.XXXXXX")" || \
            fail "failed to create a temporary file for the release installer"
        if ! curl -fsSL "$REPO_RAW_BASE/install/index.sh" -o "$delegate"; then
            rm -f -- "$delegate"
            fail "failed to download the v${stable_version} installer"
        fi
        SHAKERSCAN_INSTALL_VERSION="$stable_version" \
        SHAKERSCAN_RAW_BASE="$REPO_RAW_BASE" \
            sh "$delegate" "$@"
        delegate_status=$?
        rm -f -- "$delegate"
        exit "$delegate_status"
    fi
fi

say "ShakerScan installer"
say ""
say "Install directory: $INSTALL_DIR"
say "Command path:      $BIN_DIR/shakerscan"
say "Source:            $REPO_RAW_BASE"
say ""

mkdir -p "$INSTALL_DIR/db" "$INSTALL_DIR/results" "$INSTALL_DIR/scripts" "$INSTALL_DIR/api/scan" "$INSTALL_DIR/api/runtime"
mkdir -p "$INSTALL_DIR/scanner/scanner_tools"
mkdir -p "$INSTALL_DIR/runner/guest" "$INSTALL_DIR/runner/host"
mkdir -p "$INSTALL_DIR/skills/ai-security-session/agents" "$INSTALL_DIR/skills/ai-security-session/references"
mkdir -p "$INSTALL_DIR/skills/content-discovery/agents" "$INSTALL_DIR/skills/content-discovery/references"
mkdir -p "$INSTALL_DIR/skills/device-hunt/agents" "$INSTALL_DIR/skills/device-hunt/references"
mkdir -p "$INSTALL_DIR/skills/device-triage/agents"
mkdir -p "$INSTALL_DIR/skills/hunt"
mkdir -p "$INSTALL_DIR/skills/js-analyze/agents" "$INSTALL_DIR/skills/js-analyze/references"
mkdir -p "$INSTALL_DIR/skills/review-skills/agents"
mkdir -p "$INSTALL_DIR/skills/research-agent/agents"
mkdir -p "$INSTALL_DIR/skills/shakerscan/agents" "$INSTALL_DIR/skills/shakerscan/references"
mkdir -p "$INSTALL_DIR/.claude/agents" "$INSTALL_DIR/.claude/commands" "$INSTALL_DIR/.claude/hooks"
touch "$INSTALL_DIR/.env"
INSTALL_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-install.XXXXXX")"
trap cleanup_install_stage EXIT HUP INT TERM

say "Downloading ShakerScan runtime files..."
download "$REPO_RAW_BASE/scanner.sh" "$INSTALL_DIR/scanner.sh"
download "$REPO_RAW_BASE/docker-compose.release.yml" "$INSTALL_DIR/docker-compose.release.yml"
download "$REPO_RAW_BASE/docker-compose.worker.yml" "$INSTALL_DIR/docker-compose.worker.yml"
download "$REPO_RAW_BASE/docker-compose.broker-worker.yml" "$INSTALL_DIR/docker-compose.broker-worker.yml"
download "$REPO_RAW_BASE/db/init.sql" "$INSTALL_DIR/db/init.sql"
download "$REPO_RAW_BASE/db/configure-model-intake-signer-role.sh" "$INSTALL_DIR/db/configure-model-intake-signer-role.sh"
download "$REPO_RAW_BASE/VERSION" "$INSTALL_DIR/VERSION"
release_version="$(tr -d '[:space:]' < "$INSTALL_STAGE/VERSION")"
case "$release_version" in
    2.*)
        download "$RELEASE_ASSET_ROOT/v${release_version}/release-image-lock.env" \
            "$INSTALL_DIR/release-image-lock.env"
        for binding in \
            "SCANNER_IMAGE=shakerscan/shakerscan-scanner" \
            "API_IMAGE=shakerscan/shakerscan-api" \
            "UI_IMAGE=shakerscan/shakerscan-ui" \
            "SIGNER_IMAGE=shakerscan/shakerscan-model-intake-signer"; do
            key="${binding%%=*}"
            repository="${binding#*=}"
            value="$(sed -n "s/^${key}=//p" "$INSTALL_STAGE/release-image-lock.env")"
            if ! printf '%s' "$value" | grep -Eq "^${repository}@sha256:[0-9a-f]{64}$"; then
                fail "release image lock is missing an exact ${key} digest"
            fi
        done
        [ "$(wc -l < "$INSTALL_STAGE/release-image-lock.env" | tr -d ' ')" -eq 4 ] || \
            fail "release image lock must contain exactly four images"
        ;;
esac
download "$REPO_RAW_BASE/README.md" "$INSTALL_DIR/README.md"
download "$REPO_RAW_BASE/AGENTS.md" "$INSTALL_DIR/AGENTS.md"
download "$REPO_RAW_BASE/CLAUDE.md" "$INSTALL_DIR/CLAUDE.md"
download "$REPO_RAW_BASE/.dockerignore" "$INSTALL_DIR/.dockerignore"
download "$REPO_RAW_BASE/scripts/shakerscan_mcp.py" "$INSTALL_DIR/scripts/shakerscan_mcp.py"
download "$REPO_RAW_BASE/scripts/local_planner_adapter.py" "$INSTALL_DIR/scripts/local_planner_adapter.py"
download "$REPO_RAW_BASE/scripts/planner_evals.py" "$INSTALL_DIR/scripts/planner_evals.py"
download "$REPO_RAW_BASE/scripts/fleet_cli.py" "$INSTALL_DIR/scripts/fleet_cli.py"
download "$REPO_RAW_BASE/scripts/fleet_acceptance.py" "$INSTALL_DIR/scripts/fleet_acceptance.py"
download "$REPO_RAW_BASE/scripts/scan_cli.py" "$INSTALL_DIR/scripts/scan_cli.py"
download "$REPO_RAW_BASE/scripts/v2_cli.py" "$INSTALL_DIR/scripts/v2_cli.py"
download "$REPO_RAW_BASE/scripts/rebuild_scan_report.py" "$INSTALL_DIR/scripts/rebuild_scan_report.py"
download "$REPO_RAW_BASE/scripts/model_intake_runner_cli.py" "$INSTALL_DIR/scripts/model_intake_runner_cli.py"
download "$REPO_RAW_BASE/scripts/build-model-intake-guest-rootfs.sh" "$INSTALL_DIR/scripts/build-model-intake-guest-rootfs.sh"
download "$REPO_RAW_BASE/scripts/provision-model-intake-firecracker.sh" "$INSTALL_DIR/scripts/provision-model-intake-firecracker.sh"
download "$REPO_RAW_BASE/api/command_arsenal.py" "$INSTALL_DIR/api/command_arsenal.py"
download "$REPO_RAW_BASE/api/model_intake_control_plane.py" "$INSTALL_DIR/api/model_intake_control_plane.py"
download "$REPO_RAW_BASE/api/model_intake_components.py" "$INSTALL_DIR/api/model_intake_components.py"
download "$REPO_RAW_BASE/api/model_intake_loader_profiles.py" "$INSTALL_DIR/api/model_intake_loader_profiles.py"
download "$REPO_RAW_BASE/api/model_intake_runner_inputs.py" "$INSTALL_DIR/api/model_intake_runner_inputs.py"
download "$REPO_RAW_BASE/api/model_intake_runner_controller.py" "$INSTALL_DIR/api/model_intake_runner_controller.py"
download "$REPO_RAW_BASE/api/model_intake_runner_receipts.py" "$INSTALL_DIR/api/model_intake_runner_receipts.py"
download "$REPO_RAW_BASE/api/model_intake_firecracker_runner.py" "$INSTALL_DIR/api/model_intake_firecracker_runner.py"
download "$REPO_RAW_BASE/api/model_intake_runner_storage.py" "$INSTALL_DIR/api/model_intake_runner_storage.py"
download "$REPO_RAW_BASE/api/model_intake_runner_service.py" "$INSTALL_DIR/api/model_intake_runner_service.py"
download "$REPO_RAW_BASE/api/scan/__init__.py" "$INSTALL_DIR/api/scan/__init__.py"
download "$REPO_RAW_BASE/api/scan/action_plan.py" "$INSTALL_DIR/api/scan/action_plan.py"
download "$REPO_RAW_BASE/api/scan/capability_result.py" "$INSTALL_DIR/api/scan/capability_result.py"
download "$REPO_RAW_BASE/api/scan/continuation.py" "$INSTALL_DIR/api/scan/continuation.py"
download "$REPO_RAW_BASE/api/scan/execution.py" "$INSTALL_DIR/api/scan/execution.py"
download "$REPO_RAW_BASE/api/scan/external_process.py" "$INSTALL_DIR/api/scan/external_process.py"
download "$REPO_RAW_BASE/api/scan/finalizer.py" "$INSTALL_DIR/api/scan/finalizer.py"
download "$REPO_RAW_BASE/api/scan/report_rebuild.py" "$INSTALL_DIR/api/scan/report_rebuild.py"
download "$REPO_RAW_BASE/api/scan/surface_manifest.py" "$INSTALL_DIR/api/scan/surface_manifest.py"
download "$REPO_RAW_BASE/api/scan/work_manifests.py" "$INSTALL_DIR/api/scan/work_manifests.py"
download "$REPO_RAW_BASE/api/scan/contracts.py" "$INSTALL_DIR/api/scan/contracts.py"
download "$REPO_RAW_BASE/api/runtime/__init__.py" "$INSTALL_DIR/api/runtime/__init__.py"
download "$REPO_RAW_BASE/api/runtime/budget_reservations.py" "$INSTALL_DIR/api/runtime/budget_reservations.py"
download "$REPO_RAW_BASE/api/runtime/budgets.py" "$INSTALL_DIR/api/runtime/budgets.py"
download "$REPO_RAW_BASE/api/runtime/capability_registry.py" "$INSTALL_DIR/api/runtime/capability_registry.py"
download "$REPO_RAW_BASE/api/runtime/credentials.py" "$INSTALL_DIR/api/runtime/credentials.py"
download "$REPO_RAW_BASE/api/runtime/models.py" "$INSTALL_DIR/api/runtime/models.py"
download "$REPO_RAW_BASE/api/runtime/observation_manifests.py" "$INSTALL_DIR/api/runtime/observation_manifests.py"
download "$REPO_RAW_BASE/api/runtime/receipts.py" "$INSTALL_DIR/api/runtime/receipts.py"
download "$REPO_RAW_BASE/api/runtime/json_fields.py" "$INSTALL_DIR/api/runtime/json_fields.py"
download "$REPO_RAW_BASE/api/agent_tools.py" "$INSTALL_DIR/api/agent_tools.py"
download "$REPO_RAW_BASE/api/check_registry.py" "$INSTALL_DIR/api/check_registry.py"
download "$REPO_RAW_BASE/api/http_experiment.py" "$INSTALL_DIR/api/http_experiment.py"
download "$REPO_RAW_BASE/api/secret_store.py" "$INSTALL_DIR/api/secret_store.py"
download "$REPO_RAW_BASE/api/target_address_policy.py" "$INSTALL_DIR/api/target_address_policy.py"
download "$REPO_RAW_BASE/api/capabilities/http.py" "$INSTALL_DIR/api/capabilities/http.py"
download "$REPO_RAW_BASE/api/capabilities/auth.py" "$INSTALL_DIR/api/capabilities/auth.py"
download "$REPO_RAW_BASE/api/runtime/v2_runtime_hardening.py" "$INSTALL_DIR/api/runtime/v2_runtime_hardening.py"
download "$REPO_RAW_BASE/api/runtime/credential_resolver.py" "$INSTALL_DIR/api/runtime/credential_resolver.py"
download "$REPO_RAW_BASE/api/runtime/credential_store.py" "$INSTALL_DIR/api/runtime/credential_store.py"
download "$REPO_RAW_BASE/api/runtime/scan_credentials.py" "$INSTALL_DIR/api/runtime/scan_credentials.py"
download "$REPO_RAW_BASE/api/runtime/request_collection_store.py" "$INSTALL_DIR/api/runtime/request_collection_store.py"
download "$REPO_RAW_BASE/api/runtime/target_bound_socket.py" "$INSTALL_DIR/api/runtime/target_bound_socket.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/__init__.py" "$INSTALL_DIR/scanner/scanner_tools/__init__.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/build_fingerprint.py" "$INSTALL_DIR/scanner/scanner_tools/build_fingerprint.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/device_postman.py" "$INSTALL_DIR/scanner/scanner_tools/device_postman.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/request_replay.py" "$INSTALL_DIR/scanner/scanner_tools/request_replay.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/request_collections.py" "$INSTALL_DIR/scanner/scanner_tools/request_collections.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/device_request_formats.py" "$INSTALL_DIR/scanner/scanner_tools/device_request_formats.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/url_redaction.py" "$INSTALL_DIR/scanner/scanner_tools/url_redaction.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/v2_fingerprint_hardening.py" "$INSTALL_DIR/scanner/scanner_tools/v2_fingerprint_hardening.py"
download "$REPO_RAW_BASE/scanner/scanner_tools/v2_request_replay_hardening.py" "$INSTALL_DIR/scanner/scanner_tools/v2_request_replay_hardening.py"
download "$REPO_RAW_BASE/scanner/manifests.py" "$INSTALL_DIR/scanner/manifests.py"
download "$REPO_RAW_BASE/runner/guest/Dockerfile" "$INSTALL_DIR/runner/guest/Dockerfile"
download "$REPO_RAW_BASE/runner/guest/guest-init" "$INSTALL_DIR/runner/guest/guest-init"
download "$REPO_RAW_BASE/runner/guest/guest_worker.py" "$INSTALL_DIR/runner/guest/guest_worker.py"
download "$REPO_RAW_BASE/runner/guest/requirements.in" "$INSTALL_DIR/runner/guest/requirements.in"
download "$REPO_RAW_BASE/runner/guest/requirements.lock" "$INSTALL_DIR/runner/guest/requirements.lock"
download "$REPO_RAW_BASE/runner/host/requirements.in" "$INSTALL_DIR/runner/host/requirements.in"
download "$REPO_RAW_BASE/runner/host/requirements.lock" "$INSTALL_DIR/runner/host/requirements.lock"
download "$REPO_RAW_BASE/runner/host/system-requirements.ubuntu.txt" "$INSTALL_DIR/runner/host/system-requirements.ubuntu.txt"
download "$REPO_RAW_BASE/skills/README.md" "$INSTALL_DIR/skills/README.md"
download "$REPO_RAW_BASE/skills/scanner-skill.md" "$INSTALL_DIR/skills/scanner-skill.md"
download "$REPO_RAW_BASE/skills/ai-security-session/SKILL.md" "$INSTALL_DIR/skills/ai-security-session/SKILL.md"
download "$REPO_RAW_BASE/skills/ai-security-session/agents/openai.yaml" "$INSTALL_DIR/skills/ai-security-session/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/ai-security-session/references/api.md" "$INSTALL_DIR/skills/ai-security-session/references/api.md"
download "$REPO_RAW_BASE/skills/content-discovery/SKILL.md" "$INSTALL_DIR/skills/content-discovery/SKILL.md"
download "$REPO_RAW_BASE/skills/content-discovery/agents/openai.yaml" "$INSTALL_DIR/skills/content-discovery/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/content-discovery/references/shakerscan.md" "$INSTALL_DIR/skills/content-discovery/references/shakerscan.md"
download "$REPO_RAW_BASE/skills/device-hunt/SKILL.md" "$INSTALL_DIR/skills/device-hunt/SKILL.md"
download "$REPO_RAW_BASE/skills/device-hunt/agents/openai.yaml" "$INSTALL_DIR/skills/device-hunt/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/device-hunt/references/smart-tv-platforms.md" "$INSTALL_DIR/skills/device-hunt/references/smart-tv-platforms.md"
download "$REPO_RAW_BASE/skills/device-hunt/references/smart-tv-protocol-application.md" "$INSTALL_DIR/skills/device-hunt/references/smart-tv-protocol-application.md"
download "$REPO_RAW_BASE/skills/device-hunt/references/smart-tv-capabilities.md" "$INSTALL_DIR/skills/device-hunt/references/smart-tv-capabilities.md"
download "$REPO_RAW_BASE/skills/device-hunt/references/smart-tv-artifacts-sensors-lab.md" "$INSTALL_DIR/skills/device-hunt/references/smart-tv-artifacts-sensors-lab.md"
download "$REPO_RAW_BASE/skills/device-triage/SKILL.md" "$INSTALL_DIR/skills/device-triage/SKILL.md"
download "$REPO_RAW_BASE/skills/device-triage/agents/openai.yaml" "$INSTALL_DIR/skills/device-triage/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/hunt/SKILL.md" "$INSTALL_DIR/skills/hunt/SKILL.md"
download "$REPO_RAW_BASE/skills/js-analyze/SKILL.md" "$INSTALL_DIR/skills/js-analyze/SKILL.md"
download "$REPO_RAW_BASE/skills/js-analyze/agents/openai.yaml" "$INSTALL_DIR/skills/js-analyze/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/js-analyze/references/shakerscan.md" "$INSTALL_DIR/skills/js-analyze/references/shakerscan.md"
download "$REPO_RAW_BASE/skills/review-skills/SKILL.md" "$INSTALL_DIR/skills/review-skills/SKILL.md"
download "$REPO_RAW_BASE/skills/review-skills/agents/openai.yaml" "$INSTALL_DIR/skills/review-skills/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/research-agent/SKILL.md" "$INSTALL_DIR/skills/research-agent/SKILL.md"
download "$REPO_RAW_BASE/skills/research-agent/agents/openai.yaml" "$INSTALL_DIR/skills/research-agent/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/shakerscan/SKILL.md" "$INSTALL_DIR/skills/shakerscan/SKILL.md"
download "$REPO_RAW_BASE/skills/shakerscan/agents/openai.yaml" "$INSTALL_DIR/skills/shakerscan/agents/openai.yaml"
download "$REPO_RAW_BASE/skills/shakerscan/references/model-intake.md" "$INSTALL_DIR/skills/shakerscan/references/model-intake.md"
download "$REPO_RAW_BASE/.claude/agents/content-discovery-agent.md" "$INSTALL_DIR/.claude/agents/content-discovery-agent.md"
download "$REPO_RAW_BASE/.claude/agents/js-analysis-agent.md" "$INSTALL_DIR/.claude/agents/js-analysis-agent.md"
download "$REPO_RAW_BASE/.claude/agents/skills-reviewer.md" "$INSTALL_DIR/.claude/agents/skills-reviewer.md"
download "$REPO_RAW_BASE/.claude/commands/ai-gate.md" "$INSTALL_DIR/.claude/commands/ai-gate.md"
download "$REPO_RAW_BASE/.claude/commands/ai-security-session.md" "$INSTALL_DIR/.claude/commands/ai-security-session.md"
download "$REPO_RAW_BASE/.claude/commands/content-discovery.md" "$INSTALL_DIR/.claude/commands/content-discovery.md"
download "$REPO_RAW_BASE/.claude/commands/deep-hunt.md" "$INSTALL_DIR/.claude/commands/deep-hunt.md"
download "$REPO_RAW_BASE/.claude/commands/findings.md" "$INSTALL_DIR/.claude/commands/findings.md"
download "$REPO_RAW_BASE/.claude/commands/js-analyze.md" "$INSTALL_DIR/.claude/commands/js-analyze.md"
download "$REPO_RAW_BASE/.claude/commands/research.md" "$INSTALL_DIR/.claude/commands/research.md"
download "$REPO_RAW_BASE/.claude/commands/review-skills.md" "$INSTALL_DIR/.claude/commands/review-skills.md"
download "$REPO_RAW_BASE/.claude/commands/save-finding.md" "$INSTALL_DIR/.claude/commands/save-finding.md"
download "$REPO_RAW_BASE/.claude/commands/scan.md" "$INSTALL_DIR/.claude/commands/scan.md"
download "$REPO_RAW_BASE/.claude/commands/status.md" "$INSTALL_DIR/.claude/commands/status.md"
download "$REPO_RAW_BASE/.claude/commands/subdomains.md" "$INSTALL_DIR/.claude/commands/subdomains.md"
download "$REPO_RAW_BASE/.claude/commands/workers.md" "$INSTALL_DIR/.claude/commands/workers.md"
download "$REPO_RAW_BASE/.claude/hooks/session-start.sh" "$INSTALL_DIR/.claude/hooks/session-start.sh"
download "$REPO_RAW_BASE/.claude/settings.json" "$INSTALL_DIR/.claude/settings.json"
if [ -d "$INSTALL_DIR/db/configure-model-intake-signer-role.sh" ]; then
    rmdir "$INSTALL_DIR/db/configure-model-intake-signer-role.sh" || \
        fail "cannot replace non-empty signer role script directory from an earlier broken install"
fi
commit_staged_downloads
chmod +x "$INSTALL_DIR/scanner.sh"
chmod +x "$INSTALL_DIR/db/configure-model-intake-signer-role.sh"
chmod +x "$INSTALL_DIR/scripts/build-model-intake-guest-rootfs.sh"
chmod +x "$INSTALL_DIR/scripts/provision-model-intake-firecracker.sh"
chmod +x "$INSTALL_DIR/.claude/hooks/session-start.sh"

install_command

say ""
say "Installed ShakerScan to $INSTALL_DIR"
say ""

if [ "$START_AFTER_INSTALL" != "1" ]; then
    # Not auto-starting: show how to start, then the usage summary.
    say "Start the scanner when ready:"
    say "  $(sk) start            # local (UI stays on http://localhost:3000)"
    say "  $(sk) start --remote   # VPS access over Tailscale"
    print_next_steps
    say "Upgrade later by re-running:  curl -fsSL https://install.shakerscan.com | sh"
    exit 0
fi

say "Starting ShakerScan with release Docker Hub images (the first pull may take several minutes)..."
say ""
cd "$INSTALL_DIR"
start_rc=0
if [ "$REMOTE_ACCESS" = "1" ]; then
    "$BIN_DIR/shakerscan" start -y --remote || start_rc=$?
else
    "$BIN_DIR/shakerscan" start -y || start_rc=$?
fi

if [ "$start_rc" -ne 0 ]; then
    say ""
    say "Startup did not finish cleanly (exit $start_rc)."
    say "Check what happened, then retry:"
    say "  $(sk) status"
    say "  $(sk) logs -f"
    say "  $(sk) start"
    exit "$start_rc"
fi

# scanner.sh prints health + UI/API URLs above; add the "what now" guidance last
# so it is the final thing on screen rather than a pull progress bar.
print_next_steps
say "Upgrade later by re-running:  curl -fsSL https://install.shakerscan.com | sh"
