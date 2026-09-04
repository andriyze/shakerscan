#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shakerscan-installer-smoke.XXXXXX")"
SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd -P)"
trap 'rm -rf "$SMOKE_ROOT"' EXIT

export HOME="$SMOKE_ROOT/home"
export SHAKERSCAN_HOME="$HOME/.shakerscan"
export SHAKERSCAN_BIN_DIR="$HOME/.local/bin"
export SHAKERSCAN_RAW_BASE="file://$ROOT_DIR"
export SHAKERSCAN_START=0
export SHAKERSCAN_DISABLE_IMAGE_LOCK=1
export SHELL=/bin/bash

mkdir -p "$HOME"
version="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
mkdir -p "$SMOKE_ROOT/assets/v$version"
printf '%s\n' \
  "SCANNER_IMAGE=shakerscan/shakerscan-scanner@sha256:$(printf '1%.0s' {1..64})" \
  "API_IMAGE=shakerscan/shakerscan-api@sha256:$(printf '2%.0s' {1..64})" \
  "UI_IMAGE=shakerscan/shakerscan-ui@sha256:$(printf '3%.0s' {1..64})" \
  "SIGNER_IMAGE=shakerscan/shakerscan-model-intake-signer@sha256:$(printf '4%.0s' {1..64})" \
  "MODEL_INTAKE_IMAGE=shakerscan/shakerscan-model-intake@sha256:$(printf '5%.0s' {1..64})" \
  "RUNTIME_MANIFEST_SHA256=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$ROOT_DIR/install/MANIFEST.sha256")" \
  > "$SMOKE_ROOT/assets/v$version/release-image-lock.env"
export SHAKERSCAN_RELEASE_ASSET_ROOT="file://$SMOKE_ROOT/assets"
# Docker created this empty directory on affected 0.8.0 installs because the
# bootstrap omitted the bind-mounted signer role script. The next installer
# must repair that state rather than nesting the script inside the directory.
mkdir -p "$SHAKERSCAN_HOME/db/configure-model-intake-signer-role.sh"
sh "$ROOT_DIR/install/index.sh" >/dev/null
export PATH="$SHAKERSCAN_BIN_DIR:$PATH"

required_files=(
  scanner.sh
  docker-compose.release.yml
  docker-compose.worker.yml
  docker-compose.broker-worker.yml
  db/init.sql
  db/configure-model-intake-signer-role.sh
  VERSION
  release-image-lock.env
  README.md
  AGENTS.md
  CLAUDE.md
  .dockerignore
  scripts/shakerscan_mcp.py
  scripts/local_planner_adapter.py
  scripts/planner_evals.py
  scripts/fleet_cli.py
  scripts/fleet_acceptance.py
  scripts/scan_cli.py
  scripts/v2_cli.py
  scripts/rebuild_scan_report.py
  scripts/model_intake_runner_cli.py
  scripts/build-model-intake-guest-rootfs.sh
  scripts/provision-model-intake-firecracker.sh
  api/command_arsenal.py
  api/model_intake_control_plane.py
  api/model_intake_components.py
  api/model_intake_loader_profiles.py
  api/model_intake_runner_inputs.py
  api/model_intake_runner_controller.py
  api/model_intake_runner_receipts.py
  api/model_intake_firecracker_runner.py
  api/model_intake_runner_service.py
  api/scan/__init__.py
  api/scan/action_plan.py
  api/scan/capability_result.py
  api/scan/continuation.py
  api/scan/execution.py
  api/scan/external_process.py
  api/scan/finalizer.py
  api/scan/scoring.py
  api/scan/report_rebuild.py
  api/scan/surface_manifest.py
  api/scan/work_manifests.py
  api/runtime/__init__.py
  api/runtime/budget_reservations.py
  api/runtime/budgets.py
  api/runtime/capability_registry.py
  api/runtime/credentials.py
  api/runtime/models.py
  api/runtime/observation_manifests.py
  api/runtime/receipts.py
  api/runtime/v2_runtime_hardening.py
  scanner/ai_verdict_policy.py
  scanner/risk_scoring.py
  scanner/score_bands.py
  scanner/scanner_tools/__init__.py
  scanner/scanner_tools/build_fingerprint.py
  scanner/scanner_tools/device_postman.py
  scanner/scanner_tools/request_replay.py
  scanner/scanner_tools/url_redaction.py
  scanner/scanner_tools/v2_fingerprint_hardening.py
  scanner/scanner_tools/v2_request_replay_hardening.py
  scanner/manifests.py
  runner/guest/Dockerfile
  runner/guest/guest-init
  runner/guest/guest_worker.py
  runner/guest/requirements.in
  runner/guest/requirements.lock
  runner/host/requirements.in
  runner/host/requirements.lock
  runner/host/system-requirements.ubuntu.txt
  skills/device-hunt/SKILL.md
  skills/device-hunt/agents/openai.yaml
  skills/device-hunt/references/smart-tv-platforms.md
  skills/device-hunt/references/smart-tv-protocol-application.md
  skills/device-hunt/references/smart-tv-capabilities.md
  skills/device-hunt/references/smart-tv-artifacts-sensors-lab.md
  skills/device-triage/SKILL.md
  skills/device-triage/agents/openai.yaml
)

for relative_path in "${required_files[@]}"; do
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing runtime file $relative_path" >&2
    exit 1
  fi
done

while IFS= read -r source_path; do
  relative_path="${source_path#"$ROOT_DIR"/}"
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing skill asset $relative_path" >&2
    exit 1
  fi
done < <(find "$ROOT_DIR/skills" -type f -print | sort)

for source_path in "$ROOT_DIR"/.claude/commands/*.md; do
  relative_path="${source_path#"$ROOT_DIR"/}"
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing command $relative_path" >&2
    exit 1
  fi
done

test -x "$SHAKERSCAN_BIN_DIR/shakerscan"
test -x "$SHAKERSCAN_HOME/scanner.sh"
test -x "$SHAKERSCAN_HOME/db/configure-model-intake-signer-role.sh"
test -x "$SHAKERSCAN_HOME/scripts/build-model-intake-guest-rootfs.sh"
test -x "$SHAKERSCAN_HOME/scripts/provision-model-intake-firecracker.sh"
test -x "$SHAKERSCAN_HOME/.claude/hooks/session-start.sh"

installed_version="$(tr -d '[:space:]' < "$SHAKERSCAN_HOME/VERSION")"
grep -F ": \"\${SCANNER_IMAGE_TAG:=$installed_version}\"" "$SHAKERSCAN_BIN_DIR/shakerscan" >/dev/null
grep -F 'export SCANNER_IMAGE_TAG' "$SHAKERSCAN_BIN_DIR/shakerscan" >/dev/null

bash -n "$SHAKERSCAN_HOME/scanner.sh"
bash -n "$SHAKERSCAN_HOME/scripts/build-model-intake-guest-rootfs.sh"
bash -n "$SHAKERSCAN_HOME/scripts/provision-model-intake-firecracker.sh"
python3 -m py_compile \
  "$SHAKERSCAN_HOME/scripts/shakerscan_mcp.py" \
  "$SHAKERSCAN_HOME/scripts/local_planner_adapter.py" \
  "$SHAKERSCAN_HOME/scripts/planner_evals.py" \
  "$SHAKERSCAN_HOME/scripts/fleet_cli.py" \
  "$SHAKERSCAN_HOME/scripts/fleet_acceptance.py" \
  "$SHAKERSCAN_HOME/scripts/scan_cli.py" \
  "$SHAKERSCAN_HOME/scripts/v2_cli.py" \
  "$SHAKERSCAN_HOME/scripts/rebuild_scan_report.py" \
  "$SHAKERSCAN_HOME/scripts/model_intake_runner_cli.py"

help_commands=(
  "scan --help"
  "hunt --help"
  "hunt start --help"
  "hunt call --help"
  "credentials create --help"
  "credentials rotate --help"
  "credentials test --help"
  "collections upload --help"
  "collections bind --help"
  "collections select --help"
  "evidence export --help"
  "report-rebuild --help"
)
for command in "${help_commands[@]}"; do
  # Help exits before dependency checks or service access and is therefore a
  # non-mutating installed-wrapper contract.
  read -r -a arguments <<<"$command"
  "$SHAKERSCAN_BIN_DIR/shakerscan" "${arguments[@]}" >/dev/null
done

env_output="$("$SHAKERSCAN_BIN_DIR/shakerscan" env)"
grep -F "Runtime directory: $SHAKERSCAN_HOME" <<<"$env_output" >/dev/null
grep -F "Launcher:          $SHAKERSCAN_BIN_DIR/shakerscan" <<<"$env_output" >/dev/null

echo "installer smoke passed: frozen source runtime is complete and executable"
