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
export SHELL=/bin/bash

mkdir -p "$HOME"
sh "$ROOT_DIR/install/index.sh" >/dev/null
export PATH="$SHAKERSCAN_BIN_DIR:$PATH"

required_files=(
  scanner.sh
  docker-compose.release.yml
  docker-compose.worker.yml
  docker-compose.broker-worker.yml
  db/init.sql
  VERSION
  README.md
  AGENTS.md
  CLAUDE.md
  .dockerignore
  scripts/shakerscan_mcp.py
  scripts/local_planner_adapter.py
  scripts/planner_evals.py
  scripts/fleet_cli.py
  scripts/fleet_acceptance.py
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
  runner/guest/Dockerfile
  runner/guest/guest-init
  runner/guest/guest_worker.py
  runner/guest/requirements.in
  runner/guest/requirements.lock
  runner/host/requirements.in
  runner/host/requirements.lock
  runner/host/system-requirements.ubuntu.txt
)

for relative_path in "${required_files[@]}"; do
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing runtime file $relative_path" >&2
    exit 1
  fi
done

for source_path in "$ROOT_DIR"/skills/*/SKILL.md; do
  relative_path="${source_path#"$ROOT_DIR"/}"
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing skill $relative_path" >&2
    exit 1
  fi
done

for source_path in "$ROOT_DIR"/.claude/commands/*.md; do
  relative_path="${source_path#"$ROOT_DIR"/}"
  if [[ ! -f "$SHAKERSCAN_HOME/$relative_path" ]]; then
    echo "installer smoke: missing command $relative_path" >&2
    exit 1
  fi
done

test -x "$SHAKERSCAN_BIN_DIR/shakerscan"
test -x "$SHAKERSCAN_HOME/scanner.sh"
test -x "$SHAKERSCAN_HOME/scripts/build-model-intake-guest-rootfs.sh"
test -x "$SHAKERSCAN_HOME/scripts/provision-model-intake-firecracker.sh"
test -x "$SHAKERSCAN_HOME/.claude/hooks/session-start.sh"

bash -n "$SHAKERSCAN_HOME/scanner.sh"
bash -n "$SHAKERSCAN_HOME/scripts/build-model-intake-guest-rootfs.sh"
bash -n "$SHAKERSCAN_HOME/scripts/provision-model-intake-firecracker.sh"
python3 -m py_compile \
  "$SHAKERSCAN_HOME/scripts/shakerscan_mcp.py" \
  "$SHAKERSCAN_HOME/scripts/local_planner_adapter.py" \
  "$SHAKERSCAN_HOME/scripts/planner_evals.py" \
  "$SHAKERSCAN_HOME/scripts/fleet_cli.py" \
  "$SHAKERSCAN_HOME/scripts/fleet_acceptance.py" \
  "$SHAKERSCAN_HOME/scripts/model_intake_runner_cli.py"

env_output="$("$SHAKERSCAN_BIN_DIR/shakerscan" env)"
grep -F "Runtime directory: $SHAKERSCAN_HOME" <<<"$env_output" >/dev/null
grep -F "Launcher:          $SHAKERSCAN_BIN_DIR/shakerscan" <<<"$env_output" >/dev/null

echo "installer smoke passed: frozen source runtime is complete and executable"
