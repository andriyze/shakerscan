#!/usr/bin/env bash
# Run the exposure E2E smoke suite inside the worker container (which ships
# Playwright + Chromium and sits on the compose network with ui/api).
#
# Usage, from the repo root:  ui/e2e/run.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! docker compose ps --status running worker >/dev/null 2>&1; then
  echo "worker container is not running — start the stack with ./scanner.sh start" >&2
  exit 2
fi

docker compose exec -T worker python3 - < ui/e2e/exposure_smoke.py
