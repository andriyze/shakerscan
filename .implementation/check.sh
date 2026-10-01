#!/usr/bin/env bash
set -euo pipefail
python -m pip install --disable-pip-version-check --require-hashes -r scanner/requirements.lock
python -m pytest -q tests/test_target_asset_migration_postgres.py
python scripts/check_module_size.py
