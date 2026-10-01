#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q --disable-pip-version-check --require-hashes -r scanner/requirements.lock
python -m pytest --tb=short -q tests/test_target_asset_migration_postgres.py tests/test_target_asset_inputs_postgres.py tests/test_device_shared_inputs_postgres.py
python scripts/check_module_size.py
