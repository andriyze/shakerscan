#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q --disable-pip-version-check --require-hashes -r scanner/requirements.lock
set +e
python -m pytest --tb=short -q tests/test_target_asset_migration_postgres.py tests/test_target_asset_inputs_postgres.py tests/test_device_shared_inputs_postgres.py tests/test_target_asset_startup_postgres.py tests/test_target_asset_store_postgres.py > .implementation/test-output.txt 2>&1
result=$?
python scripts/check_module_size.py >> .implementation/test-output.txt 2>&1
ratchet=$?
printf '\npytest_exit=%s module_size_exit=%s\n' "$result" "$ratchet" >> .implementation/test-output.txt
cat .implementation/test-output.txt
git add .implementation/test-output.txt
if ! git diff --cached --quiet; then
  git -c user.name=ChatGPT -c user.email=noreply@openai.com commit -m 'chore(dev): record isolated regression results'
  git push origin "HEAD:refs/heads/$GITHUB_REF_NAME"
fi
if test "$result" -ne 0; then exit "$result"; fi
exit "$ratchet"
