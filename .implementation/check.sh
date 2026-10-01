#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q --disable-pip-version-check --require-hashes -r scanner/requirements.lock
npm --prefix ui ci --silent
set +e
python -m pytest --tb=short -q tests/test_target_asset_migration_postgres.py tests/test_target_asset_inputs_postgres.py tests/test_device_shared_inputs_postgres.py tests/test_target_asset_startup_postgres.py tests/test_target_asset_store_postgres.py tests/test_target_asset_authority_postgres.py > .implementation/test-output.txt 2>&1
result=$?
python scripts/check_module_size.py >> .implementation/test-output.txt 2>&1
ratchet=$?
npm --prefix ui test > .implementation/ui-test-output.txt 2>&1
ui=$?
(cd ui && npx tsc --noEmit) >> .implementation/test-output.txt 2>&1
types=$?
npm --prefix ui run build > .implementation/ui-build-output.txt 2>&1
build=$?
printf '\npytest_exit=%s module_size_exit=%s ui_tests_exit=%s types_exit=%s build_exit=%s\n' "$result" "$ratchet" "$ui" "$types" "$build" >> .implementation/test-output.txt
cat .implementation/test-output.txt
tail -15 .implementation/ui-test-output.txt
tail -30 .implementation/ui-build-output.txt
git add .implementation/*output.txt
if ! git diff --cached --quiet; then
  git -c user.name=ChatGPT -c user.email=noreply@openai.com commit -m 'chore(dev): record isolated integration results'
  git push origin "HEAD:refs/heads/$GITHUB_REF_NAME"
fi
if test "$result" -ne 0; then exit "$result"; fi
if test "$ratchet" -ne 0; then exit "$ratchet"; fi
if test "$ui" -ne 0; then exit "$ui"; fi
if test "$types" -ne 0; then exit "$types"; fi
exit "$build"
