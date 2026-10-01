#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$PWD:$PWD/api:$PWD/scanner"
python -m pip install -q --disable-pip-version-check --require-hashes -r scanner/requirements.lock
npm --prefix ui ci --silent
python scripts/generate_public_api_contract.py
set +e
python -m pytest --tb=short -q tests/test_target_asset_*.py tests/test_device_shared_inputs_postgres.py > .implementation/test-output.txt 2>&1
result=$?
# Existing contracts and runtime behavior around the changed ownership boundaries.
mapfile -t affected_files < <(python - <<'PY'
from pathlib import Path
patterns=('test_target_authorization*.py','test_device_*.py','test_credential_*.py','test_request_collection*.py','test_hunt*knowledge*.py')
for name in sorted({str(path) for pattern in patterns for path in Path('tests').glob(pattern)}):
    if name != 'tests/test_device_shared_inputs_postgres.py': print(name)
PY
)
python -m pytest --tb=short -q "${affected_files[@]}" > .implementation/affected-test-output.txt 2>&1
affected=$?
python scripts/check_module_size.py >> .implementation/test-output.txt 2>&1
ratchet=$?
npm --prefix ui test > .implementation/ui-test-output.txt 2>&1
ui=$?
(cd ui && npx tsc --noEmit) >> .implementation/test-output.txt 2>&1
types=$?
npm --prefix ui run build > .implementation/ui-build-output.txt 2>&1
build=$?
browser=99
if test "$build" -eq 0; then
  (cd ui && npx playwright install --with-deps chromium) > .implementation/browser-install-output.txt 2>&1
  if test "$?" -eq 0; then
    (cd ui && npm run start -- --hostname 127.0.0.1 --port 3000) > .implementation/browser-server-output.txt 2>&1 &
    server=$!
    for attempt in $(seq 1 60); do curl -fsS http://127.0.0.1:3000 >/dev/null && break; sleep 1; done
    (cd ui && CI=1 PLAYWRIGHT_BASE_URL=http://127.0.0.1:3000 npx playwright test tests/browser/target-assets.spec.ts) > .implementation/browser-test-output.txt 2>&1
    browser=$?
    kill "$server" || true
  fi
fi
printf '\npytest_exit=%s affected_exit=%s module_size_exit=%s ui_tests_exit=%s types_exit=%s build_exit=%s browser_exit=%s\n' "$result" "$affected" "$ratchet" "$ui" "$types" "$build" "$browser" >> .implementation/test-output.txt
cat .implementation/test-output.txt
tail -40 .implementation/affected-test-output.txt
tail -12 .implementation/ui-test-output.txt
tail -25 .implementation/browser-test-output.txt
# Only diagnostic reports and generated public metadata are staged here.
git add .implementation/*output.txt docs/generated/public-openapi-manifest.json ui/src/lib/publicApi.generated.ts
if ! git diff --cached --quiet; then
  git -c user.name=ChatGPT -c user.email=noreply@openai.com commit -m 'chore(dev): record isolated ownership and browser integration results'
  git push origin "HEAD:refs/heads/$GITHUB_REF_NAME"
fi
for code in "$result" "$affected" "$ratchet" "$ui" "$types" "$build" "$browser"; do
  if test "$code" -ne 0; then exit "$code"; fi
done
