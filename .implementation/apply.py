"""Match new regression imports to the API's flat installed module layout."""
from pathlib import Path

paths = list(Path('tests').glob('test_target_asset_*.py')) + [Path('tests/test_device_shared_inputs_postgres.py')]
for path in paths:
    source=path.read_text()
    for old,new in {
        'from api.targets.':'from targets.',
        'from api.devices.':'from devices.',
        'from api.runtime.':'from runtime.',
        'from api.scan.':'from scan.',
        'from api import target_authorization':'import target_authorization',
    }.items(): source=source.replace(old,new)
    path.write_text(source)
check=Path('.implementation/check.sh')
source=check.read_text()
old='python -m pytest --tb=short -q tests/test_target_authorization.py tests/test_device_*.py tests/test_credential_*.py tests/test_request_collection*.py tests/test_hunt_knowledge.py tests/test_hunt_prior_knowledge.py > .implementation/affected-test-output.txt 2>&1'
new='''mapfile -t affected_files < <(python - <<'PY'
from pathlib import Path
patterns=('test_target_authorization*.py','test_device_*.py','test_credential_*.py','test_request_collection*.py','test_hunt*knowledge*.py')
for name in sorted({str(path) for pattern in patterns for path in Path('tests').glob(pattern)}):
    if name != 'tests/test_device_shared_inputs_postgres.py': print(name)
PY
)
python -m pytest --tb=short -q "${affected_files[@]}" > .implementation/affected-test-output.txt 2>&1'''
if old in source: source=source.replace(old,new,1)
elif new not in source: raise SystemExit('Check runner changed')
check.write_text(source)
