"""Allow only the deliberate two-operation API-contract delta, never bless unrelated drift."""
from pathlib import Path
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET

OUT = Path('/tmp/budget-results')
FILES = (
    'docs/generated/public-openapi-manifest.json',
    'ui/src/lib/publicApi.generated.ts',
    'tests/fixtures/api_contract/routes.json',
    'tests/fixtures/api_contract/operations.json',
    'tests/fixtures/api_contract/app_contract.json',
)

def before(path):
    return json.loads(subprocess.check_output(['git', 'show', ':' + path]))

changed = set(subprocess.check_output(['git', 'diff', '--name-only']).decode().splitlines())
assert changed == set(FILES), changed
old, new = before(FILES[0]), json.loads(Path(FILES[0]).read_text())
expected = {'GET /hunts/{hunt_id}/budget-amendments', 'POST /hunts/{hunt_id}/budget-amendments'}
assert set(new['operations']) - set(old['operations']) == expected
assert not set(old['operations']) - set(new['operations'])
assert all(new['operations'][key] == value for key, value in old['operations'].items())
assert new['operation_count'] == old['operation_count'] + 2
assert set(new['component_schema_sha256']) - set(old['component_schema_sha256']) == {'HuntBudgetAmendmentRequest'}
assert all(new['component_schema_sha256'][key] == value for key, value in old['component_schema_sha256'].items())
for path in FILES[2:4]:
    previous, current = before(path), json.loads(Path(path).read_text())
    stable = [item for item in current if item['path'] != '/hunts/{hunt_id}/budget-amendments']
    assert stable == previous, path
    assert len(current) == len(previous) + 2, path
previous, current = before(FILES[4]), json.loads(Path(FILES[4]).read_text())
assert current == {**previous, 'route_count': previous['route_count'] + 2}
cases = list(ET.parse(OUT / 'characterization.xml').getroot().iter('testcase'))
assert cases and not any(c.find(tag) is not None for c in cases for tag in ('failure', 'error', 'skipped'))
for path in FILES:
    target = OUT / 'generated' / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
print('API contract delta verified: only two new routes and one request schema; middleware and prior operations unchanged.')
