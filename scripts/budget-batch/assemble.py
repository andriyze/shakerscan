"""Reconstruct one explicit, reviewed budget batch; never move a remote ref."""
from pathlib import Path
import hashlib
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
EXPECTED = '2155f71fffd0dbfacc2eec6d155b54c6a0f5cb31'
PARENT = '76653d344228eed9ce1cdfe59786a230ce119eb0'
NEW = {
    'api/hunt/budget_amendments.py': 'b66a4edb035fa654dbaaa77eacc3d2113f6140c6',
    'tests/test_hunt_budget_amendments.py': '042be72bb80c35c5c4ba658e9254c28dd98bf255',
    'tests/test_hunt_budget_amendments_postgres.py': '5025914de369068d42a2c92de9d88acabeef7187',
    'ui/src/components/hunt/HuntBudgetEditor.tsx': 'bfe0dd2f7ea817bd2ffa38cfe9324d4ec5fa4f95',
    'ui/tests/browser/hunt-budget-amendments.spec.ts': '0f5792fb94b7a6b6202c8f2cf5e3f0603ac49500',
}

def blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

patch = HERE / 'existing.patch'
assert blob_sha(patch.read_bytes()) == '24a9f90fafae32e551eba647796e1f5d69ed4d26'
subprocess.run(['git', 'apply', '--index', str(patch)], check=True)
for name, sha in NEW.items():
    source = HERE / 'files' / (name + '.txt')
    assert blob_sha(source.read_bytes()) == sha, name
    target = Path(name)
    assert not target.exists(), name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
for generator in ('generate_capability_inventory', 'generate_hunt_contract', 'generate_install_manifest'):
    subprocess.run(['python', f'scripts/{generator}.py'], check=True)
subprocess.run(['git', 'add', '-A'], check=True)
actual = subprocess.check_output(['git', 'write-tree']).decode().strip()
assert actual == EXPECTED, (actual, EXPECTED)
followup = HERE / 'resume.patch'
assert blob_sha(followup.read_bytes()) == 'fc968a49b728568f8e3d98171852f78051130e39'
subprocess.run(['git', 'apply', '--index', str(followup)], check=True)
for generator in ('generate_capability_inventory', 'generate_hunt_contract', 'generate_install_manifest'):
    subprocess.run(['python', f'scripts/{generator}.py'], check=True)
subprocess.run(['git', 'add', '-A'], check=True)
actual = subprocess.check_output(['git', 'write-tree']).decode().strip()
expected_final = '5dc4a8d266a0c28b3a8bfb7571c44ef221b1d4a4'
assert actual == expected_final, (actual, expected_final)
print('Reconstructed exact product tree:', actual)
