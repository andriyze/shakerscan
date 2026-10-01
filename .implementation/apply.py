"""Read-only source contract extraction; temporary workspace material only."""
from pathlib import Path
import ast
out = []
def emit(path, names):
    source = Path(path).read_text(); lines = source.splitlines()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in names:
            out.append(f'\n=== {path}:{node.lineno} {node.name} ===\n' + '\n'.join(lines[node.lineno-1:node.end_lineno]))

emit('api/runtime/credential_store.py', ['get_profile', 'list_profiles', 'resolve_version', 'get_worker_secret', 'grant_target', '_validate_kind_placement'])
emit('api/runtime/request_collection_store.py', ['PostgresRequestCollectionStore'])
emit('api/runtime/models.py', ['target_kinds_share_asset'])
emit('api/devices/router.py', ['create_device', 'create_device_target', 'update_device', 'change_device_locator', 'create_device_credential', 'create_device_credential_profile', 'list_device_credentials', 'list_device_credential_profiles', 'create_device_request_collection', 'list_device_request_collections', 'get_device_request_collection', '_resolve_device_credentials', '_resolve_device_request_collections'])
out.append('\n=== DEVICE FUNCTION LOCATIONS ===')
source = Path('api/devices/router.py').read_text()
for n in ast.parse(source).body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
        out.append(f'{n.name} {n.lineno}-{n.end_lineno}')
out.append('\n=== DEVICE LEGACY STORE REFERENCES ===')
for root in ['api','scanner']:
    for path in sorted(Path(root).rglob('*.py')):
        if str(path) in ['api/retest_contract.py', 'api/devices/router.py']: continue
        text=path.read_text()
        for i,line in enumerate(text.splitlines(),1):
            if 'device_credential_profiles' in line or 'device_request_collections' in line:
                out.append(f'{path}:{i}: {line.strip()}')
for path,ranges in {'api/retest_contract.py':[(1110,1145),(4930,5024)],'api/api.py':[(5410,5500)]}.items():
    lines=Path(path).read_text().splitlines()
    for a,b in ranges: out.append(f'\n=== {path}:{a}-{b} ===\n'+'\n'.join(lines[a-1:b]))
Path('.implementation/contracts.txt').write_text('\n'.join(out)+'\n')
print('Extracted contract lines:', len('\n'.join(out).splitlines()))
