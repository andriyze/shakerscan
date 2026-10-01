"""Temporary source amendments and read-only runtime contract extraction."""
from pathlib import Path
import ast


def substitute(path, old, new):
    source = Path(path).read_text()
    if new in source:
        return
    if source.count(old) != 1:
        raise RuntimeError(f'Patch context changed: {path}: {old[:80]}')
    Path(path).write_text(source.replace(old,new,1))

substitute('api/targets/asset_inputs_migration.py',
    'await sync_legacy_device_credential(conn, legacy_profile_id=row["id"])',
    'await sync_legacy_device_credential(conn, row["id"])')
substitute('tests/test_target_asset_inputs_postgres.py',
    'from test_target_asset_migration_postgres import database',
    'from tests.test_target_asset_migration_postgres import database')
substitute('api/targets/asset_inputs_schema.py',
    'b.allowed_capabilities,p.created_at,p.updated_at',
    'b.allowed_capabilities,p.rotated_at,p.created_at,p.updated_at')

out=[]
def emit(path,names):
    source=Path(path).read_text(); lines=source.splitlines()
    for node in ast.parse(source).body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
            out.append(f'\n=== {path}:{node.lineno} {node.name} ===\n'+'\n'.join(lines[node.lineno-1:node.end_lineno]))

emit('api/worker.py',['_hydrate_device_scan_credentials','_hydrate_device_request_collections'])
emit('api/devices/router.py',['_public_device_credential_profile','_public_device_request_collection','_validate_device_credential_refs','get_device_request_collection','create_device_request_collection','update_device_request_collection','deactivate_device_request_collection'])
emit('api/credential_api.py',['_sync_legacy_device_from_generic'])
emit('scanner/scanner_tools/device_web.py',['_credential_headers','_credential_request','_attempt_login'])
for path in ['scanner/scanner_tools/device_web.py','api/target_authorization.py','api/api.py']:
    source=Path(path).read_text(); lines=source.splitlines()
    for node in ast.parse(source).body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and (path!='api/api.py' or 'target' in node.name):
            out.append(f'FUNCTION {path} {node.name} {node.lineno}-{node.end_lineno}')
Path('.implementation/runtime-contracts.txt').write_text('\n'.join(out)+'\n')
