"""Explicit function-level patches, validated against parsed source boundaries."""
from pathlib import Path
import ast


def substitute(path,old,new):
    source=Path(path).read_text()
    if new in source: return
    if source.count(old)!=1: raise RuntimeError(f'Patch context changed: {path}: {old[:90]}')
    Path(path).write_text(source.replace(old,new,1))


def edit_function(path,name,transform):
    source=Path(path).read_text(); lines=source.splitlines(keepends=True)
    nodes=[n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
    if len(nodes)!=1: raise RuntimeError(f'Missing function {path}:{name}')
    node=nodes[0]; old=''.join(lines[node.lineno-1:node.end_lineno]); new=transform(old)
    ast.parse(new)
    lines[node.lineno-1:node.end_lineno]=[new.rstrip()+'\n']
    Path(path).write_text(''.join(lines))


def between(source,start,end,replacement):
    a=source.index(start); b=source.index(end,a)
    return source[:a]+replacement+source[b:]

substitute('api/targets/asset_inputs_migration.py',
    '    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", INPUTS_MIGRATION)',
    '    await conn.reload_schema_state()\n    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", INPUTS_MIGRATION)')
substitute('tests/test_target_asset_inputs_postgres.py',
    "credential_profile_bindings(id,profile_id,binding_kind,binding_id,is_active,revoked_at)\n                VALUES($1,$2,'target',$3,false,NOW())",
    "credential_profile_bindings(id,profile_id,binding_kind,binding_id,is_active,revoked_at,created_at)\n                VALUES($1,$2,'target',$3,false,NOW(),NOW())")

router='api/devices/router.py'
source=Path(router).read_text()
if 'from .shared_credentials import' not in source:
    source=source.replace('router = APIRouter()', '''from .shared_credentials import (
    create_device_profile, rotate_device_profile, deactivate_device_profile, device_execution_capability,
)
from .shared_collections import save_device_collection, deactivate_device_collection, collection_view

router = APIRouter()''',1)
    Path(router).write_text(source)


def create_credential(source):
    if 'await create_device_profile(' in source: return source
    return between(source,'        try:\n            row = await conn.fetchrow(', '        operation = await _record_command_result(', '''        try:
            row = await create_device_profile(conn, device_uuid, request)
        except CredentialStoreError as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
''')
edit_function(router,'create_device_credential',create_credential)


def rotate_credential(source):
    if 'await rotate_device_profile(' in source: return source
    return between(source,'        row = await conn.fetchrow(', '        await conn.execute("DELETE FROM device_credential_attempts', '''        try:
            row = await rotate_device_profile(conn, device_uuid, profile_uuid, request)
        except CredentialStoreError as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
''')
edit_function(router,'rotate_device_credential',rotate_credential)


def deactivate_credential(source):
    if 'await deactivate_device_profile(' in source: return source
    return between(source,'        row = await conn.fetchrow(', '        operation = await _record_command_result(', '''        try:
            row = await deactivate_device_profile(conn, device_uuid, profile_uuid)
        except CredentialStoreError as exc:
            raise _legacy_credential_migration_http_error(exc) from exc
''')
edit_function(router,'deactivate_device_credential',deactivate_credential)


def credential_refs(source):
    if 'device_execution_capability(role,' in source: return source
    source=source.replace('SELECT id, auth_kind, port FROM device_credential_profiles',
        'SELECT id, auth_kind, port, current_version, record_version, allowed_capabilities FROM device_credential_profiles')
    source=source.replace('        refs.append({', '''        allowed = row['allowed_capabilities']
        if isinstance(allowed, str):
            allowed = json.loads(allowed)
        capability = device_execution_capability(role, allowed)
        if not capability:
            raise HTTPException(status_code=422, detail=f'This {role} profile has no applicable capability grant')
        refs.append({
            'current_version': int(row['current_version']),
            'record_version': int(row['record_version']),
            'capability': capability,''',1)
    return source
edit_function(router,'_validate_device_credential_refs',credential_refs)


def create_collection(source):
    if 'await save_device_collection(' in source: return source
    return between(source,'            row = await conn.fetchrow(', '    except asyncpg.UniqueViolationError', '''            row = await save_device_collection(conn, device_uuid, summary=summary, encrypted_payload=encrypted_payload)
''')
edit_function(router,'create_device_request_collection',create_collection)


def update_collection(source):
    if 'await save_device_collection(' in source: return source
    return between(source,'            row = await conn.fetchrow(', '    except asyncpg.UniqueViolationError', '''            row = await save_device_collection(conn, device_uuid, collection_id=collection_uuid,
                summary=summary, encrypted_payload=encrypted_payload, expected_digest=str(current['document_sha256']))
''')
edit_function(router,'update_device_request_collection',update_collection)


def deactivate_collection(source):
    if 'await deactivate_device_collection(' in source: return source
    return between(source,'        row = await conn.fetchrow(', '    if not row:', '''        row = await deactivate_device_collection(conn, device_uuid, collection_uuid)
''')
edit_function(router,'deactivate_device_request_collection',deactivate_collection)


def get_collection(source):
    if 'await collection_view(' in source: return source
    source=between(source,'        row = await conn.fetchrow(', '    if not row:', '''        row = await collection_view(conn, device_uuid, collection_uuid)
''')
    return source.replace('payload["summary"]["requests_total"] = len(requests)',
                          'payload["summary"]["requests_total"] = int(summary.get("requests_total") or summary.get("request_count") or len(requests))')
edit_function(router,'get_device_request_collection',get_collection)


def generic_sync(source):
    if 'unified_target_asset_inputs_v1' in source: return source
    return source.replace('    legacy = await _legacy_device_profile(conn, profile)', '''    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name='unified_target_asset_inputs_v1'"):
        return  # device_credential_profiles is now a view of this exact canonical version.
    legacy = await _legacy_device_profile(conn, profile)''',1)
edit_function('api/credential_api.py','_sync_legacy_device_from_generic',generic_sync)

# Extract worker hydration without changing cooldown, daily caps, size limits, or digest checks.
worker=Path('api/worker.py')
if not Path('api/devices/worker_inputs.py').exists():
    source=worker.read_text(); lines=source.splitlines(); selected={}
    for node in ast.parse(source).body:
        if isinstance(node,ast.AsyncFunctionDef) and node.name in {'_hydrate_device_scan_credentials','_hydrate_device_request_collections'}:
            selected[node.name]='\n'.join(lines[node.lineno-1:node.end_lineno])+'\n'
    first=selected['_hydrate_device_scan_credentials']
    first=first.replace('_hydrate_device_scan_credentials(options: dict[str, Any], scan_id: str)',
                        'hydrate_device_scan_credentials(options: dict[str, Any], scan_id: str, *, pool: Any, ssh_daily_cap: int, ssh_cooldown_seconds: int, utc_now: Any)')
    first=first.replace('db_pool','pool').replace('DEVICE_SSH_AUTH_DAILY_FAILURE_CAP','ssh_daily_cap').replace('DEVICE_SSH_AUTH_COOLDOWN_SECONDS','ssh_cooldown_seconds')
    first=first.replace('    async with pool.acquire() as conn:\n        rows =', '''    async with pool.acquire() as conn:
        device_id = await conn.fetchval('SELECT device_target_id FROM scans WHERE id=$1', scan_uuid)
        if device_id is None:
            raise ValueError('Device scan target is unavailable')
        rows =''',1)
    first=between(first,'        raw_secret = str(decrypt_secret(', '    hydrated["_resolved_device_credentials"]', '''        async with pool.acquire() as conn:
            resolved.append(await resolve_device_credential(conn, device_id, ref))
''')
    second=selected['_hydrate_device_request_collections'].replace('_hydrate_device_request_collections(options: dict[str, Any], scan_id: str)',
        'hydrate_device_request_collections(options: dict[str, Any], scan_id: str, *, pool: Any)').replace('db_pool','pool')
    header='''"""Worker-only hydration from canonical asset inputs; never a public secret API."""
from __future__ import annotations
from datetime import datetime
import hashlib
import json
from typing import Any
import uuid
try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:
    from ..secret_store import decrypt_secret
from .shared_credentials import resolve_device_credential

'''
    Path('api/devices/worker_inputs.py').write_text(header+first+'\n'+second)
    edit_function('api/worker.py','_hydrate_device_scan_credentials',lambda old: '''async def _hydrate_device_scan_credentials(options: dict[str, Any], scan_id: str) -> dict[str, Any]:
    from devices.worker_inputs import hydrate_device_scan_credentials
    return await hydrate_device_scan_credentials(options, scan_id, pool=db_pool,
        ssh_daily_cap=DEVICE_SSH_AUTH_DAILY_FAILURE_CAP,
        ssh_cooldown_seconds=DEVICE_SSH_AUTH_COOLDOWN_SECONDS, utc_now=utc_now)
''')
    edit_function('api/worker.py','_hydrate_device_request_collections',lambda old: '''async def _hydrate_device_request_collections(options: dict[str, Any], scan_id: str) -> dict[str, Any]:
    from devices.worker_inputs import hydrate_device_request_collections
    return await hydrate_device_request_collections(options, scan_id, pool=db_pool)
''')

substitute('scanner/scanner_tools/device_web.py',
    '        if kind == "web_authorization_header":',
    '''        if kind == "web_headers":
            request_headers.update(_safe_request_headers(dict(credential.get("headers") or {})))
            credentials_attempted = bool(request_headers)
        elif kind == "web_authorization_header":''')

out=[]
for path,names in [('api/targets/router.py',{'list_targets_grouped','create_target','get_target','update_target','scan_target'}),
                   ('api/scan/authorization.py',set()),('api/retest_contract.py',{'run_schema_migrations'})]:
    source=Path(path).read_text(); lines=source.splitlines()
    if not names:
        out.append(f'\n=== {path} ===\n'+source); continue
    for node in ast.parse(source).body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
            out.append(f'\n=== {path}:{node.lineno} {node.name} ===\n'+'\n'.join(lines[node.lineno-1:node.end_lineno]))
Path('.implementation/target-contracts.txt').write_text('\n'.join(out)+'\n')
for path in ['api/devices/shared_credentials.py','api/devices/shared_collections.py','api/devices/worker_inputs.py',router,'api/worker.py']:
    ast.parse(Path(path).read_text())
