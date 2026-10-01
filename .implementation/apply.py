"""Integrate reviewed modules; the temporary script is not part of the deliverable."""
from pathlib import Path
import ast
import subprocess


def substitute(path,old,new):
    source=Path(path).read_text()
    if new in source: return
    if source.count(old)!=1: raise RuntimeError(f'Patch context changed: {path}: {old[:90]}')
    Path(path).write_text(source.replace(old,new,1))


def edit_function(path,name,transform):
    source=Path(path).read_text(); lines=source.splitlines(keepends=True)
    node=next(n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    old=''.join(lines[node.lineno-1:node.end_lineno]); new=transform(old)
    ast.parse(new);lines[node.lineno-1:node.end_lineno]=[new.rstrip()+'\n']
    Path(path).write_text(''.join(lines))

# Import the already-tested #295 source, not its temporary work files.
if not Path('ui/src/lib/networkScanCoverage.mjs').exists():
    commit='3b66ee4108d1b78b1f4e666e9887a959b3774011'
    subprocess.run(['git','fetch','--depth=1','origin',commit],check=True)
    subprocess.run(['git','checkout',commit,'--',
        'ui/src/lib/api.ts','ui/src/lib/deviceScanPresentation.mjs','ui/src/lib/networkScanCoverage.mjs',
        'ui/src/components/DevicePortCoverage.tsx','ui/src/app/devices/[id]/page.tsx',
        'ui/tests/device-port-coverage.test.mjs','ui/tests/network-scan-coverage.test.mjs'],check=True)

substitute('api/targets/asset_inputs_migration.py',
    "    if await conn.fetchval(\"SELECT 1 FROM app_schema_migrations WHERE name=$1\", INPUTS_MIGRATION):\n        return",
    "    from .asset_authority import migrate_asset_authority\n    if await conn.fetchval(\"SELECT 1 FROM app_schema_migrations WHERE name=$1\", INPUTS_MIGRATION):\n        await migrate_asset_authority(conn)\n        return")
substitute('api/targets/asset_inputs_migration.py',
    '    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", INPUTS_MIGRATION)',
    '    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", INPUTS_MIGRATION)\n    await migrate_asset_authority(conn)')

path=Path('api/target_authorization.py'); source=path.read_text()
if '_current_exact_target_authorization' not in source:
    source=source.replace('async def current_target_authorization(', 'async def _current_exact_target_authorization(',1)
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_current_exact_target_authorization')
    lines=source.splitlines(keepends=True)
    lines[node.lineno-1:node.lineno-1]=['''async def current_target_authorization(conn: Any, target_id: Any) -> dict[str, Any] | None:
    try:
        from targets.asset_authority import resolve_target_authorization
    except ModuleNotFoundError:
        from api.targets.asset_authority import resolve_target_authorization
    return await resolve_target_authorization(conn, target_id, _current_exact_target_authorization)


''']
    path.write_text(''.join(lines))

def host_scope(source):
    if 'host://' in source: return source
    return source.replace('    host = _host(url)', '    if url.startswith("host://"):\n        url = "http://" + url[len("host://"):].split("#",1)[0]\n    host = _host(url)',1)
edit_function('api/target_authorization.py','authorize_target',host_scope)

def revoke(source):
    if 'authorization_inheritance=false' in source: return source
    return source.replace('    result = await conn.execute(', '''    await conn.execute("""UPDATE targets SET authorization_inheritance=false,
        metadata_json=jsonb_set(COALESCE(metadata_json,'{}'::jsonb),'{authorization_inheritance_revoked}',
            jsonb_build_object('revoked_by',$2::text,'reason',$3::text,'at',NOW())),updated_at=NOW()
        WHERE id=$1""", target_uuid, revoked_by, reason[:2000])
    result = await conn.execute(''',1)
edit_function('api/target_authorization.py','revoke_target_authorization',revoke)

substitute('api/api.py',
    '    if requested_target_id and scope_target_id and requested_target_id != scope_target_id:\n        await _deny("approval_scope_target_mismatch", "Approval receipt scope target does not match requested target", approval_ref=approval_ref, scope_ref=scope_ref)',
    '''    if requested_target_id and scope_target_id and requested_target_id != scope_target_id:
        from targets.asset_authority import standing_authorization_matches_target
        inherited = standing and await standing_authorization_matches_target(conn,
            target_id=requested_target_id,scope_target_id=scope_target_id,approval_receipt_id=approval_ref)
        if not inherited:
            await _deny("approval_scope_target_mismatch", "Approval receipt scope target does not match requested target", approval_ref=approval_ref, scope_ref=scope_ref)''')

# The worker re-checks the current database relationship, never a submitted inheritance flag.
path=Path('api/scan/authorization.py'); source=path.read_text()
if 'asset_authority_validated' not in source:
    nodes={n.name:n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    node=nodes['revalidate_action_authority']; lines=source.splitlines(keepends=True)
    old=''.join(lines[node.lineno-1:node.end_lineno])
    signature_end=old.index(') ->')
    old=old[:signature_end]+'    asset_authority_validated: bool = False,\n'+old[signature_end:]
    old=old.replace('scope_target_id != target_binding.target_id', 'scope_target_id != target_binding.target_id and not asset_authority_validated')
    lines[node.lineno-1:node.end_lineno]=[old]
    source=''.join(lines); path.write_text(source)
    def recheck(old):
        insertion='''    from targets.asset_authority import standing_authorization_matches_target
    asset_authority_validated = False
    if approval and scope and str(approval.get("action_name") or "") == STANDING_ACTION_NAME:
        asset_authority_validated = await standing_authorization_matches_target(conn,
            target_id=target_binding.target_id,scope_target_id=scope.get("target_id"),
            approval_receipt_id=approval.get("id"))
'''
        return old.replace('    return revalidate_action_authority(', insertion+'    return revalidate_action_authority(\n        asset_authority_validated=asset_authority_validated,',1)
    edit_function(path,'revalidate_scan_action_authority',recheck)

substitute('api/targets/asset_store.py',
    "    return {\n        'target': public_asset(row), 'requested_target_id': str(target_id),",
    "    try:\n        from target_authorization import current_target_authorization\n    except ModuleNotFoundError:\n        from ..target_authorization import current_target_authorization\n    return {\n        'authorization': await current_target_authorization(conn,owner),\n        'target': public_asset(row), 'requested_target_id': str(target_id),")

substitute('ui/src/app/targets/page.tsx',
    "import { featureEnabled } from '@/lib/workspaceCapabilities'",
    "import { featureEnabled } from '@/lib/workspaceCapabilities'\nimport { TargetInventory } from '@/components/targets/TargetInventory'")
substitute('ui/src/app/targets/page.tsx','      <TargetsContent />','      <TargetInventory domainView={<TargetsContent />} />')
substitute('ui/src/app/devices/[id]/page.tsx',
    'const [scanOpen, setScanOpen] = useState(false)',
    "const [scanOpen, setScanOpen] = useState(searchParams.get('action') === 'scan')")
substitute('ui/src/app/devices/[id]/page.tsx',' }}>Scan device</Button>', ' }}>Start network scan</Button>')
substitute('ui/src/app/devices/[id]/page.tsx',
    '        <RetireDeviceButton deviceId={deviceId}',
    '        <Link href={`/targets/${deviceId}/asset`}><Button variant="secondary">Asset overview</Button></Link>\n        <RetireDeviceButton deviceId={deviceId}')

# Installed-startup checks use an isolated database with the actual public schema,
# not a search_path fixture that the baseline deliberately rejects.
path=Path('tests/test_target_asset_startup_postgres.py'); source=path.read_text()
if 'startup_database' not in source:
    source=source.replace('from tests.test_target_asset_migration_postgres import database', '''from contextlib import asynccontextmanager
import os
import uuid
import pytest

@asynccontextmanager
async def startup_database():
    asyncpg=pytest.importorskip('asyncpg')
    dsn=os.environ.get('TARGET_ASSET_TEST_DATABASE_URL')
    if not dsn: pytest.skip('TARGET_ASSET_TEST_DATABASE_URL is not configured')
    admin=await asyncpg.connect(dsn)
    name='asset_startup_'+uuid.uuid4().hex
    conn=None
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
        conn=await asyncpg.connect(dsn,database=name)
        await conn.execute((Path(__file__).resolve().parents[1]/'db/init.sql').read_text())
        yield conn
    finally:
        if conn: await conn.close()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await admin.close()''')
    source=source.replace('async with database() as conn:', 'async with startup_database() as conn:')
    path.write_text(source)

# Focused source inventory for the next integration batch.
out=[]
def emit(path,names):
    text=Path(path).read_text();lines=text.splitlines()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
            out.append(f'\n=== {path}:{node.lineno} {node.name} ===\n'+'\n'.join(lines[node.lineno-1:node.end_lineno]))
emit('api/request_collection_api.py',{'_target_binding','list_request_collections','get_request_collection','create_request_collection','_collection_metadata','create_request_collection_selection'})
emit('api/runtime/request_collection_store.py',{'get_collection','list_collections','bind_target','load_for_worker','resolve_selection','create_selection'})
emit('api/targets/router.py',{'_authorized_for_active_testing_sql','_public_target_row'})
emit('api/target_dedupe.py',{'canonical_target_key','canonical_target_identity','canonical_target_url'})
for path in ['ui/src/app/request-collections/page.tsx','ui/src/components/credentials/ShareCredentialDialog.tsx']:
    if Path(path).exists():
        lines=Path(path).read_text().splitlines()
        out.append(f'\n=== {path} {len(lines)} lines ===\n')
        for i,line in enumerate(lines):
            if any(term in line for term in ['getTargets(', 'getDevices(', 'const choices', 'const target', "target_kind", 'targetKind']):
                out.extend(f'{j+1}: {lines[j]}' for j in range(max(0,i-3),min(len(lines),i+7)))
Path('.implementation/collections-ui-contracts.txt').write_text('\n'.join(out)+'\n')
for path in ['api/scan/authorization.py','api/target_authorization.py','api/api.py','api/targets/asset_store.py']:
    ast.parse(Path(path).read_text())
