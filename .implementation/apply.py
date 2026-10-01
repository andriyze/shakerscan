"""Anchored source integration plus read-only inspection for the remaining callers."""
from pathlib import Path
import ast


def substitute(path,old,new):
    source=Path(path).read_text()
    if new in source: return
    if source.count(old)!=1: raise RuntimeError(f'Patch context changed: {path}: {old[:90]}')
    Path(path).write_text(source.replace(old,new,1))

substitute('tests/test_target_asset_inputs_postgres.py',
    'binding_id,is_active,revoked_at,created_at)\n                VALUES($1,$2,\'target\',$3,false,NOW(),NOW())',
    'binding_id,is_active,revoked_at,created_at,updated_at)\n                VALUES($1,$2,\'target\',$3,false,NOW(),NOW(),NOW())')
substitute('api/devices/shared_credentials.py',
    'immediate_http_headers(material)', 'immediate_http_headers({**material, "auth_kind": kind})')
substitute('api/targets/asset_migration.py',
    '                    await migrate_target_assets(conn)\n        finally:',
    '                    await migrate_target_assets(conn)\n                from .asset_inputs_migration import migrate_asset_inputs\n                await migrate_asset_inputs(conn)\n        finally:')

path=Path('api/retest_contract.py'); source=path.read_text()
if '_run_schema_migrations_26_baseline' not in source:
    source=source.replace('async def run_schema_migrations(', 'async def _run_schema_migrations_26_baseline(',1)
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_run_schema_migrations_26_baseline')
    lines=source.splitlines(keepends=True)
    lines[node.lineno-1:node.lineno-1]=['''async def run_schema_migrations(db_pool):
    """Upgrade atomically; the 2.6 baseline is frozen after inventory conversion."""
    from targets.asset_migration import run_unified_startup
    await run_unified_startup(db_pool, _run_schema_migrations_26_baseline)


''']
    path.write_text(''.join(lines))

path=Path('api/targets/router.py'); source=path.read_text()
if 'configure_asset_router' not in source:
    source=source.replace('router = APIRouter()', '''from .asset_router import router as asset_router, configure_asset_router
router = APIRouter()
router.include_router(asset_router)''',1)
    source=source.replace('    _pool_provider = pool_provider', '    _pool_provider = pool_provider\n    configure_asset_router(pool_provider)',1)
    path.write_text(source)

out=[]
def emit(path,names):
    source=Path(path).read_text(); lines=source.splitlines()
    for node in ast.parse(source).body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
            out.append(f'\n=== {path}:{node.lineno} {node.name} ===\n'+'\n'.join(lines[node.lineno-1:node.end_lineno]))
emit('api/api.py',{'_validate_approval_receipt_for_action','_authorized_for_active_testing_sql','_public_target_row'})
emit('api/scan/contracts.py',{'bind_scan_scope_receipt'})
emit('api/target_authorization.py',{'current_target_authorization','authorize_target','revoke_target_authorization'})
emit('scanner/scanner_tools/device_web.py',{'_safe_request_headers'})
for path in ['ui/src/app/targets/page.tsx','ui/src/app/credentials/page.tsx','ui/src/lib/apiConfig.ts']:
    lines=Path(path).read_text().splitlines()
    out.append(f'\n=== {path} total {len(lines)} lines ===\n')
    if path.endswith('apiConfig.ts'):
        out.extend(lines)
    elif '/targets/' in path:
        out.extend(f'{i+1}: {line}' for i,line in enumerate(lines) if 'export default' in line or 'function ' in line or 'return (' in line)
        out.extend(lines[-70:])
    else:
        for i,line in enumerate(lines):
            if 'getDevices(' in line or 'getTargets(' in line or 'target_kind:' in line or 'useUrlFilters' in line:
                out.extend(f'{j+1}: {lines[j]}' for j in range(max(0,i-4),min(len(lines),i+18)))
Path('.implementation/authority-ui-contracts.txt').write_text('\n'.join(out)+'\n')
for path in Path('api/targets').glob('asset*.py'): ast.parse(path.read_text())
