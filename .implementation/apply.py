"""Reviewed worker-dispatch and cross-view regression amendments."""
from pathlib import Path
import ast


def replace(path,old,new,count=1):
    p=Path(path);s=p.read_text()
    if new in s:return
    if s.count(old)!=count:raise RuntimeError((path,old[:100],s.count(old)))
    p.write_text(s.replace(old,new,count))

replace('api/worker.py', '''        if row:
            target_id = str(row['target_id']) if row['target_id'] else None
            ai_target_id = str(row['ai_target_id']) if row['ai_target_id'] else None
            device_target_id = str(row['device_target_id']) if row['device_target_id'] else None
''', '''        if row:
            from targets.asset_execution import execution_target_refs
            references = execution_target_refs(row)
            # target_id below is the application-only persistence path. Device scans
            # retain their canonical target_id in the database and execution receipts.
            canonical_target_id = references.canonical_target_id
            target_id = references.web_target_id
            ai_target_id = references.ai_target_id
            device_target_id = references.device_target_id
''')
replace('api/worker.py','    # Update database\n    target_id = None','    # Update database\n    canonical_target_id = None\n    target_id = None')
replace('api/worker.py', '''            await _record_internal_executor_tool_receipt(
                conn,
                scan_id=scan_id,
                job_id=job_id,
                target=target,
                target_id=target_id,''', '''            await _record_internal_executor_tool_receipt(
                conn,
                scan_id=scan_id,
                job_id=job_id,
                target=target,
                target_id=canonical_target_id,''')
replace('tests/test_target_asset_inputs_postgres.py', '    await PostgresRequestCollectionStore().ensure_schema(conn)\n', '''    await PostgresRequestCollectionStore().ensure_schema(conn)
    # Use the real baseline authority DDL, not a reduced mock schema.
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'api/retest_contract.py').read_text()
    constants = [node.value for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    for table in ('scope_receipts', 'approval_receipts'):
        ddl = [sql for sql in constants if f'CREATE TABLE IF NOT EXISTS {table} (' in sql]
        assert len(ddl) == 1, f'Baseline schema for {table} changed'
        await conn.execute(ddl[0])
''')
replace('ui/src/app/request-collections/page.tsx','id:asset.id,label:asset.name || asset.locator,detail:',
        'id:asset.id,label:(asset.name || asset.locator).slice(0, 240),detail:')
replace('ui/tests/credentials-page.test.mjs',
 "test('changing credential target kind cannot query with the previous kind target ID', () => {",
 "test('changing the view kind preserves the canonical asset ID and reloads profiles', () => {")
replace('ui/tests/credentials-page.test.mjs',
 "  // Kind and target change in one URL update, so no render pairs the new kind with the old ID.\n  assert.match(changeKind, /setFilters\\(\\{ target_kind: kind === 'web' \\? undefined : kind, target_id: undefined/)",
 "  // Kind selects a view of the same canonical target, not another inventory.\n  assert.match(changeKind, /setFilters\\(\\{ target_kind: kind === 'web' \\? undefined : kind/)\n  assert.doesNotMatch(changeKind, /target_id: undefined/)")
replace('ui/tests/request-collections-page.test.mjs','assert.match(page, /Ownership is exact target ID/)',
        'assert.match(page, /The asset owns one document/)')
replace('ui/tests/request-collections-page.test.mjs',r'assert.match(page, /exact scheme \+ hostname \+ port/)',
        r'assert.match(page, /application bindings retain the exact scheme, hostname, and port/)')
replace('ui/tests/target-choice-robustness.test.mjs',
 r'assert.match(collectionsPage, /if \(loading \|\| !targetId \|\| choices\.some\(\(choice\) => choice\.id === targetId\)\) return/)',
 r'assert.match(collectionsPage, /if \(loading \|\| !targetId \|\| assets\.some\(\(asset\) => asset\.id === targetId\)\) return/)')
replace('ui/tests/target-filtering-ux.test.mjs',r'assert.match(credentials, /getTarget\(targetId\)/)',
        r'assert.match(credentials, /getTargetAsset\(targetId\)/)')
p=Path('api/hunt/prior_knowledge.py');s=p.read_text();a=s.index('async def device_prior_knowledge(');b=s.index('\ndef _pack(',a)
part=s[a:b].replace('WHERE device_target_id=$1 AND status=',
 'WHERE target_id IN (SELECT id FROM targets WHERE id=$1 OR asset_owner_id=$1) AND status=')
p.write_text(s[:a]+part+s[b:])
replace('api/hunt/knowledge.py', '''        column = "device_target_id" if device else "target_id"
        where = [f"{column}={bind(target_id)}"]''', '''        owner = bind(target_id)
        if kind == "collections":
            where = [f"target_collection_visible(id,{owner})"]
        elif device and kind in {"findings", "scans", "candidates"}:
            where = [f"target_id IN (SELECT id FROM targets WHERE id={owner} OR asset_owner_id={owner})"]
        else:
            where = [f"target_id={owner}"]''')
for path in ['api/worker.py','api/hunt/knowledge.py','api/hunt/prior_knowledge.py']:
    ast.parse(Path(path).read_text())
