"""Real PostgreSQL deletion acceptance. Never uses DATABASE_URL or a deployed database.

LIFECYCLE_TEST_DATABASE_URL must address localhost/shakerscan_lifecycle_test. This
isolated test database is RESET at module setup. No target traffic is generated.
"""
import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest

DSN = os.environ.get('LIFECYCLE_TEST_DATABASE_URL')
pytestmark = pytest.mark.skipif(not DSN, reason='Requires an explicit disposable local lifecycle test database')
asyncpg = pytest.importorskip('asyncpg')
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'api'), str(ROOT / 'scanner')]
from api.data_lifecycle import service
from api.data_lifecycle.inventory import decoded
from fastapi import HTTPException


@pytest.fixture(scope='module', autouse=True)
def schema():
    if not DSN:
        pytest.skip('No disposable lifecycle database configured')
    address = urlsplit(DSN)
    assert address.hostname in {'localhost', '127.0.0.1', '::1'}
    assert address.path == '/shakerscan_lifecycle_test', 'Refusing to reset a non-test database'

    async def initialize():
        from retest_contract import run_schema_migrations
        async with asyncpg.create_pool(DSN, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                await conn.execute('DROP SCHEMA public CASCADE; CREATE SCHEMA public;')
                await conn.execute((ROOT / 'db/init.sql').read_text())
            await run_schema_migrations(pool)
    asyncio.run(initialize())


async def seeded(pool):
    target, sibling, scan, finding, other, evidence = (uuid4() for _ in range(6))
    async with pool.acquire() as c:
        await c.execute("INSERT INTO targets(id,url,root_domain,active_findings_count) VALUES($1,$2,'example.invalid',1)", target, f'https://{target}.example.invalid')
        await c.execute("INSERT INTO targets(id,url,parent_target_id) VALUES($1,$2,$3)", sibling, f'https://{sibling}.example.invalid', target)
        await c.execute("INSERT INTO scans(id,target_id,target_url,status) VALUES($1,$2,$3,'completed')", scan,target,f'https://{target}.example.invalid')
        for fid, tid in [(finding,target),(other,sibling)]:
            await c.execute("INSERT INTO findings(id,target_id,scan_id,fingerprint,title,severity) VALUES($1,$2,$3,$4,'Synthetic issue','low')",fid,tid,scan if tid==target else None,str(fid))
        await c.execute("INSERT INTO evidence_objects(id,scan_id,finding_id,storage_uri) VALUES($1,$2,$3,'file:///synthetic/unread/evidence.json')",evidence,scan,finding)
    return target,sibling,scan,finding,other,evidence


async def approve(pool, preview):
    receipt = uuid4()
    async with pool.acquire() as c:
        await c.execute("""INSERT INTO approval_receipts(id,scope_receipt_id,risk_tier,confirmations,action_name,
            action_context,approved_by,expires_at,status) VALUES($1,$2,'dangerous',$3::jsonb,$4,$5::jsonb,'test operator',$6,'active')""",
            receipt,preview['scope_receipt_id'],json.dumps(sorted(service.CONFIRMATIONS)),service.COMMAND,
            json.dumps({'preview_id':preview['preview_id'],'preview_hash':preview['preview_hash']}),
            datetime.fromisoformat(preview['expires_at']))
    return receipt


def run(scenario):
    async def work():
        async with asyncpg.create_pool(DSN, min_size=1, max_size=5) as pool:
            await scenario(pool)
    asyncio.run(work())


def test_finding_delete_preserves_storage_and_scopes_and_replays():
    async def scenario(pool):
        t,s,scan,f,other,e = await seeded(pool)
        with pytest.raises(HTTPException) as error:
            await service.preview(pool, {'kind':'findings','finding_ids':[str(f)],'scan_id':str(uuid4())})
        assert error.value.status_code == 404
        preview = await service.preview(pool, {'kind':'findings','finding_ids':[str(f)],'scan_id':str(scan)})
        assert preview['blockers'] == []
        assert preview['records']['delete']['findings']['count']==1
        receipt = await approve(pool,preview)
        first, second = await asyncio.gather(*(service.execute(pool,preview['preview_id'],receipt,preview_hash=preview['preview_hash']) for _ in range(2)))
        assert first['deleted']==second['deleted']==1
        assert {first['idempotent_replay'], second['idempotent_replay']} == {True,False}
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1',f)==0
            assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1',other)==1
            assert await c.fetchval('SELECT active_findings_count FROM targets WHERE id=$1',t)==0
            row=await c.fetchrow('SELECT finding_id,storage_uri FROM evidence_objects WHERE id=$1',e)
            assert row['finding_id'] is None and row['storage_uri'].startswith('file:')
            assert await c.fetchval('SELECT target_id FROM scans WHERE id=$1',scan)==t
    run(scenario)


def test_target_delete_removes_exact_root_and_preserves_child_and_scan():
    async def scenario(pool):
        t,s,scan,f,other,e = await seeded(pool)
        async with pool.acquire() as c:
            await c.execute("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'completed')",t)
            profile = uuid4()
            await c.execute("""INSERT INTO credential_profiles(id,target_kind,target_id,name,auth_kind,principal_slot,
                configuration_json,rotated_at,created_at,updated_at) VALUES($1,'web',$2,'fixture','bearer_token','primary','{}',NOW(),NOW(),NOW())""",profile,t)
        preview = await service.preview(pool,{'kind':'target','target_id':str(t)})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['hunt_runs']['count']==1
        assert preview['records']['delete']['credential_profiles']['count']==1
        result = await service.execute(pool,preview['preview_id'],await approve(pool,preview))
        assert result['deleted_ids']==[str(t)] and not result['external_files_deleted']
        async with pool.acquire() as c:
            assert not await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1',t)
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1 AND parent_target_id IS NULL',s)==1
            assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1',other)==1
            assert await c.fetchval('SELECT COUNT(*) FROM scans WHERE id=$1 AND target_id IS NULL',scan)==1
            assert await c.fetchval('SELECT COUNT(*) FROM credential_profiles WHERE id=$1',profile)==0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1 AND finding_id IS NULL',e)==1
    run(scenario)


@pytest.mark.parametrize('blocker', ['scan','hunt','retest','owner_hold','evidence_hold','pending_evidence'])
def test_execution_and_holds_block_preview_and_execution(blocker):
    async def scenario(pool):
        t,s,scan,f,other,e = await seeded(pool)
        preview = await service.preview(pool,{'kind':'target','target_id':str(t)})
        receipt = await approve(pool,preview)
        async with pool.acquire() as c:
            if blocker=='scan': await c.execute("UPDATE scans SET status='running' WHERE id=$1",scan)
            elif blocker=='hunt': await c.execute("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'active')",t)
            elif blocker=='retest': await c.execute("INSERT INTO finding_verifications(finding_id,target_id,finding_type,target_url,status) VALUES($1,$2,'xss','https://example.invalid','queued')",f,t)
            elif blocker=='owner_hold': await c.execute("UPDATE targets SET metadata_json='{\"legal_hold\":true}' WHERE id=$1",t)
            elif blocker=='evidence_hold': await c.execute("UPDATE evidence_objects SET retention_class='legal_hold' WHERE id=$1",e)
            else: await c.execute('UPDATE evidence_objects SET retention_delete_pending_at=NOW() WHERE id=$1',e)
        newer = await service.preview(pool,{'kind':'target','target_id':str(t)})
        assert newer['blockers']
        with pytest.raises(HTTPException) as error: await service.execute(pool,preview['preview_id'],receipt)
        assert error.value.status_code==409
        async with pool.acquire() as c: assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1',t)==1
    run(scenario)


def test_drift_rolls_back_and_new_preview_is_required():
    async def scenario(pool):
        t,s,scan,f,other,e = await seeded(pool)
        preview=await service.preview(pool,{'kind':'findings','finding_ids':[str(f)]})
        receipt=await approve(pool,preview)
        async with pool.acquire() as c: await c.execute("UPDATE findings SET notes='analyst update' WHERE id=$1",f)
        with pytest.raises(HTTPException) as error: await service.execute(pool,preview['preview_id'],receipt)
        assert error.value.status_code==409
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT finding_id FROM evidence_objects WHERE id=$1',e)==f
            assert await c.fetchval('SELECT status FROM command_results WHERE id=$1',UUID(preview['preview_id']))=='approval_required'
    run(scenario)


def test_age_execution_uses_frozen_ids_not_new_age_matches():
    async def scenario(pool):
        t,s,scan,f,other,e = await seeded(pool)
        domain=f'{t}.age.invalid'
        async with pool.acquire() as c:
            await c.execute('UPDATE targets SET root_domain=$2 WHERE id=$1',t,domain)
            await c.execute("UPDATE findings SET last_seen_at=NOW()-INTERVAL '60 days' WHERE id=$1",f)
        selection={'kind':'findings','older_than_days':30,'root_domain':domain}
        preview=await service.preview(pool,selection)
        assert preview['root_ids']==[str(f)]
        async with pool.acquire() as c:
            newer=uuid4()
            await c.execute("INSERT INTO findings(id,target_id,fingerprint,title,severity,last_seen_at) VALUES($1,$2,$3,'Late import','low',NOW()-INTERVAL '90 days')",newer,t,str(newer))
        # A newly matching row is not added to the immutable batch.
        result=await service.execute(pool,preview['preview_id'],await approve(pool,preview),selection=selection)
        assert result['deleted_ids']==[str(f)]
        async with pool.acquire() as c: assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1',newer)==1
    run(scenario)


def test_retained_sensitive_scan_archive_keeps_original_ownership_in_receipt():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        transaction = uuid4()
        async with pool.acquire() as c:
            await c.execute("""INSERT INTO http_transactions(id,plane,scan_id,target_id,method,url)
                VALUES($1,'scan',$2,$3,'GET','https://example.invalid/synthetic')""", transaction, scan, t)
            await c.execute("UPDATE evidence_objects SET retention_class='sensitive' WHERE id=$1", evidence)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        links = preview['records']['retain']['http_transactions']['ownership']
        assert {'id': str(transaction), 'scan_id': str(scan), 'target_id': str(t)} in links
        receipt = await approve(pool, preview)
        await service.execute(pool, preview['preview_id'], receipt)
        async with pool.acquire() as c:
            row = await c.fetchrow('SELECT target_id,scan_id,retention_class FROM http_transactions WHERE id=$1', transaction)
            assert row['target_id'] is None and row['scan_id'] == scan and row['retention_class'] == 'sensitive'
            payload = decoded(await c.fetchval('SELECT result_json FROM command_results WHERE id=$1', UUID(preview['preview_id'])))
            assert payload['manifest']['records']['retain']['http_transactions']['ownership'] == links
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1', evidence) == 1
    run(scenario)


def test_cascading_sensitive_hunt_archive_still_requires_archive_instead_of_erasure():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            hunt = await c.fetchval("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'completed') RETURNING id", t)
            await c.execute("""INSERT INTO http_transactions(plane,hunt_run_id,target_id,method,url)
                VALUES('hunt',$1,$2,'GET','https://example.invalid/synthetic')""", hunt, t)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert any('http_transactions' in item and 'archive' in item for item in preview['blockers'])
        with pytest.raises(HTTPException):
            await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM http_transactions WHERE hunt_run_id=$1', hunt) == 1
    run(scenario)


@pytest.mark.parametrize('hold', ['legal_hold', 'audit', 'explicit'])
def test_retained_http_history_still_honors_actual_holds(hold):
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            await c.execute("""INSERT INTO http_transactions(plane,scan_id,target_id,method,url,retention_class,metadata_json)
                VALUES('scan',$1,$2,'GET','https://example.invalid/synthetic',$3,$4::jsonb)""",
                scan, t, 'sensitive' if hold == 'explicit' else hold,
                json.dumps({'legal_hold': True} if hold == 'explicit' else {}))
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert any('http_transactions' in item for item in preview['blockers'])
    run(scenario)
