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
from uuid import UUID, uuid4

import pytest
from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get('LIFECYCLE_TEST_DATABASE_URL')
REQUIRED = os.environ.get('LIFECYCLE_POSTGRES_REQUIRED') == '1'
pytestmark = pytest.mark.skipif(not DSN and not REQUIRED, reason='Requires an explicit disposable local lifecycle test database')
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip('asyncpg')
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'api'), str(ROOT / 'scanner')]
from api.data_lifecycle import service
from api.data_lifecycle.inventory import decoded
from fastapi import HTTPException


@pytest.fixture(scope='module', autouse=True)
def schema():
    require_disposable_database(DSN or '', 'shakerscan_lifecycle_test')

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


def test_finding_delete_erases_its_evidence_and_scopes_and_replays():
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
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1',e)==0
            # Only the finding goes: its scan and target remain.
            assert await c.fetchval('SELECT target_id FROM scans WHERE id=$1',scan)==t
    run(scenario)


def test_target_delete_erases_its_scans_and_evidence_and_preserves_sibling():
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
        assert preview['records']['delete']['scans']['count']==1
        assert 'scans' not in preview['records']['retain']
        result = await service.execute(pool,preview['preview_id'],await approve(pool,preview))
        assert result['deleted_ids']==[str(t)] and result['external_files_deleted'] and result['files']['complete']
        async with pool.acquire() as c:
            assert not await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1',t)
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1 AND parent_target_id IS NULL',s)==1
            assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1',other)==1
            assert await c.fetchval('SELECT COUNT(*) FROM scans WHERE id=$1',scan)==0
            assert await c.fetchval('SELECT COUNT(*) FROM credential_profiles WHERE id=$1',profile)==0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1',e)==0
    run(scenario)


@pytest.mark.parametrize('blocker', ['scan','hunt','retest','owner_hold','evidence_hold','pending_evidence'])
def test_execution_and_holds_block_preview_and_execution(blocker, monkeypatch):
    # Holds block only on deployments that enforce them; running work always blocks.
    monkeypatch.setenv('SHAKERSCAN_DELETION_ENFORCE_HOLDS', '1')

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
        if blocker == 'retest':
            # A queued verification nothing has picked up is cancelled by an approved deletion,
            # not a reason to refuse it; the stale preview below still fails on drift.
            assert not newer['blockers'] and newer['abandoned'] == {'finding_verifications': 1}
        else:
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


def test_sensitive_scan_archive_is_erased_with_its_target_and_receipted():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        transaction, blob = uuid4(), uuid4()
        async with pool.acquire() as c:
            await c.execute("""INSERT INTO evidence_objects(id,scan_id,storage_uri,retention_class)
                VALUES($1,NULL,'file:///synthetic/unread/raw-headers.json','sensitive')""", blob)
            await c.execute("""INSERT INTO http_transactions(id,plane,scan_id,target_id,method,url,request_headers_object_id)
                VALUES($1,'scan',$2,$3,'GET','https://example.invalid/synthetic',$4)""", transaction, scan, t, blob)
            await c.execute("UPDATE evidence_objects SET retention_class='sensitive' WHERE id=$1", evidence)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['http_transactions']['count'] == 1
        # The raw-header blob a transaction points at has no scan link; it is still erased.
        assert preview['records']['delete']['evidence_objects']['count'] == 2
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM http_transactions WHERE id=$1', transaction) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=ANY($1::uuid[])', [blob, evidence]) == 0
            payload = decoded(await c.fetchval('SELECT result_json FROM command_results WHERE id=$1', UUID(preview['preview_id'])))
            assert payload['result']['deleted_records']['http_transactions'] == 1
            assert payload['result']['files']['complete'] is True
    run(scenario)


def test_cascading_sensitive_hunt_archive_is_erased_with_its_target():
    """Every recorded transaction is classified sensitive by default; treating that as a hold
    made any target that had ever been hunted undeletable ("archive the target instead").
    An operator-approved, dangerous-tier deletion erases the target's own archive."""
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        blob = uuid4()
        async with pool.acquire() as c:
            hunt = await c.fetchval("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'completed') RETURNING id", t)
            # A Hunt's raw-header blob has no scan or finding link: it used to be orphaned forever.
            await c.execute("INSERT INTO evidence_objects(id,storage_uri,retention_class) VALUES($1,'local:evidence_objects/hh/hunt.json','sensitive')", blob)
            await c.execute("""INSERT INTO http_transactions(plane,hunt_run_id,target_id,method,url,request_headers_object_id)
                VALUES('hunt',$1,$2,'GET','https://example.invalid/synthetic',$3)""", hunt, t, blob)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM http_transactions WHERE hunt_run_id=$1', hunt) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1', blob) == 0
    run(scenario)


@pytest.mark.parametrize('hold', ['legal_hold', 'audit', 'explicit'])
def test_retained_http_history_still_honors_actual_holds(hold, monkeypatch):
    monkeypatch.setenv('SHAKERSCAN_DELETION_ENFORCE_HOLDS', '1')
    # 'explicit' is a sensitive row with legal_hold=true in its metadata: the flag holds it,
    # the classification alone does not.
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


def test_terminal_blocked_research_does_not_prevent_deletion():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            from api.research_agent import RESEARCH_EPISODE_VERSION
            await c.execute("INSERT INTO research_episodes(target_id,objective,episode_version,status) VALUES($1,'Synthetic blocked research',$2,'blocked')", t, RESEARCH_EPISODE_VERSION)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
    run(scenario)


def test_archive_between_due_selection_and_claim_stops_both_schedulers():
    from datetime import timezone, timedelta
    from api.targets.archive import archive
    from api.schedules.router import fetch_due_schedules, claim_due_schedule
    from api.schedules import managed_occurrences as managed
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        schedule, now = uuid4(), datetime.now(timezone.utc)
        async with pool.acquire() as c:
            await c.execute("""INSERT INTO schedules(id,target_id,name,frequency,next_run_at)
                VALUES($1,$2,'Synthetic schedule','daily',$3)""", schedule, t, now)
            # Existing execution is explicitly not cancelled by archive.
            await c.execute("UPDATE scans SET status='running' WHERE id=$1", scan)
        await managed.initialize(pool)
        assert any(row['id'] == schedule for row in await fetch_due_schedules(pool, now=now))
        result = await archive(pool, t)
        assert result['schedules_paused'] == 1
        assert not await claim_due_schedule(pool, schedule_id=schedule, now=now)
        assert await managed.claim(pool, schedule, 'https://gateway.invalid', {}, now=now) is None
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT status FROM scans WHERE id=$1', scan) == 'running'
            assert not await c.fetchval('SELECT is_active FROM schedules WHERE id=$1', schedule)
            assert await c.fetchval('SELECT next_run_at FROM schedules WHERE id=$1', schedule) is None
            assert await c.fetchval('SELECT COUNT(*) FROM findings WHERE id=$1', f) == 1
    run(scenario)


def test_completed_deletion_replay_ignores_unrelated_writer_contention():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        preview = await service.preview(pool, {'kind':'findings','finding_ids':[str(f)]})
        approval = await approve(pool, preview)
        await service.execute(pool, preview['preview_id'], approval)
        async with pool.acquire() as writer, writer.transaction():
            # Ordinary unrelated writer holds ROW EXCLUSIVE; the previous replay
            # tried SHARE ROW EXCLUSIVE across scans and would wait/fail.
            await writer.execute("UPDATE scans SET current_phase='synthetic unrelated writer' WHERE id=$1", scan)
            result = await asyncio.wait_for(service.execute(pool, preview['preview_id'], approval), timeout=1.0)
            assert result['idempotent_replay']
    run(scenario)


def test_archived_managed_occurrence_only_reconciles_existing_receipt():
    from datetime import timezone
    from api.targets.archive import archive
    from api.schedules import managed_occurrences, managed_recovery
    from api.schedules.managed_dispatch import DispatchOutcome
    async def scenario(pool):
        target, sibling, scan, finding, other, evidence = await seeded(pool)
        schedule, now = uuid4(), datetime.now(timezone.utc)
        origin = 'https://gateway.invalid'
        async with pool.acquire() as conn:
            await conn.execute("INSERT INTO schedules(id,target_id,name,frequency,next_run_at) VALUES($1,$2,'Synthetic managed schedule','daily',$3)", schedule, target, now)
        await managed_occurrences.initialize(pool)
        occurrence = await managed_occurrences.claim(pool, schedule, origin, {}, now=now)
        assert occurrence is not None
        await managed_occurrences.settle(pool, occurrence['id'], occurrence['lease_id'], state='retry')
        await archive(pool, target)
        lookups = []
        class Dispatcher:
            async def lookup(self, schedule_id, occurrence_id):
                lookups.append((schedule_id, occurrence_id))
                return DispatchOutcome('accepted', 'receipt_recorded', str(scan))
            async def dispatch(self, *args):
                raise AssertionError('Archive must not dispatch new work')
        dispatcher = Dispatcher()
        dispatcher.origin = origin
        await managed_recovery.reconcile(pool, dispatcher, now)
        assert lookups == [(str(schedule), str(occurrence['id']))]
        async with pool.acquire() as conn:
            receipt = await conn.fetchrow('SELECT state,scan_id FROM managed_schedule_occurrences WHERE id=$1', occurrence['id'])
            assert receipt['state'] == 'accepted' and receipt['scan_id'] == scan
            row = await conn.fetchrow('SELECT is_active,next_run_at FROM schedules WHERE id=$1', schedule)
            assert not row['is_active'] and row['next_run_at'] is None
    run(scenario)


def test_abandoned_unfinished_rows_are_cancelled_by_an_approved_deletion():
    """A Hunt row left 'active' by a crashed session and a queued scan nothing picked up must
    not make a target undeletable; the approved deletion cancels them and proceeds."""
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            hunt = await c.fetchval("""INSERT INTO hunt_runs(target_kind,target_id,status,updated_at)
                VALUES('web',$1,'active',NOW() - INTERVAL '1 hour') RETURNING id""", t)
            queued = await c.fetchval("""INSERT INTO scans(target_id,target_url,status)
                VALUES($1,$2,'pending') RETURNING id""", t, f'https://{t}.example.invalid')
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        assert preview['abandoned'] == {'hunt_runs': 1, 'scans': 1}
        result = await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        assert result['cancelled_unfinished'] == {'hunt_runs': 1, 'scans': 1}
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1', t) == 0
            # Cancelled first, then erased with the target it belonged to.
            assert await c.fetchval('SELECT COUNT(*) FROM scans WHERE id=$1', queued) == 0
    run(scenario)


def test_a_running_scan_still_blocks_and_is_named():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            running = await c.fetchval("""INSERT INTO scans(target_id,target_url,status)
                VALUES($1,$2,'running') RETURNING id""", t, f'https://{t}.example.invalid')
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert any('scans: 1 running record(s)' in item and str(running) in item and 'POST /scans/{id}/cancel' in item
                   for item in preview['blockers']), preview['blockers']
        assert preview['abandoned'] == {}
    run(scenario)


def test_a_recently_active_hunt_blocks_but_an_old_one_is_abandoned():
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            live = await c.fetchval("""INSERT INTO hunt_runs(target_kind,target_id,status,updated_at)
                VALUES('web',$1,'active',NOW()) RETURNING id""", t)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert any('hunt_runs: 1 running record(s)' in item and str(live) in item for item in preview['blockers'])
    run(scenario)


def test_a_campaign_whose_scans_were_all_cancelled_is_abandoned_and_settled():
    """Cancelling a scan left its campaign 'active' forever and the target undeletable."""
    from api.asm_inventory import settle_campaign_after_scan
    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        async with pool.acquire() as c:
            campaign = await c.fetchval("INSERT INTO scan_campaigns(target_id,mode,status) VALUES($1,'continuous_asm','active') RETURNING id", t)
            cancelled = await c.fetchval("""INSERT INTO scans(target_id,target_url,status,campaign_id)
                VALUES($1,$2,'cancelled',$3) RETURNING id""", t, f'https://{t}.example.invalid', campaign)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        assert preview['abandoned'] == {'scan_campaigns': 1}
        async with pool.acquire() as c:
            assert await settle_campaign_after_scan(c, cancelled) == 1
            assert await c.fetchval('SELECT status FROM scan_campaigns WHERE id=$1', campaign) == 'cancelled'
            # A campaign with another scan still running is left alone.
            live = await c.fetchval("INSERT INTO scan_campaigns(target_id,mode,status) VALUES($1,'continuous_asm','active') RETURNING id", t)
            await c.execute("INSERT INTO scans(target_id,target_url,status,campaign_id) VALUES($1,$2,'running',$3)", t, f'https://{t}.example.invalid', live)
            done = await c.fetchval("INSERT INTO scans(target_id,target_url,status,campaign_id) VALUES($1,$2,'cancelled',$3) RETURNING id", t, f'https://{t}.example.invalid', live)
            assert await settle_campaign_after_scan(c, done) == 0
    run(scenario)


def test_target_delete_erases_every_credential_homed_on_it_including_device_kind():
    # A host's SSH identity is stored with target_kind='device' on the host's targets row. Deleting
    # the host used to keep it (and its shares), so it stayed usable on the targets it was shared to.
    from datetime import timezone
    from runtime.credential_store import CredentialStoreError, PostgresCredentialProfileStore

    async def scenario(pool):
        store = PostgresCredentialProfileStore()
        host, shared_to = uuid4(), uuid4()
        now = datetime.now(timezone.utc)
        async with pool.acquire() as c:
            for target, name in ((host, 'device-host'), (shared_to, 'shared-host')):
                await c.execute("INSERT INTO targets(id,url,discovery_source) VALUES($1,$2,'host')",
                                target, f'host://{name}-{target.hex[:8]}.example.invalid')
            profile = await store.create_profile(
                c, target_kind='device', target_id=host, name='Host SSH', auth_kind='ssh_password',
                principal_slot='ssh', principal_label=None, configuration={'auth_kind': 'ssh_password', 'secret_values_visible': False},
                encrypted_secret='enc:fernet:synthetic-secret', encrypted_metadata='enc:fernet:synthetic-metadata',
                expires_at=None, allowed_capabilities=['device.ssh.propose'], created_by='test', now=now)
            await store.grant_profile(c, profile_id=profile.profile_id, target_kind='device', target_id=shared_to,
                                      granted_by='test', now=now)
            # Usable on the target it was shared to before the host is deleted.
            await store.load_for_worker(c, profile_id=profile.profile_id, target_kind='device',
                                        target_id=shared_to, capability='device.ssh.propose')
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(host)})
        assert preview['records']['delete']['credential_profiles']['count'] == 1
        assert preview['records']['delete']['credential_profile_versions']['count'] == 1
        await service.execute(pool, preview['preview_id'], await approve(pool, preview), preview_hash=preview['preview_hash'])
        profile_id = UUID(profile.profile_id)
        async with pool.acquire() as c:
            for table, column in (('credential_profiles', 'id'), ('credential_profile_versions', 'profile_id'),
                                  ('credential_profile_bindings', 'profile_id')):
                assert await c.fetchval(f'SELECT COUNT(*) FROM {table} WHERE {column}=$1', profile_id) == 0, table
            with pytest.raises(CredentialStoreError):
                await store.load_for_worker(c, profile_id=profile.profile_id, target_kind='device',
                                            target_id=shared_to, capability='device.ssh.propose')
    run(scenario)


def test_target_erasure_removes_its_files_after_commit_but_keeps_a_shared_blob(tmp_path, monkeypatch):
    """Evidence blobs, scan artifacts, the scan's result file and checkpoint are erased once the
    rows naming them are gone. A blob another surviving scan still references is kept."""
    monkeypatch.setenv('RESULTS_DIR', str(tmp_path))

    async def scenario(pool):
        t, sibling, scan, f, other, evidence = await seeded(pool)
        kept_scan, job, own_blob, shared_blob = uuid4(), str(uuid4()), uuid4(), uuid4()
        own_uri, shared_uri = 'local:evidence_objects/aa/own.json', 'local:evidence_objects/bb/shared.json'
        artifact_uri = f'local:scan_artifacts/{scan}/result.json'
        files = {
            'own': tmp_path / 'evidence-objects/aa/own.json',
            'shared': tmp_path / 'evidence-objects/bb/shared.json',
            'artifact': tmp_path / f'scan-artifacts/{scan}/result.json',
            'checkpoint': tmp_path / f'{scan}_checkpoint.json',
            'result': tmp_path / f'host.example.invalid/20261003_010000_{job[:8]}.json',
            'latest': tmp_path / 'host.example.invalid/latest.json',
            'other_result': tmp_path / f'host.example.invalid/20261003_020000_{job[:8]}.json',
        }
        for name, path in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            owner = {'scan_id': str(scan), 'job_id': job} if name in ('result', 'latest') else {'scan_id': 'someone-else'}
            path.write_text(json.dumps(owner))
        async with pool.acquire() as c:
            await c.execute('UPDATE scans SET job_id=$2 WHERE id=$1', scan, job)
            await c.execute("INSERT INTO scans(id,target_id,target_url,status) VALUES($1,$2,$3,'completed')",
                            kept_scan, sibling, f'https://{sibling}.example.invalid')
            for blob, uri in ((own_blob, own_uri), (shared_blob, shared_uri)):
                await c.execute('INSERT INTO evidence_objects(id,storage_uri) VALUES($1,$2)', blob, uri)
            await c.execute("""INSERT INTO http_transactions(plane,scan_id,target_id,method,url,request_headers_object_id,response_body_object_id)
                VALUES('scan',$1,$2,'GET','https://example.invalid/a',$3,$4)""", scan, t, own_blob, shared_blob)
            await c.execute("""INSERT INTO http_transactions(plane,scan_id,target_id,method,url,response_body_object_id)
                VALUES('scan',$1,$2,'GET','https://example.invalid/b',$3)""", kept_scan, sibling, shared_blob)
            await c.execute("""INSERT INTO scan_artifacts(scan_id,artifact_type,artifact_key,storage_uri,storage_backend,content_sha256)
                VALUES($1,'result','result',$2,'local','0')""", scan, artifact_uri)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        result = await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        assert result['files']['complete'] and result['external_files_deleted']
        for name in ('own', 'artifact', 'checkpoint', 'result', 'latest'):
            assert not files[name].exists(), name
        # Shared content and a file that does not provably belong to the deleted scan stay.
        assert files['shared'].exists() and files['other_result'].exists()
        assert str(files['other_result']) in result['files']['unverified_result_files']
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1', own_blob) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1', shared_blob) == 1
    run(scenario)


def test_deleting_a_host_takes_its_linked_services_and_device_findings_do_not_block():
    async def scenario(pool):
        host, web, unrelated = uuid4(), uuid4(), uuid4()
        async with pool.acquire() as c:
            await c.execute("INSERT INTO targets(id,url,discovery_source) VALUES($1,'host://tv.example.invalid','host')", host)
            await c.execute("INSERT INTO targets(id,url,asset_owner_id) VALUES($1,'https://tv.example.invalid:8443',$2)", web, host)
            await c.execute("INSERT INTO targets(id,url) VALUES($1,'https://other.example.invalid')", unrelated)
            # A device finding carries the host's own id as device_target_id.
            await c.execute("""INSERT INTO findings(id,target_id,device_target_id,fingerprint,title,severity)
                VALUES($1,$2,$2,$3,'Device issue','low')""", uuid4(), host, str(uuid4()))
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(host)})
        assert not preview['blockers'], preview['blockers']
        assert preview['root_ids'] == [str(host), str(web)]
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=ANY($1::uuid[])', [host, web]) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1', unrelated) == 1
    run(scenario)


def test_domain_deletion_selects_its_group_and_linked_services_only():
    async def scenario(pool):
        ids = {name: uuid4() for name in ('apex', 'sub', 'host', 'service', 'lookalike', 'other_tld', 'co_uk')}
        rows = [('apex', 'https://acme-test.com', None), ('sub', 'https://api.acme-test.com', None),
                ('host', 'host://db.acme-test.com', None), ('service', 'https://db.acme-test.com:9000', 'host'),
                ('lookalike', 'https://notacme-test.com', None), ('other_tld', 'https://acme-test.org', None),
                ('co_uk', 'https://shop.acme-test.co.uk', None)]
        async with pool.acquire() as c:
            for name, url, owner in rows:
                source = 'host' if url.startswith('host://') else None
                await c.execute("INSERT INTO targets(id,url,discovery_source,asset_owner_id) VALUES($1,$2,$3,$4)",
                                ids[name], url, source, ids[owner] if owner else None)
        preview = await service.preview(pool, {'kind': 'domain', 'domain': 'acme-test.com'})
        roots = set(preview['root_ids'])
        assert {str(ids[n]) for n in ('apex', 'sub', 'host', 'service')} <= roots
        assert not {str(ids[n]) for n in ('lookalike', 'other_tld', 'co_uk')} & roots
        async with pool.acquire() as c:
            # Hosts the database created for these web targets belong to the same group.
            locators = [r['locator'] for r in await c.fetch(
                'SELECT target_asset_locator(url) AS locator FROM targets WHERE id=ANY($1::uuid[])',
                [UUID(v) for v in roots])]
        assert all(l == 'acme-test.com' or l.endswith('.acme-test.com') for l in locators), locators
        multi_part = await service.preview(pool, {'kind': 'domain', 'domain': 'acme-test.co.uk'})
        assert str(ids['co_uk']) in multi_part['root_ids']
        assert not {str(ids[n]) for n in ('apex', 'lookalike', 'other_tld')} & set(multi_part['root_ids'])
        with pytest.raises(HTTPException) as missing:
            await service.preview(pool, {'kind': 'domain', 'domain': 'nothing-here.example'})
        assert missing.value.status_code == 404
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            left = {r['id'] for r in await c.fetch('SELECT id FROM targets WHERE id=ANY($1::uuid[])', list(ids.values()))}
            assert left == {ids['lookalike'], ids['other_tld'], ids['co_uk']}
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=ANY($1::uuid[])', [UUID(v) for v in roots]) == 0
    run(scenario)


def test_a_credentials_sessions_on_other_targets_do_not_block_deleting_its_home():
    from datetime import timezone
    from runtime.credential_store import PostgresCredentialProfileStore

    async def scenario(pool):
        store = PostgresCredentialProfileStore()
        home, elsewhere = uuid4(), uuid4()
        now = datetime.now(timezone.utc)
        async with pool.acquire() as c:
            for target, name in ((home, 'home'), (elsewhere, 'elsewhere')):
                await c.execute("INSERT INTO targets(id,url) VALUES($1,$2)", target, f'https://{name}-{target.hex[:6]}.example.invalid')
            profile = await store.create_profile(
                c, target_kind='web', target_id=home, name='Shared login', auth_kind='json_login',
                principal_slot='primary', principal_label=None,
                configuration={'auth_kind': 'json_login', 'secret_values_visible': False},
                encrypted_secret='enc:fernet:synthetic', encrypted_metadata='enc:fernet:synthetic',
                expires_at=None, allowed_capabilities=['http.request'], created_by='test', now=now)
            await store.grant_profile(c, profile_id=profile.profile_id, target_kind='web', target_id=elsewhere,
                                      granted_by='test', now=now)
            await c.execute("""INSERT INTO auth_sessions(id,owner_kind,owner_id,target_kind,target_id,target_binding_digest,
                principal_slot,profile_id,profile_version,auth_kind,encrypted_headers,status,established_at,expires_at,
                refresh_after,evidence_receipt_digest,source_action_id)
                VALUES($1,'hunt',$2,'web',$3,$5,'primary',$4,1,'json_login','enc:fernet:session','active',NOW(),
                       NOW()+INTERVAL '1 hour',NOW()+INTERVAL '30 minutes',$6,$7)""",
                uuid4(), uuid4(), elsewhere, UUID(profile.profile_id), '0' * 64, 'a' * 64, uuid4())
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(home)})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['auth_sessions']['count'] == 1
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM auth_sessions WHERE profile_id=$1', UUID(profile.profile_id)) == 0
    run(scenario)


async def _two_targets(c):
    home, elsewhere = uuid4(), uuid4()
    for target, name in ((home, 'home'), (elsewhere, 'elsewhere')):
        await c.execute("INSERT INTO targets(id,url) VALUES($1,$2)", target, f'https://{name}-{target.hex[:6]}.example.invalid')
    return home, elsewhere


async def _shared_login(c, store, home, elsewhere, now):
    profile = await store.create_profile(
        c, target_kind='web', target_id=home, name=f'Login {uuid4().hex[:6]}', auth_kind='json_login',
        principal_slot='primary', principal_label=None,
        configuration={'auth_kind': 'json_login', 'secret_values_visible': False},
        encrypted_secret='enc:fernet:synthetic', encrypted_metadata='enc:fernet:synthetic',
        expires_at=None, allowed_capabilities=['http.request'], created_by='test', now=now)
    await store.grant_profile(c, profile_id=profile.profile_id, target_kind='web', target_id=elsewhere,
                              granted_by='test', now=now)
    session = uuid4()
    await c.execute("""INSERT INTO auth_sessions(id,owner_kind,owner_id,target_kind,target_id,target_binding_digest,
        principal_slot,profile_id,profile_version,auth_kind,encrypted_headers,status,established_at,expires_at,
        refresh_after,evidence_receipt_digest,source_action_id)
        VALUES($1,'hunt',$2,'web',$3,$5,'primary',$4,1,'json_login','enc:fernet:live-cookies','active',NOW(),
               NOW()+INTERVAL '1 hour',NOW()+INTERVAL '30 minutes',$6,$7)""",
        session, uuid4(), elsewhere, UUID(profile.profile_id), '0' * 64, 'a' * 64, uuid4())
    return profile, session


def test_deactivating_a_credential_ends_its_live_sessions_now():
    from datetime import timezone
    from runtime.credential_store import PostgresCredentialProfileStore

    async def scenario(pool):
        store, now = PostgresCredentialProfileStore(), datetime.now(timezone.utc)
        async with pool.acquire() as c:
            home, elsewhere = await _two_targets(c)
            profile, session = await _shared_login(c, store, home, elsewhere, now)
            await store.deactivate_profile(c, profile_id=profile.profile_id, target_kind='web', target_id=home, now=now)
            row = await c.fetchrow('SELECT status, encrypted_headers, revocation_reason FROM auth_sessions WHERE id=$1', session)
        assert row['status'] == 'revoked' and row['revocation_reason'] == 'credential_deactivated'
        assert row['encrypted_headers'] != 'enc:fernet:live-cookies'
    run(scenario)


def test_a_credential_is_deleted_permanently_with_every_copy_and_reference():
    from datetime import timezone
    from runtime.credential_store import PostgresCredentialProfileStore

    async def scenario(pool):
        store, now = PostgresCredentialProfileStore(), datetime.now(timezone.utc)
        async with pool.acquire() as c:
            home, elsewhere = await _two_targets(c)
            profile, session = await _shared_login(c, store, home, elsewhere, now)
            pid = UUID(profile.profile_id)
            # A legacy mirror with the same id, assurance history (NO ACTION FK), and references.
            await c.execute("""INSERT INTO target_credential_profiles(id,target_id,name,auth_kind,secret_value)
                VALUES($1,$2,'legacy mirror','cookie','enc:fernet:legacy')""", pid, home)
            await c.execute("""INSERT INTO authenticated_profile_revisions(profile_id,revision,credential_version,
                credential_record_version,configuration_json,configuration_digest,created_by)
                VALUES($1,1,1,0,'{}'::jsonb,$2,'test')""", pid, 'b' * 64)
            await c.execute("""UPDATE targets SET metadata_json=jsonb_build_object('hunt_authority',
                jsonb_build_object('credential_profile_ids', jsonb_build_array($2::text, 'keep-me'))) WHERE id=$1""",
                elsewhere, str(pid))
            schedule = await c.fetchval("""INSERT INTO schedules(target_id,frequency,scan_options)
                VALUES($1,'daily',jsonb_build_object('credential_profile_ids', jsonb_build_array($2::text)))
                RETURNING id""", home, str(pid))
            running = await c.fetchval("""INSERT INTO scans(target_id,target_url,status,options)
                VALUES($1,'https://home.example.invalid','running',
                       jsonb_build_object('credential_profile_refs', jsonb_build_array($2::text))) RETURNING id""",
                home, str(pid))
        blocked = await service.preview(pool, {'kind': 'credential_profile', 'id': str(pid)})
        assert any('use this credential' in b for b in blocked['blockers']), blocked['blockers']
        async with pool.acquire() as c:
            await c.execute("UPDATE scans SET status='completed' WHERE id=$1", running)
        preview = await service.preview(pool, {'kind': 'credential_profile', 'id': str(pid)})
        assert not preview['blockers'], preview['blockers']
        for table in ('credential_profiles', 'credential_profile_versions', 'credential_profile_bindings',
                      'auth_sessions', 'target_credential_profiles', 'authenticated_profile_revisions'):
            assert preview['records']['delete'][table]['count'] >= 1, table
        result = await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        assert result['detached_references'] == {'targets.metadata_json': 1, 'schedules.scan_options': 1}
        async with pool.acquire() as c:
            for table, column in (('credential_profiles', 'id'), ('credential_profile_versions', 'profile_id'),
                                  ('credential_profile_bindings', 'profile_id'), ('auth_sessions', 'profile_id'),
                                  ('target_credential_profiles', 'id'), ('authenticated_profile_revisions', 'profile_id')):
                assert await c.fetchval(f'SELECT COUNT(*) FROM {table} WHERE {column}=$1', pid) == 0, table
            assert await c.fetchval("SELECT metadata_json->'hunt_authority'->'credential_profile_ids' FROM targets WHERE id=$1",
                                    elsewhere) == '["keep-me"]'
            assert await c.fetchval("SELECT scan_options->'credential_profile_ids' FROM schedules WHERE id=$1", schedule) == '[]'
            # The home target itself is untouched.
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1', home) == 1
    run(scenario)


def test_a_request_collection_is_deleted_permanently_with_environments_and_bindings():
    async def scenario(pool):
        async with pool.acquire() as c:
            home, elsewhere = await _two_targets(c)
            collection = await c.fetchval("""INSERT INTO request_collections(target_id,name,format,encrypted_payload,payload_sha256)
                VALUES($1,'Partner API','postman','enc:fernet:document',$2) RETURNING id""", home, 'c' * 64)
            await c.execute("""INSERT INTO request_collection_environments(collection_id,name,encrypted_payload,payload_sha256)
                VALUES($1,'prod','enc:fernet:environment',$2)""", collection, 'd' * 64)
            await c.execute("""INSERT INTO request_collection_bindings(collection_id,target_kind,target_id,allowed_origins)
                VALUES($1,'web',$2,'["https://elsewhere.example.invalid"]'::jsonb)""", collection, elsewhere)
            await c.execute("""UPDATE targets SET metadata_json=jsonb_build_object('hunt_authority',
                jsonb_build_object('collection_ids', jsonb_build_array($2::text))) WHERE id=$1""", elsewhere, str(collection))
        preview = await service.preview(pool, {'kind': 'request_collection', 'id': str(collection)})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['request_collection_environments']['count'] == 1
        assert preview['records']['delete']['request_collection_bindings']['count'] == 1
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM request_collections WHERE id=$1', collection) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM request_collection_environments WHERE collection_id=$1', collection) == 0
            assert await c.fetchval("SELECT metadata_json->'hunt_authority'->'collection_ids' FROM targets WHERE id=$1",
                                    elsewhere) == '[]'
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=ANY($1::uuid[])', [home, elsewhere]) == 2
    run(scenario)


@pytest.mark.parametrize('hold', ['owner_hold', 'evidence_hold', 'audit_instance'])
def test_holds_do_not_block_deletion_unless_the_deployment_enforces_them(hold, monkeypatch):
    """An open-source operator can delete every record they own. Authorization replay writes
    audit-class evidence, which used to make a target undeletable forever."""
    monkeypatch.delenv('SHAKERSCAN_DELETION_ENFORCE_HOLDS', raising=False)

    async def scenario(pool):
        t, s, scan, f, other, e = await seeded(pool)
        async with pool.acquire() as c:
            if hold == 'owner_hold':
                await c.execute("UPDATE targets SET metadata_json='{\"legal_hold\":true}' WHERE id=$1", t)
            elif hold == 'evidence_hold':
                await c.execute("UPDATE evidence_objects SET retention_class='legal_hold' WHERE id=$1", e)
            else:
                await c.execute("""INSERT INTO evidence_instances(finding_id,target_id,evidence_object_id,retention_policy,hash)
                    VALUES($1,$2,$3,'audit',$4)""", f, t, e, 'e' * 64)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM targets WHERE id=$1', t) == 0
            assert await c.fetchval('SELECT COUNT(*) FROM evidence_objects WHERE id=$1', e) == 0
    run(scenario)


async def _session(c, owner_kind, owner, target):
    profile = await c.fetchval("""INSERT INTO credential_profiles(id,target_kind,target_id,name,auth_kind,principal_slot,
        configuration_json,rotated_at,created_at,updated_at)
        VALUES($1,'web',$2,$3,'bearer_token','primary','{}',NOW(),NOW(),NOW()) RETURNING id""",
        uuid4(), target, f'login {uuid4().hex[:8]}')
    await c.execute("""INSERT INTO auth_sessions(id,owner_kind,owner_id,target_kind,target_id,target_binding_digest,
        principal_slot,profile_id,profile_version,auth_kind,encrypted_headers,status,established_at,expires_at,
        refresh_after,evidence_receipt_digest,source_action_id)
        VALUES($1,$2,$3,'web',$4,$5,'primary',$6,1,'json_login','enc:fernet:session','active',NOW(),
               NOW()+INTERVAL '1 hour',NOW()+INTERVAL '30 minutes',$7,$8)""",
        uuid4(), owner_kind, owner, target, '0' * 64, profile, 'a' * 64, uuid4())


async def _reservation(c, owner_kind, owner):
    await c.execute("""INSERT INTO budget_reservations(id,owner_kind,owner_id,action_id,action_digest,capability_name,
        status,version,state_digest,state_json,requested_json,created_at,updated_at)
        VALUES($1,$2,$3,'a1',$4,'http.request','requested',1,$4,'{}'::jsonb,'{}'::jsonb,NOW(),NOW())""",
        uuid4().hex, owner_kind, str(owner), 'c' * 64)


async def _count(c, table, column, value):
    return await c.fetchval(f'SELECT COUNT(*) FROM {table} WHERE {column}=$1', value)


def test_a_scan_is_deleted_with_its_shards_findings_traffic_and_sessions_and_nothing_else():
    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        async with pool.acquire() as c:
            url = f'https://{t}.example.invalid'
            shard = await c.fetchval("INSERT INTO scans(target_id,target_url,status,parent_scan_id) VALUES($1,$2,'completed',$3) RETURNING id", t, url, scan)
            later = await c.fetchval("INSERT INTO scans(target_id,target_url,status,baseline_scan_id) VALUES($1,$2,'completed',$3) RETURNING id", t, url, scan)
            # Re-observed by a later scan: it belongs to that scan now, and stays.
            kept = await c.fetchval("""INSERT INTO findings(target_id,scan_id,first_seen_scan_id,fingerprint,title,severity)
                VALUES($1,$2,$3,'re-observed','Synthetic issue','low') RETURNING id""", t, later, scan)
            await c.execute("""INSERT INTO http_transactions(plane,scan_id,target_id,method,url)
                VALUES('scan',$1,$2,'GET','https://example.invalid/shard')""", shard, t)
            await _session(c, 'scan', scan, t)
            await _reservation(c, 'scan', scan)
        preview = await service.preview(pool, {'kind': 'scan', 'id': str(scan)})
        assert not preview['blockers'], preview['blockers']
        assert preview['root_ids'][0] == str(scan) and str(shard) in preview['root_ids']
        assert preview['records']['delete']['scans']['count'] == 2
        assert preview['records']['delete']['findings']['count'] == 1
        assert preview['records']['delete']['http_transactions']['count'] == 1
        assert preview['records']['delete']['auth_sessions']['count'] == 1
        result = await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        assert result['kind'] == 'scan' and result['deleted'] == 2
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM scans WHERE id=ANY($1::uuid[])', [scan, shard]) == 0
            assert await _count(c, 'findings', 'id', f) == 0 and await _count(c, 'evidence_objects', 'id', e) == 0
            assert await _count(c, 'http_transactions', 'scan_id', shard) == 0
            assert await _count(c, 'auth_sessions', 'owner_id', scan) == 0
            assert await _count(c, 'budget_reservations', 'owner_id', str(scan)) == 0
            # The target, the later scan (baseline cleared) and its finding all remain.
            assert await _count(c, 'targets', 'id', t) == 1
            assert await c.fetchval('SELECT baseline_scan_id FROM scans WHERE id=$1', later) is None
            assert await c.fetchval('SELECT first_seen_scan_id FROM findings WHERE id=$1', kept) is None
    run(scenario)


def test_a_running_scan_blocks_its_own_deletion_and_a_never_started_one_is_cancelled():
    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        async with pool.acquire() as c:
            await c.execute("UPDATE scans SET status='running' WHERE id=$1", scan)
            queued = await c.fetchval("INSERT INTO scans(target_id,target_url,status) VALUES($1,'https://q.example.invalid','queued') RETURNING id", t)
        blocked = await service.preview(pool, {'kind': 'scan', 'id': str(scan)})
        assert any(str(scan) in b and 'cancel' in b for b in blocked['blockers']), blocked['blockers']
        # Another scan on the same target never blocks this one.
        preview = await service.preview(pool, {'kind': 'scan', 'id': str(queued)})
        assert not preview['blockers'], preview['blockers']
        result = await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        assert result['cancelled_unfinished'] == {'scans': 1}
        async with pool.acquire() as c:
            assert await _count(c, 'scans', 'id', queued) == 0 and await _count(c, 'scans', 'id', scan) == 1
    run(scenario)


def test_a_hunt_is_deleted_with_its_traffic_sessions_candidates_and_only_its_own_findings():
    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        blob = uuid4()
        async with pool.acquire() as c:
            hunt = await c.fetchval("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'completed') RETURNING id", t)
            await c.execute("INSERT INTO hunt_actions(hunt_run_id,capability_name,status) VALUES($1,'http.request','completed')", hunt)
            await c.execute("INSERT INTO evidence_objects(id,storage_uri) VALUES($1,'local:evidence_objects/hh/hunt-delete.json')", blob)
            await c.execute("""INSERT INTO http_transactions(plane,hunt_run_id,target_id,method,url,request_headers_object_id)
                VALUES('hunt',$1,$2,'GET','https://example.invalid/hunt',$3)""", hunt, t, blob)
            candidate = await c.fetchval("""INSERT INTO investigation_candidates(family,plane,title,claim,fingerprint,target_id,hunt_run_id)
                VALUES('access_control','web','Synthetic','claim',$1,$2,$3) RETURNING id""", uuid4().hex, t, hunt)
            own = await c.fetchval("""INSERT INTO findings(target_id,hunt_run_id,fingerprint,title,severity)
                VALUES($1,$2,'hunt-only','Synthetic issue','low') RETURNING id""", t, hunt)
            await c.execute('UPDATE findings SET hunt_run_id=$2 WHERE id=$1', f, hunt)  # a scan also observed it
            await _session(c, 'hunt', hunt, t)
            await _reservation(c, 'hunt', hunt)
            live = await c.fetchval("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'active') RETURNING id", t)
        blocked = await service.preview(pool, {'kind': 'hunt', 'id': str(live)})
        assert any(str(live) in b for b in blocked['blockers']), blocked['blockers']
        preview = await service.preview(pool, {'kind': 'hunt', 'id': str(hunt)})
        assert not preview['blockers'], preview['blockers']
        for table in ('hunt_actions', 'http_transactions', 'investigation_candidates', 'auth_sessions'):
            assert preview['records']['delete'][table]['count'] == 1, table
        assert preview['records']['delete']['findings']['count'] == 1
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await _count(c, 'hunt_runs', 'id', hunt) == 0
            assert await _count(c, 'http_transactions', 'hunt_run_id', hunt) == 0
            assert await _count(c, 'evidence_objects', 'id', blob) == 0
            assert await _count(c, 'investigation_candidates', 'id', candidate) == 0
            assert await _count(c, 'findings', 'id', own) == 0
            assert await _count(c, 'auth_sessions', 'owner_id', hunt) == 0
            assert await _count(c, 'budget_reservations', 'owner_id', str(hunt)) == 0
            assert await c.fetchval('SELECT hunt_run_id FROM findings WHERE id=$1', f) is None
            assert await _count(c, 'scans', 'id', scan) == 1 and await _count(c, 'hunt_runs', 'id', live) == 1
    run(scenario)


def test_an_ai_target_is_deleted_with_its_credentials_their_store_copies_scans_and_findings():
    async def scenario(pool):
        async with pool.acquire() as c:
            ai = await c.fetchval("""INSERT INTO ai_targets(name,endpoint_url,headers_template)
                VALUES('Assistant',$1,'{"X-Api-Key":"plaintext"}'::jsonb) RETURNING id""", f'https://{uuid4().hex}.example.invalid/chat')
            credential = await c.fetchval("""INSERT INTO ai_target_credentials(ai_target_id,auth_kind)
                VALUES($1,'bearer') RETURNING id""", ai)
            await c.execute("""INSERT INTO credential_profiles(id,target_kind,target_id,name,auth_kind,principal_slot,
                configuration_json,rotated_at,created_at,updated_at)
                VALUES($1,'api',$2,'AI key','bearer_token','primary','{}',NOW(),NOW(),NOW())""", credential, ai)
            ai_scan = await c.fetchval("""INSERT INTO scans(ai_target_id,target_url,status)
                VALUES($1,'https://ai.example.invalid','completed') RETURNING id""", ai)
            finding = await c.fetchval("""INSERT INTO findings(ai_target_id,scan_id,fingerprint,title,severity)
                VALUES($1,$2,'ai-finding','Prompt injection','high') RETURNING id""", ai, ai_scan)
            await c.execute("UPDATE ai_targets SET last_scan_id=$2 WHERE id=$1", ai, ai_scan)
            running = await c.fetchval("""INSERT INTO scans(ai_target_id,target_url,status)
                VALUES($1,'https://ai.example.invalid','running') RETURNING id""", ai)
        blocked = await service.preview(pool, {'kind': 'ai_target', 'id': str(ai)})
        assert any(str(running) in b for b in blocked['blockers']), blocked['blockers']
        async with pool.acquire() as c:
            await c.execute("UPDATE scans SET status='cancelled' WHERE id=$1", running)
        preview = await service.preview(pool, {'kind': 'ai_target', 'id': str(ai)})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['scans']['count'] == 2
        assert preview['records']['delete']['credential_profiles']['count'] == 1
        assert preview['records']['delete']['ai_target_credentials']['count'] == 1
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await _count(c, 'ai_targets', 'id', ai) == 0
            assert await _count(c, 'ai_target_credentials', 'id', credential) == 0
            assert await _count(c, 'credential_profiles', 'id', credential) == 0
            assert await _count(c, 'scans', 'ai_target_id', ai) == 0
            assert await _count(c, 'findings', 'id', finding) == 0
    run(scenario)


def test_a_model_intake_submission_and_a_model_intake_target_can_be_deleted():
    async def scenario(pool):
        async with pool.acquire() as c:
            subject = await c.fetchval("""INSERT INTO targets(url,discovery_source)
                VALUES($1,'model-intake') RETURNING id""", f'model://{uuid4().hex}')
            scan = await c.fetchval("""INSERT INTO scans(target_id,target_url,status)
                VALUES($1,'model://subject','completed') RETURNING id""", subject)
            submission = await c.fetchval("""INSERT INTO model_intake_submissions(scan_id,requested_by,requested_environment,
                source_kind,source_reference_hash,state) VALUES($1,'operator','staging','huggingface',$2,'evidence_ready')
                RETURNING id""", scan, 'e' * 64)
            await c.execute("""INSERT INTO model_intake_runner_jobs(submission_id,operation,state,remote_job_id,request_sha256,
                request_json,created_by) VALUES($1,'runtime','pending',$2,$3,'{}'::jsonb,'operator')""", submission, uuid4(), 'f' * 64)
            await c.execute("""INSERT INTO model_intake_admissions(submission_id,target_id,scan_id,status,artifact_sha256,
                statement_sha256,admission_package,decision,issued_at,expires_at,reassessment_due_at)
                VALUES($1,$2,$3,'active',$4,$4,'{}'::jsonb,'admit',NOW(),NOW()+INTERVAL '30 days',NOW()+INTERVAL '7 days')""",
                submission, subject, scan, '1' * 64)
        preview = await service.preview(pool, {'kind': 'model_intake_submission', 'id': str(submission)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await _count(c, 'model_intake_submissions', 'id', submission) == 0
            assert await _count(c, 'model_intake_runner_jobs', 'submission_id', submission) == 0
            assert await _count(c, 'model_intake_admissions', 'target_id', subject) == 0
            assert await _count(c, 'scans', 'id', scan) == 0
        # The subject target itself is no longer refused.
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(subject)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await _count(c, 'targets', 'id', subject) == 0
    run(scenario)


def test_a_deleted_domain_takes_its_scope_records_and_discovery_runs_but_not_its_deletion_receipt():
    async def scenario(pool):
        async with pool.acquire() as c:
            target = await c.fetchval("INSERT INTO targets(url,root_domain) VALUES('https://app.scope-gone.com','scope-gone.com') RETURNING id")
            other = await c.fetchval("INSERT INTO targets(url,root_domain) VALUES('https://app.scope-kept.com','scope-kept.com') RETURNING id")
            for owner in (target, other):
                await c.execute("""INSERT INTO scope_receipts(id,target_id,input_scope,normalized_scope,verdict)
                    VALUES($1,$2,'{"url":"https://app.example.invalid"}'::jsonb,'{}'::jsonb,'allowed')""", str(uuid4()), owner)
            for domain in ('scope-gone.com', 'scope-kept.com'):
                await c.execute("INSERT INTO discovery_runs(id,root_domain,status) VALUES($1,$2,'completed')", uuid4(), domain)
        preview = await service.preview(pool, {'kind': 'domain', 'domain': 'scope-gone.com'})
        assert not preview['blockers'], preview['blockers']
        assert preview['records']['delete']['scope_receipts']['count'] == 1
        assert preview['records']['delete']['discovery_runs']['count'] == 1
        receipt = await approve(pool, preview)
        await service.execute(pool, preview['preview_id'], receipt)
        async with pool.acquire() as c:
            assert await c.fetchval("""SELECT COUNT(*) FROM scope_receipts WHERE target_id=$1
                AND COALESCE(normalized_scope->>'kind','')<>'record_deletion'""", target) == 0
            # The deletion's own receipt (IDs only) stays so a retry replays the same result.
            assert await c.fetchval('SELECT COUNT(*) FROM scope_receipts WHERE id=$1', preview['scope_receipt_id']) == 1
            assert await _count(c, 'discovery_runs', 'root_domain', 'scope-gone.com') == 0
            assert await _count(c, 'discovery_runs', 'root_domain', 'scope-kept.com') == 1
            assert await _count(c, 'scope_receipts', 'target_id', other) == 1
        replay = await service.execute(pool, preview['preview_id'], receipt)
        assert replay['idempotent_replay'] is True
    run(scenario)


def test_an_enforced_hold_on_its_target_blocks_deleting_a_scan(monkeypatch):
    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        async with pool.acquire() as c:
            await c.execute("""UPDATE targets SET metadata_json=COALESCE(metadata_json,'{}'::jsonb)
                || '{"legal_hold": true}'::jsonb WHERE id=$1""", t)
        assert not (await service.preview(pool, {'kind': 'scan', 'id': str(scan)}))['blockers']
        monkeypatch.setenv('SHAKERSCAN_DELETION_ENFORCE_HOLDS', '1')
        blocked = await service.preview(pool, {'kind': 'scan', 'id': str(scan)})
        assert any('hold' in b for b in blocked['blockers']), blocked['blockers']
    run(scenario)


def test_ai_header_secrets_are_encrypted_on_an_already_converted_database(monkeypatch):
    """The startup baseline never runs again once targets are converted; the backfill must."""
    from cryptography.fernet import Fernet
    import secret_store
    from retest_contract import run_schema_migrations
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY', Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, '_fernet', None)
    monkeypatch.setattr(secret_store, '_loaded', False)

    async def scenario(pool):
        async with pool.acquire() as c:
            assert await c.fetchval("SELECT 1 FROM app_schema_migrations WHERE name='unified_target_assets_v1'")
            await c.execute("DELETE FROM app_schema_migrations WHERE name='v2_ai_header_template_secrets_v1'")
            ai = await c.fetchval("""INSERT INTO ai_targets(name,endpoint_url,headers_template)
                VALUES('Legacy',$1,'{"X-Api-Key":"sk-plain","Accept":"application/json"}'::jsonb) RETURNING id""",
                f'https://{uuid4().hex}.example.invalid/chat')
        await run_schema_migrations(pool)
        async with pool.acquire() as c:
            headers = json.loads(await c.fetchval('SELECT headers_template::text FROM ai_targets WHERE id=$1', ai))
            assert await c.fetchval("SELECT 1 FROM app_schema_migrations WHERE name='v2_ai_header_template_secrets_v1'")
        assert headers['X-Api-Key'].startswith('enc:fernet:') and headers['Accept'] == 'application/json'
        assert secret_store.decrypt_secret(headers['X-Api-Key']) == 'sk-plain'
    run(scenario)


def _archive_key(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    monkeypatch.setenv("AI_CREDENTIAL_ENC_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(secret_store, "_fernet", None)
    monkeypatch.setattr(secret_store, "_loaded", False)
    return secret_store


def test_raw_traffic_is_encrypted_at_rest_and_revealed_only_for_raw_views(tmp_path, monkeypatch):
    _archive_key(monkeypatch)
    monkeypatch.setenv("SHAKERSCAN_HTTP_ARCHIVE", "full")
    from runtime.http_archive import HttpTransaction, archive_http_transactions, _default_store
    from runtime.http_archive_reader import read_transactions

    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        tx = HttpTransaction(plane="scan", method="POST", url="https://example.invalid/login", sequence=1,
                             scan_id=str(scan), target_id=str(t), status_code=200,
                             request_headers={"Authorization": "Bearer raw-canary-req"},
                             request_body=b'{"password":"raw-canary-body"}',
                             response_headers={"Set-Cookie": "sid=raw-canary-cookie"})
        async with pool.acquire() as c:
            assert await archive_http_transactions(c, [tx], store=_default_store(tmp_path), scan_id=str(scan)) == 1
            at_rest = await c.fetchval("""SELECT string_agg(to_jsonb(e)::text, ' ') FROM evidence_objects e
                WHERE object_type='http_archive_blob' AND scan_id=$1""", scan)
            assert at_rest and "raw-canary" not in at_rest
            rows = await read_transactions(c, scan_id=str(scan))
        assert "Bearer raw-canary-req" in json.dumps(rows[0]["request_headers"])
        assert "raw-canary-body" in json.dumps(rows[0]["request_body"])
        assert "raw-canary-cookie" in json.dumps(rows[0]["response_headers"])
    run(scenario)


def test_archived_plaintext_is_encrypted_once_at_startup_including_local_files(tmp_path, monkeypatch):
    _archive_key(monkeypatch)
    from runtime import archive_blob_secrets as blobs

    async def scenario(pool):
        t, sibling, scan, f, other, e = await seeded(pool)
        async with pool.acquire() as c:
            await c.execute("DELETE FROM app_schema_migrations WHERE name=$1", blobs.MIGRATION)
            inline = await c.fetchval("""INSERT INTO evidence_objects(scan_id,object_type,content_sha256,size_bytes,
                storage_uri,redaction_profile,content) VALUES($1,'http_archive_blob',$2,10,'inline:','none',
                '{"authorization":"Bearer legacy-canary"}'::jsonb) RETURNING id""", scan, 'a' * 64)
            uri = "local:evidence_objects/bb/" + "b" * 64 + ".json"
            path = tmp_path / "evidence-objects" / "bb" / ("b" * 64 + ".json")
            path.parent.mkdir(parents=True)
            path.write_text('"Set-Cookie: sid=legacy-file-canary"')
            await c.execute("""INSERT INTO evidence_objects(scan_id,object_type,content_sha256,size_bytes,
                storage_uri,redaction_profile) VALUES($1,'http_archive_blob',$2,10,$3,'none')""", scan, 'b' * 64, uri)
            assert await blobs.encrypt_stored_blobs(c, results_dir=tmp_path) == 2
            stored = await c.fetchval("SELECT content::text FROM evidence_objects WHERE id=$1", inline)
            assert "legacy-canary" not in stored and "legacy-file-canary" not in path.read_text()
            assert json.loads(blobs.reveal(stored)) == {"authorization": "Bearer legacy-canary"}
            assert json.loads(blobs.reveal(path.read_text())) == "Set-Cookie: sid=legacy-file-canary"
            assert await blobs.encrypt_stored_blobs(c, results_dir=tmp_path) == 0  # marker: once
    run(scenario)
