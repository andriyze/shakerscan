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
        async with pool.acquire() as c:
            hunt = await c.fetchval("INSERT INTO hunt_runs(target_kind,target_id,status) VALUES('web',$1,'completed') RETURNING id", t)
            await c.execute("""INSERT INTO http_transactions(plane,hunt_run_id,target_id,method,url)
                VALUES('hunt',$1,$2,'GET','https://example.invalid/synthetic')""", hunt, t)
        preview = await service.preview(pool, {'kind': 'target', 'target_id': str(t)})
        assert not preview['blockers'], preview['blockers']
        await service.execute(pool, preview['preview_id'], await approve(pool, preview))
        async with pool.acquire() as c:
            assert await c.fetchval('SELECT COUNT(*) FROM http_transactions WHERE hunt_run_id=$1', hunt) == 0
    run(scenario)


@pytest.mark.parametrize('hold', ['legal_hold', 'audit', 'explicit'])
def test_retained_http_history_still_honors_actual_holds(hold):
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
