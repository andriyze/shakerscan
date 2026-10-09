"""Installed startup converts the complete legacy schema once, including subsequent writes."""
import asyncio
import importlib
from pathlib import Path
import sys

from targets.asset_migration import BoundConnectionPool
from contextlib import asynccontextmanager
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
        await admin.close()


def test_real_startup_upgrade_and_restart_preserve_new_writes():
    async def run():
        async with startup_database() as conn:
            api_root = str(Path(__file__).resolve().parents[1] / 'api')
            if api_root not in sys.path:
                sys.path.insert(0, api_root)
            module = importlib.import_module('retest_contract')
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Before upgrade','startup.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://startup.test:8443') RETURNING id")
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_targets'::regclass") == 'v'
            assert await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1',origin) == device
            after = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('After upgrade','after-startup.test') RETURNING id")
            total = await conn.fetchval('SELECT count(*) FROM targets')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT count(*) FROM targets') == total
            assert await conn.fetchval('SELECT name FROM targets WHERE id=$1',after) == 'After upgrade'
            assert await conn.fetchval("SELECT count(*) FROM app_schema_migrations WHERE name IN ('unified_target_assets_v1','unified_target_asset_inputs_v1')") == 2
            import asyncpg
            pool = await asyncpg.create_pool(os.environ['TARGET_ASSET_TEST_DATABASE_URL'],
                database=await conn.fetchval('SELECT current_database()'),min_size=2,max_size=2)
            try:
                await asyncio.gather(module.run_schema_migrations(pool),module.run_schema_migrations(pool))
                assert await conn.fetchval('SELECT count(*) FROM targets') == total
            finally:
                await pool.close()
    asyncio.run(run())


def test_restart_repairs_drifted_finding_badges_on_a_converted_database():
    async def run():
        async with startup_database() as conn:
            api_root = str(Path(__file__).resolve().parents[1] / 'api')
            if api_root not in sys.path:
                sys.path.insert(0, api_root)
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            web = await conn.fetchval("INSERT INTO targets(url) VALUES('https://badge.test') RETURNING id")
            clean = await conn.fetchval("INSERT INTO targets(url) VALUES('https://clean-badge.test') RETURNING id")
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Badge device','badge-device.test') RETURNING id")
            for status in ('active', 'resolved'):
                await conn.execute(
                    "INSERT INTO findings(target_id,fingerprint,title,severity,status) VALUES($1,$2,'Badge','low',$3)",
                    web, 'badge-' + status, status,
                )
            # The legacy baseline that once repaired these never runs again after conversion.
            await conn.execute('UPDATE targets SET active_findings_count=3 WHERE id=$1', web)
            await conn.execute('UPDATE target_device_profiles SET active_findings_count=2 WHERE target_id=$1', device)
            clean_version = await conn.fetchval('SELECT xmin::text FROM targets WHERE id=$1', clean)
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT active_findings_count FROM targets WHERE id=$1', web) == 1
            assert await conn.fetchval('SELECT active_findings_count FROM device_targets WHERE id=$1', device) == 0
            # A consistent badge is not rewritten.
            assert await conn.fetchval('SELECT xmin::text FROM targets WHERE id=$1', clean) == clean_version
    asyncio.run(run())


def test_converted_installation_adds_hunt_coverage_on_restart():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_targets'::regclass") == 'v'
            # Reproduce an already-converted installation from before coverage shipped.
            # This is an isolated disposable database; no retained operator evidence exists.
            await conn.execute('DROP TABLE hunt_coverage_angle_events')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval("SELECT to_regclass('hunt_coverage_angle_events')") is not None
            assert await conn.fetchval("SELECT to_regclass('idx_hunt_coverage_angle_events_run_seq')") is not None
            assert await conn.fetchval("SELECT to_regclass('idx_hunt_coverage_angle_events_fingerprint_seq')") is not None
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT count(*) FROM hunt_coverage_angle_events') == 0
    asyncio.run(run())


def test_converted_installation_adds_the_hunt_credential_use_ledger_on_restart():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            # A fresh install already has the ledger from db/init.sql; startup keeps it intact.
            assert await conn.fetchval("SELECT to_regclass('hunt_credential_uses')") is not None
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # Reproduce an already-converted installation from before the ledger shipped.
            # This is an isolated disposable database; no retained operator evidence exists.
            await conn.execute('DROP TABLE hunt_credential_uses')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval("SELECT to_regclass('hunt_credential_uses')") is not None
            assert await conn.fetchval("SELECT to_regclass('idx_hunt_credential_uses_run')") is not None
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('https://ledger.test') RETURNING id")
            hunt = await conn.fetchval(
                "INSERT INTO hunt_runs(target_kind,target_id) VALUES('web',$1) RETURNING id", target)
            action = await conn.fetchval(
                "INSERT INTO hunt_actions(hunt_run_id,capability_name,status) "
                "VALUES($1,'candidate.verify','running') RETURNING id", hunt)
            await conn.execute(
                "INSERT INTO hunt_credential_uses(hunt_run_id,action_id,profile_id,profile_version,source,slot) "
                "VALUES($1,$2,$3,1,'target_own','primary')", hunt, action, uuid.uuid4())
            # Restarting again is idempotent and keeps the recorded uses.
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT count(*) FROM hunt_credential_uses') == 1
    asyncio.run(run())


def test_converted_installation_adds_the_finding_hunt_verification_ledger_on_restart():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            # A fresh install already has the relation from db/init.sql; startup keeps it intact.
            assert await conn.fetchval("SELECT to_regclass('finding_hunt_verifications')") is not None
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # Reproduce an already-converted installation from before the relation shipped (D21).
            # This is an isolated disposable database; no retained operator evidence exists.
            await conn.execute('DROP TABLE finding_hunt_verifications')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            for index in ('idx_finding_hunt_verifications_run', 'idx_finding_hunt_verifications_finding'):
                assert await conn.fetchval("SELECT to_regclass($1)", index) is not None
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('https://verified.test') RETURNING id")
            hunt = await conn.fetchval(
                "INSERT INTO hunt_runs(target_kind,target_id) VALUES('web',$1) RETURNING id", target)
            action = await conn.fetchval(
                "INSERT INTO hunt_actions(hunt_run_id,capability_name,status) "
                "VALUES($1,'candidate.verify','completed') RETURNING id", hunt)
            finding = await conn.fetchval(
                "INSERT INTO findings(target_id,hunt_run_id,fingerprint,title,severity) "
                "VALUES($1,$2,'verified','Verified','high') RETURNING id", target, hunt)
            await conn.execute(
                "INSERT INTO finding_hunt_verifications(finding_id,hunt_run_id,action_id,role) "
                "VALUES($1,$2,$3,'owner')", finding, hunt, action)
            # Restarting again is idempotent and keeps the recorded verifications.
            await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT count(*) FROM finding_hunt_verifications') == 1
    asyncio.run(run())


def test_restart_upgrades_the_first_release_coverage_ledger_in_place():
    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            # Recreate the ledger exactly as the first release installed it (no event_seq,
            # auto-named status check, timestamp indexes) with one retained event.
            await conn.execute('DROP TABLE hunt_coverage_angle_events')
            await conn.execute((Path(__file__).resolve().parent / 'fixtures' / 'hunt'
                                / 'coverage_ledger_first_release.sql').read_text(encoding='utf-8'))
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('https://ledger.test') RETURNING id")
            hunt = await conn.fetchval(
                "INSERT INTO hunt_runs(target_kind,target_id) VALUES('web',$1) RETURNING id", target)
            await conn.execute(
                "INSERT INTO hunt_coverage_angle_events(hunt_run_id,fingerprint,family,status) "
                "VALUES($1,'kept','authorization','planned')", hunt)
            for _ in range(2):
                await module.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval(
                "SELECT event_seq FROM hunt_coverage_angle_events WHERE fingerprint='kept'") == 1
            names = {row['conname'] for row in await conn.fetch(
                "SELECT conname FROM pg_constraint WHERE conrelid='hunt_coverage_angle_events'::regclass")}
            assert 'hunt_coverage_angle_status_check' in names
            assert 'hunt_coverage_angle_events_status_check' not in names
            assert await conn.fetchval("SELECT to_regclass('idx_hunt_coverage_angle_events_run')") is None
            assert await conn.fetchval("SELECT to_regclass('idx_hunt_coverage_angle_events_run_seq')") is not None
    asyncio.run(run())


def test_restart_mirrors_an_unmirrored_legacy_web_credential_on_a_converted_database(monkeypatch):
    from cryptography.fernet import Fernet
    import secret_store
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY', key)
    monkeypatch.setattr(secret_store, '_loaded', False)
    monkeypatch.setattr(secret_store, '_fernet', None)

    async def run():
        async with startup_database() as conn:
            api_root = str(Path(__file__).resolve().parents[1] / 'api')
            if api_root not in sys.path:
                sys.path.insert(0, api_root)
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            target = await conn.fetchval("INSERT INTO targets(url) VALUES('https://mirror.test') RETURNING id")
            secret = 'enc:fernet:' + Fernet(key.encode()).encrypt(b'Bearer fixture').decode()
            legacy = await conn.fetchval(
                "INSERT INTO target_credential_profiles(target_id,name,auth_kind,secret_value,secret_preview) "
                "VALUES($1,'legacy-primary','authorization_header',$2,'Bearer …fixture') RETURNING id",
                target, secret,
            )
            # The baseline that mirrors legacy rows never runs again after conversion.
            await conn.execute("DELETE FROM app_schema_migrations WHERE name='v2_target_credentials_to_generic_v1'")
            await module.run_schema_migrations(BoundConnectionPool(conn))
            mirrored = await conn.fetchrow(
                "SELECT target_kind,target_id,name,auth_kind FROM credential_profiles WHERE id=$1", legacy,
            )
            assert mirrored is not None
            assert (mirrored['target_kind'], mirrored['target_id'], mirrored['name'], mirrored['auth_kind']) == (
                'web', target, 'legacy-primary', 'authorization_header',
            )
            assert await conn.fetchval(
                "SELECT count(*) FROM app_schema_migrations WHERE name='v2_target_credentials_to_generic_v1'"
            ) == 1
    asyncio.run(run())


def test_startup_rebuilds_hunt_authority_2_8_0_left_after_a_revocation_and_ends_an_unrepairable_hunt():
    """R1 (external release audit, 2026-10-09): 2.8.0 revocation restored whole-policy snapshots.
    The real startup rebuilds each such Hunt from its baseline and live grants, in its own
    transaction, and ends a Hunt it cannot rebuild instead of failing startup. The grant rows
    are written as 2.8.0 stored them (fixture rows, not produced by 2.8.0 code)."""
    import json

    flags = ("active_testing", "allow_state_changing_http", "allow_oob_interactions", "network_discovery",
             "mutation_allowed")
    start = {key: False for key in flags}
    after_a = {**start, "active_testing": True, "allow_state_changing_http": True, "mutation_allowed": True}

    async def legacy_hunt(conn, *, corrupt):
        target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id",
                                     f"https://r1-{uuid.uuid4().hex[:8]}.test")
        policy = {**after_a, "allowed_capabilities": ["http.request", "web.probe"], "approval_receipt_id": None}
        hunt = await conn.fetchval(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,budget_json,
                                     budget_used_json,context_pack,created_by)
               VALUES('web',$1,'r1','active','fast',$2::jsonb,'{}'::jsonb,'{}'::jsonb,
                      '{"allowed_capabilities":["http.request","web.probe","service.snmp.inspect"]}'::jsonb,
                      'fixture') RETURNING id""", target, json.dumps(policy))
        for capability, flag, before, added in (("http.request", "state-changing", start, False),
                                                 ("service.snmp.inspect", "tcp-discovery", after_a, True)):
            subject = json.dumps({"capability": capability, "flag": flag})
            digest = uuid.uuid4().hex * 2
            request = await conn.fetchval(
                """INSERT INTO hunt_permission_requests(hunt_run_id,kind,reason_code,subject_json,subject_digest,
                                                        status,expires_at,decided_at)
                   VALUES($1,'capability.enable','capability_requires_active_testing',$2::jsonb,$3,'granted',
                          NOW()+interval '1 hour',NOW()) RETURNING id""", hunt, subject, digest)
            effect = "[1]" if corrupt and added else json.dumps({
                "policy_before": before, "flag": flag, "capability": capability, "capability_added": added})
            await conn.execute(
                """INSERT INTO hunt_permission_grants(hunt_run_id,request_id,kind,subject_json,subject_digest,scope,
                                                      effect_json,created_by,revoked_at,revoked_by)
                   VALUES($1,$2,'capability.enable',$3::jsonb,$4,'hunt',$5::jsonb,'alice',NOW(),'alice')""",
                hunt, request, subject, digest, effect)
        return hunt

    async def run():
        async with startup_database() as conn:
            module = importlib.import_module('retest_contract')
            await module.run_schema_migrations(BoundConnectionPool(conn))
            bad = await legacy_hunt(conn, corrupt=False)
            broken = await legacy_hunt(conn, corrupt=True)
            await module.run_schema_migrations(BoundConnectionPool(conn))  # a restart on the upgrade
            policy = json.loads(await conn.fetchval("SELECT policy_json FROM hunt_runs WHERE id=$1", bad))
            assert {key: policy[key] for key in flags} == start
            context = json.loads(await conn.fetchval("SELECT context_pack FROM hunt_runs WHERE id=$1", bad))
            assert "service.snmp.inspect" not in context["allowed_capabilities"]
            assert await conn.fetchval(
                "SELECT source FROM hunt_permission_baselines WHERE hunt_run_id=$1", bad) == 'reconstructed'
            row = await conn.fetchrow("SELECT status, stop_reason FROM hunt_runs WHERE id=$1", broken)
            assert (row['status'], row['stop_reason']) == ('cancelled', 'permission_authority_unrepaired')
            assert await conn.fetchval("SELECT COUNT(*) FROM hunt_permission_baselines WHERE hunt_run_id=$1",
                                       broken) == 0
            await module.run_schema_migrations(BoundConnectionPool(conn))  # idempotent
    asyncio.run(run())
