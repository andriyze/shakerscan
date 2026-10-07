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
