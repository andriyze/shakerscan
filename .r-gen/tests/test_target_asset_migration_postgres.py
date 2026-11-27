"""Exercise the inventory conversion against the actual 2.6 PostgreSQL schema."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import sys
import uuid

import pytest

from targets.asset_migration import host_url, locator_from_url, migrate_target_assets

ROOT = Path(__file__).resolve().parents[1]


def _real_asyncpg():
    """The installed asyncpg, even when another test module stubbed ``sys.modules["asyncpg"]`` at
    import time (``sys.modules.setdefault("asyncpg", SimpleNamespace(Pool=object))``). The stub is
    put back afterwards, so this neither depends on nor changes collection order."""
    loaded = sys.modules.get("asyncpg")
    if loaded is not None and hasattr(loaded, "connect"):
        return loaded
    stub = sys.modules.pop("asyncpg", None)
    try:
        return pytest.importorskip("asyncpg")
    finally:
        if stub is not None:
            sys.modules["asyncpg"] = stub


@asynccontextmanager
async def database():
    asyncpg = _real_asyncpg()
    dsn = os.environ.get("TARGET_ASSET_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TARGET_ASSET_TEST_DATABASE_URL is not configured")
    conn = await asyncpg.connect(dsn)
    schema = "asset_test_" + uuid.uuid4().hex
    try:
        await conn.execute(f'CREATE SCHEMA "{schema}"')
        await conn.execute(f'SET search_path TO "{schema}", public')
        await conn.execute((ROOT / "db/init.sql").read_text())
        yield conn
    finally:
        await conn.execute('SET search_path TO public')
        await conn.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await conn.close()


@pytest.mark.parametrize(("url", "host"), [
    ("https://EXAMPLE.test.:8443/x", "example.test"),
    ("host://[2001:0db8::1]", "2001:db8::1"),
    ("http://192.0.2.1:8000", "192.0.2.1"),
    ("https://name:password@example.test", None),
    ("file:///tmp/example", None),
])
def test_literal_host_normalization(url, host):
    assert locator_from_url(url) == host
    if host:
        assert locator_from_url(host_url(host)) == host


def test_migration_preserves_identity_and_has_one_inventory():
    async def run():
        async with database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','device.example.test') RETURNING id")
            first = await conn.fetchval("INSERT INTO targets(url) VALUES('http://device.example.test:3000') RETURNING id")
            second = await conn.fetchval("INSERT INTO targets(url) VALUES('https://device.example.test:8443') RETURNING id")
            scan = await conn.fetchval("INSERT INTO scans(target_url,device_target_id,run_kind,status) VALUES('device.example.test',$1,'device_posture','completed') RETURNING id", device)
            await conn.execute("INSERT INTO device_interfaces(device_target_id,locator) VALUES($1,'192.0.2.10')", device)
            async with conn.transaction():
                await migrate_target_assets(conn)
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_targets'::regclass") == 'v'
            assert await conn.fetchval("SELECT count(*) FROM target_device_profiles WHERE target_id=$1", device) == 1
            assert await conn.fetchval("SELECT canonical_key FROM targets WHERE id=$1", device) == 'host:device.example.test'
            assert await conn.fetchval("SELECT count(*) FROM targets WHERE asset_owner_id=$1", device) == 2
            assert await conn.fetchval("SELECT target_id FROM scans WHERE id=$1", scan) == device
            assert await conn.fetchval("SELECT target_id FROM device_interfaces WHERE device_target_id=$1", device) == device
            await conn.execute("UPDATE device_targets SET name='Renamed TV' WHERE id=$1", device)
            assert await conn.fetchval("SELECT name FROM targets WHERE id=$1", device) == 'Renamed TV'
            await conn.execute("UPDATE targets SET name='Shared name' WHERE id=$1", device)
            assert await conn.fetchval("SELECT name FROM device_targets WHERE id=$1", device) == 'Shared name'
            new_origin = await conn.fetchval("INSERT INTO targets(url) VALUES('http://device.example.test:9000') RETURNING id")
            assert await conn.fetchval("SELECT asset_owner_id FROM targets WHERE id=$1", new_origin) == device
            assert await conn.fetchval("SELECT target_asset_access_owner($1)", first) == device
            new_scan = await conn.fetchval("INSERT INTO scans(target_url,device_target_id,run_kind) VALUES('device.example.test',$1,'device_posture') RETURNING target_id", device)
            assert new_scan == device
            await conn.execute("UPDATE device_targets SET primary_locator='changed.example.test', locator_generation=locator_generation+1 WHERE id=$1", device)
            assert await conn.fetchval("SELECT id FROM device_targets WHERE primary_locator='changed.example.test'") == device
            assert await conn.fetchval("SELECT locator_generation FROM device_targets WHERE id=$1", device) == 2
            assert await conn.fetchval("SELECT target_asset_access_owner($1)", first) == first
            assert await conn.fetchval("SELECT target_asset_access_owner($1)", second) == second
            total = await conn.fetchval('SELECT count(*) FROM targets')
            async with conn.transaction():
                await migrate_target_assets(conn)
            assert await conn.fetchval('SELECT count(*) FROM targets') == total
    asyncio.run(run())


def test_new_device_reuses_existing_host_and_locator_reuse_does_not_reuse_identity():
    async def run():
        async with database() as conn:
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://new.example.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
            owner = await conn.fetchval("SELECT asset_owner_id FROM targets WHERE id=$1", origin)
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('New profile','new.example.test') RETURNING id")
            assert owner == device
            await conn.execute("UPDATE device_targets SET is_active=false WHERE id=$1", device)
            replacement = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Replacement','new.example.test') RETURNING id")
            assert replacement != device
            assert await conn.fetchval("SELECT is_active FROM targets WHERE id=$1", device) is False
            assert await conn.fetchval("SELECT target_asset_access_owner($1)", origin) == origin
    asyncio.run(run())


def test_transaction_rollback_restores_old_schema_and_data():
    async def run():
        async with database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Original','rollback.example.test') RETURNING id")
            with pytest.raises(RuntimeError, match='forced rollback'):
                async with conn.transaction():
                    await migrate_target_assets(conn)
                    raise RuntimeError('forced rollback')
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_targets'::regclass") == 'r'
            assert await conn.fetchval("SELECT name FROM device_targets WHERE id=$1", device) == 'Original'
            # Check the fixture schema: an already upgraded local instance may
            # also expose the table through the public search-path fallback.
            assert await conn.fetchval("SELECT to_regclass(format('%I.target_device_profiles',current_schema()))") is None
            assert await conn.fetchval("SELECT count(*) FROM targets") == 0
    asyncio.run(run())
