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
    asyncio.run(run())
