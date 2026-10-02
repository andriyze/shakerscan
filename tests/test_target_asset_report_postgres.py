"""Reproduce report failures with persisted legacy state and the actual startup DDL."""
import asyncio
import json
import uuid

import pytest

from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_startup_postgres import startup_database


async def legacy_baseline(conn, monkeypatch):
    import retest_contract
    from targets import asset_migration, asset_inputs_migration
    async def unchanged(_conn):
        pass
    with monkeypatch.context() as patch:
        patch.setattr(asset_migration, 'migrate_target_assets', unchanged)
        patch.setattr(asset_inputs_migration, 'migrate_asset_inputs', unchanged)
        await retest_contract._run_schema_migrations_once(BoundConnectionPool(conn))


def test_existing_and_new_device_candidates_keep_canonical_alias(monkeypatch):
    async def run():
        async with startup_database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','candidate.test') RETURNING id")
            await legacy_baseline(conn,monkeypatch)
            async def candidate(fingerprint):
                return await conn.fetchval("""INSERT INTO investigation_candidates(
                    plane,device_target_id,family,title,claim,fingerprint)
                    VALUES('device',$1,'service','Observation','Unverified',$2) RETURNING id""",device,fingerprint)
            old = await candidate('before')
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            new = await candidate('after')
            for row in (old,new):
                assert await conn.fetchval('SELECT target_id FROM investigation_candidates WHERE id=$1',row) == device
            with pytest.raises(Exception,match='investigation_candidates_target_check'):
                await conn.execute("UPDATE investigation_candidates SET plane='web' WHERE id=$1",new)
    asyncio.run(run())


def test_latest_legacy_collection_replaces_stale_mirror_and_deleted_stays_inactive(monkeypatch):
    async def run():
        async with startup_database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','collections-report.test') RETURNING id")
            ids = [uuid.uuid4() for _ in range(3)]
            for i,ident in enumerate(ids):
                await conn.execute("""INSERT INTO device_request_collections(id,device_target_id,
                    name,format,document_sha256,encrypted_payload,summary_json)
                    VALUES($1,$2,$3,'postman_collection',$4,'ciphertext-before','{}')""",ident,device,f'Collection {i}','a'*64)
            await legacy_baseline(conn,monkeypatch)
            await conn.execute("""UPDATE device_request_collections SET document_sha256=$2,
                encrypted_payload='ciphertext-after',name='Edited',summary_json=$3,updated_at=NOW() WHERE id=$1""",
                ids[0],'b'*64,json.dumps({'requests':[{'request_id':'request-after','method':'GET','safe_method':True,'normalized_path':'/after'}]}))
            await conn.execute('UPDATE device_request_collections SET is_active=false WHERE id=$1',ids[1])
            await conn.execute('DELETE FROM device_request_collections WHERE id=$1',ids[2])
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            updated = await conn.fetchrow('SELECT * FROM request_collections WHERE id=$1',ids[0])
            assert updated['payload_sha256'] == 'b'*64 and updated['encrypted_payload'] == 'ciphertext-after'
            assert updated['name'] == 'Edited'
            assert await conn.fetchval('SELECT request_id FROM request_collection_requests WHERE collection_id=$1',ids[0]) == 'request-after'
            assert not await conn.fetchval('SELECT is_active FROM request_collections WHERE id=$1',ids[1])
            assert not await conn.fetchval('SELECT is_active FROM request_collections WHERE id=$1',ids[2])
    asyncio.run(run())


@pytest.mark.parametrize(('url','key'),[
    ('https://[2001:db8::1]','web:2001:db8::1'),
    ('https://[2001:db8::1]:443','web:2001:db8::1'),
    ('http://[2001:db8::1]:8080','web:2001:db8::1:8080'),
])
def test_ipv6_canonical_keys_match_before_and_after_conversion(monkeypatch,url,key):
    async def run():
        async with startup_database() as conn:
            await legacy_baseline(conn,monkeypatch)
            old = await conn.fetchval('INSERT INTO targets(url) VALUES($1) RETURNING id',url)
            assert await conn.fetchval('SELECT canonical_key FROM targets WHERE id=$1',old) == key
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            await conn.execute('UPDATE targets SET url=$2 WHERE id=$1',old,url)
            assert await conn.fetchval('SELECT canonical_key FROM targets WHERE id=$1',old) == key
            with pytest.raises(Exception,match='unique'):
                await conn.execute('INSERT INTO targets(url) VALUES($1)',url)
    asyncio.run(run())


def test_archive_pauses_every_current_service_schedule(monkeypatch):
    async def run():
        from targets.archive import archive
        import retest_contract
        async with startup_database() as conn:
            host = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','archive-report.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://archive-report.test:8443') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            for target in (host,origin):
                await conn.execute("""INSERT INTO schedules(target_id,frequency,is_active,next_run_at)
                    VALUES($1,'daily',true,NOW())""",target)
            result = await archive(BoundConnectionPool(conn),host)
            assert result['targets_archived'] == 2 and result['schedules_paused'] == 2
            assert await conn.fetchval('SELECT count(*) FROM targets WHERE is_active') == 0
            assert await conn.fetchval('SELECT count(*) FROM schedules WHERE is_active OR next_run_at IS NOT NULL') == 0
    asyncio.run(run())


def test_re_registering_host_adds_hints_without_erasing_known_ports():
    async def run():
        from targets import asset_router
        import retest_contract
        async with startup_database() as conn:
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            previous = asset_router._pool_provider
            asset_router.configure_asset_router(lambda: BoundConnectionPool(conn))
            try:
                first = await asset_router.create_host_target(asset_router.HostTargetCreate(locator='ports-report.test',port_hints=[22,443]))
                second = await asset_router.create_host_target(asset_router.HostTargetCreate(locator='ports-report.test',port_hints=[443,8080]))
                assert first['id'] == second['id']
                metadata = json.loads(await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1',uuid.UUID(first['id'])))
                assert metadata['port_hints'] == [22,443,8080]
                assert not second['port_hints_truncated']
            finally:
                asset_router._pool_provider = previous
    asyncio.run(run())


def test_idn_origin_and_host_have_current_membership_after_upgrade(monkeypatch):
    async def run():
        async with startup_database() as conn:
            await legacy_baseline(conn,monkeypatch)
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://bücher.test:8443') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            assert await conn.fetchval('SELECT url FROM targets WHERE id=$1',origin) == 'https://xn--bcher-kva.test:8443'
            owner = await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1',origin)
            assert await conn.fetchval('SELECT target_asset_access_owner($1)',origin) == owner
    asyncio.run(run())


def test_device_retirement_keeps_historical_other_locator_active(monkeypatch):
    async def run():
        import retest_contract
        async with startup_database() as conn:
            host = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','before-retirement.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://before-retirement.test:8443') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            await conn.execute("UPDATE device_targets SET primary_locator='after-retirement.test',locator_generation=locator_generation+1 WHERE id=$1",host)
            await conn.execute('UPDATE device_targets SET is_active=false WHERE id=$1',host)
            assert await conn.fetchval('SELECT is_active FROM targets WHERE id=$1',origin)
    asyncio.run(run())
