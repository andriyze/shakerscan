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


def test_restoring_an_archived_host_restores_exactly_the_services_archived_with_it():
    # Soak N7: archive covered the host and its web app, but Restore (PATCH is_active=true)
    # reactivated only the host, which then showed 0 origins.
    async def run():
        from targets.archive import archive, restore_archived_members
        import retest_contract
        async with startup_database() as conn:
            host = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('TV','restore-report.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://restore-report.test') RETURNING id")
            alone = await conn.fetchval("INSERT INTO targets(url) VALUES('https://restore-report.test:8443') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            for member in (origin, alone):
                assert await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1', member) == host
            # One service was archived on its own before the host was.
            await conn.execute('UPDATE targets SET is_active=false WHERE id=$1', alone)
            await archive(BoundConnectionPool(conn), host)
            assert await conn.fetchval('SELECT count(*) FROM targets WHERE is_active') == 0

            # The UI's Restore button sends PATCH is_active=true for the host.
            from targets import router as targets_router
            previous = targets_router._pool_provider
            targets_router._pool_provider = lambda: BoundConnectionPool(conn)
            try:
                restored = await targets_router.update_target(
                    str(host), targets_router.TargetUpdate(is_active=True))
            finally:
                targets_router._pool_provider = previous
            assert restored['services_restored'] == 1
            active = {row['id'] for row in await conn.fetch('SELECT id FROM targets WHERE is_active')}
            assert active == {host, origin}
            metadata = json.loads(await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1', origin))
            assert 'archived_with' not in metadata

            # An archive made before members were stamped is recognised by its shared timestamp.
            await conn.execute("""UPDATE targets SET is_active=false, updated_at='2026-10-01T00:00:00Z'
                WHERE id=ANY($1::uuid[])""", [host, origin])
            assert await restore_archived_members(conn, host) == 1
            assert await conn.fetchval('SELECT is_active FROM targets WHERE id=$1', origin)
            assert not await conn.fetchval('SELECT is_active FROM targets WHERE id=$1', alone)
    asyncio.run(run())


def test_credential_grant_target_facts_come_from_the_inventory():
    # Soak N6: grants trusted the caller's kind label. The facts the grant check reads must
    # describe the real target on the real schema.
    async def run():
        import credential_api
        import retest_contract
        async with startup_database() as conn:
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('VPS','2.28.1.228') RETURNING id")
            host = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Web host','facts-report.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://facts-report.test') RETURNING id")
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            assert await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1', origin) == host
            facts = {}
            for name, target in (('device', device), ('host', host), ('origin', origin)):
                row = await conn.fetchrow(credential_api._GRANT_TARGET_FACTS_SQL, target)
                assert row is not None, name
                facts[name] = (row['http_origin'], row['serves_http'], row['device'])
            assert facts['origin'] == (True, True, False)
            assert facts['host'][:2] == (False, True)
            assert facts['device'][:2] == (False, False)
            # The SSH-only VPS cannot take a web basic-auth credential under any label.
            for kind in ('device', 'network', 'web'):
                assert credential_api.grant_target_kind_error(
                    declared_kind=kind, auth_kind='basic_auth', http_origin=facts['device'][0],
                    serves_http=facts['device'][1], device=facts['device'][2]) is not None
            assert await conn.fetchrow(credential_api._GRANT_TARGET_FACTS_SQL, uuid.uuid4()) is None
    asyncio.run(run())
