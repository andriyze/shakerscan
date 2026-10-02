"""One asset count and history across network scans and distinct web origins."""
import asyncio

from targets.asset_migration import migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_store import list_assets, asset_detail, asset_history
from targets.asset_router import ensure_device_profile, DeviceProfileCreate
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption


def test_inventory_groups_origins_and_profile_addition_reuses_the_asset(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            first = await conn.fetchval("INSERT INTO targets(url) VALUES('https://inventory.test:8443') RETURNING id")
            second = await conn.fetchval("INSERT INTO targets(url) VALUES('http://inventory.test:3000') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            inventory = await list_assets(conn)
            assert inventory['total'] == 1
            assert inventory['targets'][0]['origin_count'] == 2
            asset = inventory['targets'][0]['id']
            assert not inventory['targets'][0]['connected_device']
            async with conn.transaction():
                enabled = await ensure_device_profile(conn,first,DeviceProfileCreate(device_class='media'))
            assert enabled == asset
            assert (await list_assets(conn,connected_only=True))['total'] == 1
            assert await conn.fetchval('SELECT id FROM device_targets WHERE id=$1',asset) == asset
            first_scan = await conn.fetchval("INSERT INTO scans(target_url,target_id,status) VALUES('https://inventory.test:8443',$1,'completed') RETURNING id",first)
            second_scan = await conn.fetchval("INSERT INTO scans(target_url,target_id,status) VALUES('http://inventory.test:3000',$1,'completed') RETURNING id",second)
            device_scan = await conn.fetchval("INSERT INTO scans(target_url,device_target_id,status,run_kind) VALUES('inventory.test',$1,'completed','device_posture') RETURNING id",asset)
            detail = await asset_detail(conn,first)
            assert detail['target']['id'] == asset
            assert {row['id'] for row in detail['origins']} == {first,second}
            assert {row['id'] for row in detail['history']['items']} == {first_scan,second_scan,device_scan}
            history = await asset_history(conn,second,limit=2,offset=0)
            assert history['total'] == 3 and len(history['items']) == 2
            assert len((await asset_history(conn,asset,limit=2,offset=2))['items']) == 1
            assert (await list_assets(conn,search=':3000'))['total'] == 1
            service_choices = await list_assets(conn,include_services=True)
            assert {item['id'] for item in service_choices['targets']} == {asset,first,second}
            assert all(item['asset_id'] == asset for item in service_choices['targets'])
            assert (await list_assets(conn,search='not-present'))['total'] == 0
            await conn.execute("UPDATE targets SET name='One shared name' WHERE id=$1",asset)
            assert await conn.fetchval('SELECT name FROM device_targets WHERE id=$1',asset) == 'One shared name'
    asyncio.run(run())
