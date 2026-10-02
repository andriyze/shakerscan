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


def test_domain_hierarchy_pages_complete_groups_without_merging_asset_authority(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            hosts = ['example.test','api.example.test','tv.example.test','other.test',
                     '192.0.2.1','192.0.2.2','2001:db8::1','router.local',
                     'example.co.uk','api.example.co.uk','other.co.uk']
            from targets.asset_migration import host_url
            ids = {}
            for host in hosts:
                ids[host] = await conn.fetchval("INSERT INTO targets(url,name,discovery_source) VALUES($1,$2,'host') RETURNING id",host_url(host),host)
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://api.example.test:8443') RETURNING id")
            result = await list_assets(conn,group_by='domain',limit=2)
            assert result['total'] == len(hosts)
            assert result['total_groups'] == 8
            pages = [await list_assets(conn,group_by='domain',limit=2,offset=offset) for offset in range(0,8,2)]
            groups = {group['root_domain']:group['targets'] for page in pages for group in page['groups']}
            assert set(groups) == {'example.test','other.test','192.0.2.1','192.0.2.2','2001:db8::1','router.local','example.co.uk','other.co.uk'}
            assert [asset['locator'] for asset in groups['example.test']] == ['example.test','api.example.test','tv.example.test']
            assert {asset['locator'] for asset in groups['example.co.uk']} == {'example.co.uk','api.example.co.uk'}
            assert sum(len(group) for group in groups.values()) == len(hosts)
            assert next(asset for asset in groups['example.test'] if asset['locator']=='api.example.test')['origin_count'] == 1
            assert await conn.fetchval('SELECT target_asset_access_owner($1)',ids['api.example.test']) == ids['api.example.test']
            assert await conn.fetchval('SELECT asset_owner_id FROM targets WHERE id=$1',origin) == ids['api.example.test']
            assert len((await list_assets(conn,search='api.example.test',group_by='domain'))['groups']) == 1
            await conn.execute('UPDATE targets SET is_active=false WHERE id=$1',ids['tv.example.test'])
            active = await list_assets(conn,group_by='domain')
            retired = await list_assets(conn,group_by='domain',include_inactive=True)
            assert active['total'] == len(hosts)-1 and retired['total'] == len(hosts)
    asyncio.run(run())
