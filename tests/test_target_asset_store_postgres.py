"""One asset count and history across network scans and distinct web origins."""
import asyncio

from targets.asset_migration import migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_store import list_assets, asset_detail, asset_history
from targets.asset_router import ensure_device_profile, DeviceProfileCreate
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption


def test_web_and_network_filters_apply_before_complete_group_pagination(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            ids={}
            for host in ['example.test','api.example.test','tv.example.test','192.0.2.8','2001:db8::8','router.local']:
                from targets.asset_migration import host_url
                ids[host]=await conn.fetchval("INSERT INTO targets(url,discovery_source) VALUES($1,'host') RETURNING id",host_url(host))
            await conn.execute("INSERT INTO targets(url) VALUES('http://192.0.2.8:8080')")
            await ensure_device_profile(conn,ids['tv.example.test'],DeviceProfileCreate(device_class='media'))
            web=await list_assets(conn,asset_type='web',group_by='domain')
            network=await list_assets(conn,asset_type='network',group_by='domain')
            assert {row['locator'] for row in web['targets']} == {'example.test','api.example.test','tv.example.test','192.0.2.8'}
            assert {row['locator'] for row in network['targets']} == {'tv.example.test','192.0.2.8','2001:db8::8','router.local'}
            pages=[await list_assets(conn,asset_type='web',group_by='domain',limit=1,offset=i) for i in range(web['total_groups'])]
            assert sum(len(page['targets']) for page in pages)==web['total']
            assert any(len(page['targets'])==3 for page in pages)
            assert (await list_assets(conn,asset_type='network',search='tv.example'))['total']==1
            await conn.execute('UPDATE targets SET is_active=false WHERE id=$1',ids['192.0.2.8'])
            assert (await list_assets(conn,asset_type='network'))['total']==3
            assert (await list_assets(conn,asset_type='network',include_inactive=True))['total']==4
    asyncio.run(run())


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


def test_inventory_filters_counts_and_sorts_before_paging(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            from targets.asset_migration import host_url
            import target_authorization
            ids = {}
            for host, environment in [('alpha.test','production'),('beta.test','production'),('gamma.test','lab')]:
                ids[host] = await conn.fetchval("""INSERT INTO targets(url,name,discovery_source,metadata_json)
                    VALUES($1,$2,'host',jsonb_build_object('environment',$3::text)) RETURNING id""",
                    host_url(host), host, environment)
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://alpha.test:8443') RETURNING id")
            await target_authorization.authorize_target(conn, ids['alpha.test'], approved_by='operator')
            await conn.execute("""INSERT INTO findings(target_id,fingerprint,title,severity,status)
                VALUES($1,'fp-critical','Critical issue','critical','active'),($1,'fp-low','Low issue','low','active')""",
                ids['beta.test'])
            await conn.execute("UPDATE targets SET last_scanned_at=NOW(),last_grade='B' WHERE id=$1", origin)
            await conn.execute("INSERT INTO scans(target_url,target_id,status) VALUES('https://gamma.test',$1,'running')", ids['gamma.test'])

            result = await list_assets(conn, group_by='domain', include_facets=True)
            rows = {row['locator']: row for row in result['targets']}
            assert rows['alpha.test']['authorized'] is True and rows['beta.test']['authorized'] is False
            # A linked application origin inherits the host's standing authorization.
            assert await conn.fetchval('SELECT target_effective_authorization_target($1)', origin) == ids['alpha.test']
            assert [item['url'] for item in rows['alpha.test']['origins']] == ['https://alpha.test:8443']
            assert rows['alpha.test']['origins'][0]['last_grade'] == 'B'
            assert rows['alpha.test']['last_scanned_at'] is not None and rows['beta.test']['last_scanned_at'] is None
            assert rows['beta.test']['severity_counts'] == {'critical': 1, 'low': 1}
            assert rows['gamma.test']['scanning'] is True and rows['alpha.test']['scanning'] is False
            assert rows['gamma.test']['environment'] == 'lab'
            facets = result['facets']
            assert facets['total'] == 3
            assert facets['authorization'] == {'authorized': 1, 'unauthorized': 2}
            assert facets['findings'] == {'any': 1, 'critical_high': 1, 'none': 2}
            assert facets['activity'] == {'scanned': 1, 'never': 1, 'scanning': 1}
            assert facets['environment'] == {'production': 2, 'lab': 1}

            def locators(page):
                return [row['locator'] for row in page['targets']]
            assert locators(await list_assets(conn, authorization='authorized')) == ['alpha.test']
            assert locators(await list_assets(conn, authorization='unauthorized')) == ['beta.test', 'gamma.test']
            assert locators(await list_assets(conn, findings='critical_high')) == ['beta.test']
            assert locators(await list_assets(conn, findings='none')) == ['alpha.test', 'gamma.test']
            assert locators(await list_assets(conn, activity='never')) == ['beta.test']
            assert locators(await list_assets(conn, activity='scanning')) == ['gamma.test']
            assert locators(await list_assets(conn, environment='LAB')) == ['gamma.test']
            assert locators(await list_assets(conn, sort='risk')) == ['beta.test', 'alpha.test', 'gamma.test']
            assert locators(await list_assets(conn, sort='recent'))[0] == 'alpha.test'
            # Facets describe the search scope, independent of the other filters.
            filtered = await list_assets(conn, authorization='authorized', include_facets=True)
            assert filtered['total'] == 1 and filtered['facets']['total'] == 3
            assert (await list_assets(conn, search='beta', include_facets=True))['facets']['total'] == 1
            # Revoking the host removes the authorized state the page shows.
            await target_authorization.revoke_target_authorization(conn, ids['alpha.test'], revoked_by='operator', reason='test')
            assert locators(await list_assets(conn, authorization='authorized')) == []
    asyncio.run(run())


def test_alphabetical_groups_follow_the_domain_not_member_names(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            from targets.asset_migration import host_url
            for locator, name in [('zeta.test', 'Alpha storefront'), ('alpha.test', 'Zulu portal'), ('mid.test', None)]:
                await conn.execute("INSERT INTO targets(url,name,discovery_source) VALUES($1,$2,'host')", host_url(locator), name or locator)
            result = await list_assets(conn, group_by='domain')
            assert [group['root_domain'] for group in result['groups']] == ['alpha.test', 'mid.test', 'zeta.test']
    asyncio.run(run())
