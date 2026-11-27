"""Without a target, the collection list is a searchable library naming each owner."""
import asyncio
import json

import request_collection_api
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import prepare, encryption


async def collection(conn, owner, name, fmt='postman_v2.1'):
    return await conn.fetchval("""INSERT INTO request_collections(target_id,name,format,encrypted_payload,
        payload_sha256,request_count,safe_request_count,potentially_mutating_request_count,metadata_json)
        VALUES($1,$2,$3,'gAAAA-fixture',$4,3,2,1,'{}') RETURNING id""", owner, name, fmt, (name * 64)[:64])


def test_library_lists_every_collection_with_its_owner_and_searches_owner_and_name(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            shop = await conn.fetchval("INSERT INTO targets(url,name) VALUES('https://shop.example.test','Storefront') RETURNING id")
            api = await conn.fetchval("INSERT INTO targets(url,name) VALUES('https://api.example.test','Partner API') RETURNING id")
            checkout = await collection(conn, shop, 'Checkout flow')
            orders = await collection(conn, api, 'Orders API', 'openapi')
            retired = await collection(conn, api, 'Retired calls')
            await conn.execute('UPDATE request_collections SET is_active=false WHERE id=$1', retired)
            await conn.execute("""INSERT INTO request_collection_bindings(collection_id,target_kind,target_id,allowed_origins)
                VALUES($1,'web',$2,$3)""", orders, api, json.dumps(['https://api.example.test']))
            monkeypatch.setattr(request_collection_api, '_pool_provider', lambda: BoundConnectionPool(conn))

            library = await request_collection_api.list_request_collections(target_id=None, search='', limit=100, offset=0)
            rows = {item['name']: item for item in library['collections']}
            assert set(rows) == {'Checkout flow', 'Orders API'} and library['total'] == 2
            assert rows['Orders API']['owner_name'] == 'Partner API'
            assert rows['Orders API']['owner_locator'] == 'api.example.test'
            assert rows['Orders API']['binding_count'] == 1 and rows['Checkout flow']['binding_count'] == 0
            assert 'encrypted_payload' not in rows['Orders API'] and 'total_count' not in rows['Orders API']

            async def names(search):
                result = await request_collection_api.list_request_collections(target_id=None, search=search, limit=100, offset=0)
                return sorted(item['name'] for item in result['collections'])
            assert await names('partner') == ['Orders API']          # owner name
            assert await names('shop.example') == ['Checkout flow']  # owner URL
            assert await names('openapi') == ['Orders API']          # format
            assert await names('checkout') == ['Checkout flow']      # collection name
            assert await names('nothing-matches') == []

            scoped = await request_collection_api.list_request_collections(target_id=str(shop), search='', limit=100, offset=0)
            assert [item['id'] for item in scoped['collections']] == [str(checkout)]
            assert (await request_collection_api.list_request_collections(target_id=str(shop), search='orders', limit=100, offset=0))['collections'] == []
    asyncio.run(run())
