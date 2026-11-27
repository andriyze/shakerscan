"""Reuse one document on explicit service bindings, never by copying it across views."""
import asyncio
import json

import pytest
from fastapi import HTTPException

from devices.shared_collections import save_device_collection
from targets.asset_collections import asset_collection_binding
from targets.asset_migration import migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_migration_postgres import database
from tests.test_target_asset_inputs_postgres import encryption, prepare


def test_collection_owner_and_exact_service_bindings(monkeypatch):
    secrets = encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','collections.test') RETURNING id")
            first = await conn.fetchval("INSERT INTO targets(url) VALUES('https://collections.test:8443') RETURNING id")
            second = await conn.fetchval("INSERT INTO targets(url) VALUES('http://collections.test:3000') RETURNING id")
            other = await conn.fetchval("INSERT INTO targets(url) VALUES('https://unrelated.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            from scanner.scanner_tools.request_collections import validate_request_collection
            payload, summary = validate_request_collection({'info': {'name': 'Shared API'}, 'item':[
                {'name':'status','request':{'method':'GET','url':'https://collections.test:8443/status'}}]})
            view = await save_device_collection(conn,device,summary=summary,encrypted_payload=secrets.encrypt_secret(json.dumps(payload)))
            collection = dict(await conn.fetchrow('SELECT * FROM request_collections WHERE id=$1',view['id']))
            for target, origin in [(first,'https://collections.test:8443'),(second,'http://collections.test:3000')]:
                origins = await asset_collection_binding(conn,collection,target_kind='web',target_id=target,allowed_origins=[origin])
                await conn.execute("""INSERT INTO request_collection_bindings(collection_id,target_kind,target_id,allowed_origins)
                    VALUES($1,'web',$2,$3)""",collection['id'],target,json.dumps(origins))
                assert await conn.fetchval('SELECT target_collection_visible($1,$2)',collection['id'],target)
            assert await conn.fetchval('SELECT count(*) FROM request_collections') == 1
            assert await conn.fetchval('SELECT count(*) FROM request_collection_bindings WHERE collection_id=$1',collection['id']) == 2
            for target, origin in [(other,'https://unrelated.test'),(first,'http://collections.test:3000'),(device,'https://unrelated.test')]:
                with pytest.raises(HTTPException):
                    await asset_collection_binding(conn,collection,target_kind='web',target_id=target,allowed_origins=[origin])
            await conn.execute('UPDATE request_collection_bindings SET is_active=false WHERE collection_id=$1 AND target_id=$2',collection['id'],first)
            assert not await conn.fetchval('SELECT target_collection_visible($1,$2)',collection['id'],first)
            assert await conn.fetchval('SELECT target_collection_visible($1,$2)',collection['id'],second)
            await conn.execute('UPDATE targets SET is_active=false WHERE id=$1',device)
            assert not await conn.fetchval('SELECT is_active FROM targets WHERE id=$1',first)
            with pytest.raises(HTTPException):
                await asset_collection_binding(conn,collection,target_kind='web',target_id=second,allowed_origins=['http://collections.test:3000'])
    asyncio.run(run())
