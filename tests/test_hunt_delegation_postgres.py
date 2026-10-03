"""Hunt metadata freedom preserves operator opt-outs and exact sharing authority."""
import asyncio
import json
import uuid

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from hunt.asset_actions import execute_asset_action
from targets import asset_router, hunt_authority
from targets.hunt_authority_router import router as hunt_authority_router
from targets.asset_collections import asset_collection_binding
from targets.asset_migration import BoundConnectionPool, migrate_target_assets
from targets.asset_inputs_migration import migrate_asset_inputs
from tests.test_target_asset_inputs_postgres import prepare, encryption
from tests.test_target_asset_migration_postgres import database


async def setup(conn, monkeypatch):
    await prepare(conn)
    async with conn.transaction():
        await migrate_target_assets(conn)
        await migrate_asset_inputs(conn)
    first = await conn.fetchval("INSERT INTO targets(url,discovery_source) VALUES('host://first.test','host') RETURNING id")
    second = await conn.fetchval("INSERT INTO targets(url,discovery_source) VALUES('host://second.test','host') RETURNING id")
    pool = BoundConnectionPool(conn)
    monkeypatch.setattr(asset_router, '_pool_provider', lambda: pool)
    app = FastAPI(); app.include_router(hunt_authority_router)
    return first, second, pool, app


def test_upgrade_rejects_preplanted_authority_and_restart_preserves_operator_delegation(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            fake=json.dumps({'hunt_authority':{'target_url':'host://first.test','metadata_changes':True,'revision':1,
                'credential_profile_ids':[str(uuid.uuid4())], 'collection_ids':[str(uuid.uuid4())],
                'ssh_trust_first_contact':True}})
            target=await conn.fetchval("INSERT INTO device_targets(name,primary_locator,metadata_json) VALUES('Device','first.test',$1) RETURNING id",fake)
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            fresh=await hunt_authority.read_hunt_authority(conn,target)
            assert fresh['metadata_changes'] is True  # Product default, not pre-upgrade consent.
            assert fresh['revision'] == 0 and fresh['recorded_by'] is None
            assert fresh['credential_profile_ids'] == fresh['collection_ids'] == []
            assert fresh['ssh_trust_first_contact'] is False
            await hunt_authority.save_authority(conn,await hunt_authority.authority_row(conn,target),
                {'metadata_changes':True,'revision':1},recorded_by='operator:fixture')
            async with conn.transaction(): await migrate_asset_inputs(conn)
            assert (await hunt_authority.read_hunt_authority(conn,target))['metadata_changes'] is True
    asyncio.run(run())


def test_saved_metadata_delegation_supports_passive_hunt_crud_and_revocation(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            first, second, pool, app = await setup(conn, monkeypatch)
            hunt = {'id':uuid.uuid4(), 'target_id':first, 'target_kind':'network', 'policy_json':{}}
            inputs = {'expected_revision':0,'methodology':'Prioritize services; do not reboot.'}
            result = await execute_asset_action(pool,hunt,'targets.skill.create',inputs)
            assert result['skill']['written_by'] == f"hunt:{hunt['id']}"
            path = f'/targets/{first}/hunt-authority'
            async with AsyncClient(transport=ASGITransport(app),base_url='http://operator') as client:
                assert (await client.put(path,json={'expected_revision':0,'metadata_changes':True})).status_code == 200
                await execute_asset_action(pool,hunt,'targets.skill.update',{**inputs,'expected_revision':1,'methodology':'Updated priorities'})
                saved=json.loads(await conn.fetchval('SELECT metadata_json FROM targets WHERE id=$1',first))
                assert saved['target_skill']['history'][0]['methodology'] == inputs['methodology']
                await execute_asset_action(pool,hunt,'targets.update',{'name':'Renamed'})
                created=await execute_asset_action(pool,hunt,'targets.create',{'locator':'new.test'})
                assert created['testing_authorized'] is False
                existing=await asyncio.wait_for(execute_asset_action(pool,hunt,'targets.create',{'locator':'first.test'}),2)
                assert existing['id'] == str(first)  # Reentrant registration cannot deadlock on another pool connection.
                with pytest.raises(HTTPException,match='outside'):
                    await execute_asset_action(pool,hunt,'targets.update',{'target_id':str(second),'name':'Forbidden'})
                assert (await client.put(path,json={'expected_revision':0,'metadata_changes':True})).status_code == 409
                assert (await client.put(path,json={'expected_revision':1,'metadata_changes':False})).status_code == 200
                with pytest.raises(HTTPException,match='metadata changes'):
                    await execute_asset_action(pool,hunt,'targets.skill.delete',{'expected_revision':2,'operator_confirmed':True})
                assert (await execute_asset_action(pool,hunt,'targets.skill.read',{}))['skill']
                assert (await client.put(path,json={'expected_revision':2,'metadata_changes':True})).status_code == 200
                await conn.execute("UPDATE targets SET url='host://changed.test' WHERE id=$1",first)
                with pytest.raises(HTTPException,match='metadata changes'):
                    await execute_asset_action(pool,hunt,'targets.skill.delete',{'expected_revision':2})
    asyncio.run(run())


def test_collection_share_is_exact_recorded_revocable_and_rechecked_for_worker_visibility(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            first,second,pool,app=await setup(conn,monkeypatch)
            identifier=await conn.fetchval("""INSERT INTO request_collections(target_id,name,format,encrypted_payload,payload_sha256,
                request_count,safe_request_count,potentially_mutating_request_count)
                VALUES($1,'Source','postman','enc:fernet:fixture',$2,1,1,0) RETURNING id""",first,'a'*64)
            collection=dict(await conn.fetchrow('SELECT * FROM request_collections WHERE id=$1',identifier))
            for flag in (False,True):
                with pytest.raises(HTTPException,match='saved operator grant'):
                    await asset_collection_binding(conn,collection,target_kind='network',target_id=second,
                        allowed_origins=['http://second.test:8080'],authorize_cross_asset=flag)
            hunt={'id':uuid.uuid4(),'target_id':second,'target_kind':'network','policy_json':{'active_testing':True}}
            # The Hunt cannot mint a grant by setting its confirmation flag.
            from hunt import asset_actions
            from targets.asset_router import configure_asset_router
            configure_asset_router(lambda: pool)
            monkeypatch.setattr(asset_actions.request_collection_api,'_pool',lambda:pool)
            with pytest.raises(HTTPException,match='saved operator grant'):
                await execute_asset_action(pool,hunt,'collections.bind',{'collection_id':str(identifier),
                    'allowed_origins':['http://second.test:8080'],'operator_confirmed':True})
            path=f'/targets/{second}/hunt-authority'
            async with AsyncClient(transport=ASGITransport(app),base_url='http://operator') as client:
                granted=await client.put(path,json={'expected_revision':0,'collection_ids':[str(identifier)]})
                assert granted.status_code == 200, granted.text
                assert granted.json()['recorded_by'] == 'operator:target-permissions-api'
                bound=await execute_asset_action(pool,hunt,'collections.bind',{'collection_id':str(identifier),'allowed_origins':['http://second.test:8080']})
                from hunt.interaction_router import _hunt_bound_collection
                context={'request_collections':[{'collection_id':str(identifier),'binding_id':bound['binding']['id'],
                    'allowed_origins':['http://second.test:8080'],'payload_sha256':'a'*64}]}
                assert (await _hunt_bound_collection(conn,{**hunt,'device_target_id':None},context,identifier))[0]
                assert await conn.fetchval('SELECT target_collection_visible($1,$2)',identifier,second)
                with pytest.raises(HTTPException,match='exact target host'):
                    await asset_collection_binding(conn,collection,target_kind='network',target_id=second,allowed_origins=['http://other.test'])
                assert (await client.put(path,json={'expected_revision':1,'collection_ids':[]})).status_code == 200
                assert not await conn.fetchval('SELECT target_collection_visible($1,$2)',identifier,second)
                with pytest.raises(HTTPException,match='revoked or changed'):
                    await _hunt_bound_collection(conn,{**hunt,'device_target_id':None},context,identifier)
                with pytest.raises(HTTPException,match='saved operator grant'):
                    await execute_asset_action(pool,hunt,'collections.bind',{'collection_id':str(identifier),'allowed_origins':['http://second.test:9090']})
                # Same-asset services require no extra grant or per-port confirmation.
                service=await conn.fetchval("INSERT INTO targets(url) VALUES('http://first.test:8443') RETURNING id")
                assert await asset_collection_binding(conn,collection,target_kind='web',target_id=service,allowed_origins=['http://first.test:8443'])
    asyncio.run(run())


def test_credential_sharing_requires_selected_profile_and_consumes_consent_once(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            first,second,pool,app=await setup(conn,monkeypatch)
            hunt={'id':uuid.uuid4(),'target_id':second,'target_kind':'network','policy_json':{'active_testing':True}}
            profile=uuid.uuid4()
            with pytest.raises(HTTPException,match='not delegated'):
                await execute_asset_action(pool,hunt,'credentials.grant',{'profile_id':str(profile),'operator_confirmed':True})
            from hunt import asset_actions
            class Store:
                async def get_profile(self,*args,**kwargs): return object()
                async def grant_profile(self,*args,**kwargs): return {'profile_id':str(profile),'target_id':str(second)}
            monkeypatch.setattr(asset_actions,'PostgresCredentialProfileStore',Store)
            monkeypatch.setattr(asset_actions.credential_api,'_has_active_capabilities',lambda _:False)
            row=await hunt_authority.authority_row(conn,second,lock=True)
            await hunt_authority.save_authority(conn,row,{'revision':1,'credential_profile_ids':[str(profile)]},recorded_by='operator:fixture')
            assert (await execute_asset_action(pool,hunt,'credentials.grant',{'profile_id':str(profile)}))['grant']
            with pytest.raises(HTTPException,match='not delegated'):
                await execute_asset_action(pool,hunt,'credentials.grant',{'profile_id':str(profile),'operator_confirmed':True})
    asyncio.run(run())


def test_first_contact_pin_is_atomic_and_never_overwrites_a_trusted_key(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            first,_,_,app=await setup(conn,monkeypatch)
            path=f'/targets/{first}/hunt-authority'
            a,b='SHA256:'+'a'*43,'SHA256:'+'b'*43
            with pytest.raises(HTTPException,match='revoked'):
                await hunt_authority.pin_authorized_first_contact(conn,first,2222,a)
            async with AsyncClient(transport=ASGITransport(app),base_url='http://operator') as client:
                response=await client.put(path,json={'expected_revision':0,'ssh_trust_first_contact':True})
                assert response.status_code == 200
                await hunt_authority.pin_authorized_first_contact(conn,first,2222,a)
                assert (await hunt_authority.read_hunt_authority(conn,first))['ssh_host_keys'][0]['fingerprint'] == a
                await hunt_authority.pin_authorized_first_contact(conn,first,2222,a)
                with pytest.raises(HTTPException,match='changed'):
                    await hunt_authority.pin_authorized_first_contact(conn,first,2222,b)
    asyncio.run(run())
