"""Device CRUD and worker resolution operate on the shared input IDs and versions."""
import asyncio
from datetime import datetime, timezone
import json
from types import SimpleNamespace
import uuid

import pytest
from fastapi import HTTPException

from devices.shared_credentials import (
    create_device_profile, rotate_device_profile, deactivate_device_profile,
    resolve_device_credential, worker_material,
)
from devices.shared_collections import save_device_collection, deactivate_device_collection
from runtime.credential_store import CredentialStoreError
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_migration import migrate_target_assets
from tests.test_target_asset_inputs_postgres import encryption, prepare
from tests.test_target_asset_migration_postgres import database


def test_device_credential_crud_uses_one_profile_and_worker_version(monkeypatch):
    encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            device=await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','shared.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            request=SimpleNamespace(auth_kind='web_cookie',name='Session',secret='session=fixture',
                secondary_secret=None,username=None,login_path=None,port=8443,expires_at=None)
            async with conn.transaction():
                profile=await create_device_profile(conn,device,request)
            assert await conn.fetchval('SELECT count(*) FROM credential_profiles') == 1
            assert profile['port'] == 8443
            ref={'profile_id':str(profile['id']),'role':'web','current_version':profile['current_version'],
                 'record_version':profile['record_version'],'capability':'device.http.probe'}
            material=await resolve_device_credential(conn,device,ref)
            assert material['auth_kind']=='web_headers'
            assert material['headers']=={'Cookie':'session=fixture'}
            async with conn.transaction():
                updated=await rotate_device_profile(conn,device,profile['id'],SimpleNamespace(
                    secret='session=replacement',secondary_secret=None,clear_expiry=False,expires_at=None))
            assert updated['current_version']==2
            with pytest.raises(CredentialStoreError,match='changed'):
                await resolve_device_credential(conn,device,ref)
            ref.update(current_version=updated['current_version'],record_version=updated['record_version'])
            assert (await resolve_device_credential(conn,device,ref))['headers']=={'Cookie':'session=replacement'}
            async with conn.transaction():
                await deactivate_device_profile(conn,device,profile['id'])
            with pytest.raises(CredentialStoreError):
                await resolve_device_credential(conn,device,ref)
    asyncio.run(run())


def test_device_collection_crud_reuses_shared_document_id(monkeypatch):
    secret_store=encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            device=await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','collections.test') RETURNING id")
            origin=await conn.fetchval("INSERT INTO targets(url) VALUES('https://collections.test:8443') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            from scanner.scanner_tools.request_collections import validate_request_collection
            payload,summary=validate_request_collection({'info':{'name':'Shared collection'},'item':[
                {'name':'status','request':{'method':'GET','url':'https://collections.test:8443/status'}}]})
            encrypted=secret_store.encrypt_secret(json.dumps(payload))
            row=await save_device_collection(conn,device,summary=summary,encrypted_payload=encrypted)
            assert await conn.fetchval('SELECT count(*) FROM request_collections')==1
            assert not await conn.fetchval('SELECT target_collection_visible($1,$2)',row['id'],origin)
            await conn.execute("""INSERT INTO request_collection_bindings(collection_id,target_kind,target_id,allowed_origins)
                VALUES($1,'web',$2,'["https://collections.test:8443"]')""",row['id'],origin)
            assert await conn.fetchval('SELECT target_collection_visible($1,$2)',row['id'],origin)
            summary['name']='Renamed once'
            same=await save_device_collection(conn,device,collection_id=row['id'],expected_digest=row['document_sha256'],
                summary=summary,encrypted_payload=encrypted)
            assert same['id']==row['id']
            assert await conn.fetchval('SELECT name FROM request_collections WHERE id=$1',row['id'])=='Renamed once'
            inactive=await deactivate_device_collection(conn,device,row['id'])
            assert inactive['is_active'] is False
            assert await conn.fetchval('SELECT count(*) FROM request_collections')==1
    asyncio.run(run())


def test_canonical_http_and_ssh_material_keep_protocol_semantics():
    assert worker_material('bearer_token',{'secret':'fixture'})['headers']=={'Authorization':'Bearer fixture'}
    assert worker_material('api_key_header',{'secret':'fixture','header_name':'X-API-Key'})['headers']=={'X-API-Key':'fixture'}
    assert worker_material('ssh_private_key_with_passphrase',{'secret':'private-fixture','username':'user','secondary_secret':'pass'})=={
        'auth_kind':'ssh_private_key','secret':'private-fixture','username':'user','secondary_secret':'pass'}
