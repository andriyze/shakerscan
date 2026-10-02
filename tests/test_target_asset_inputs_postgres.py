"""A device view must consume and mutate the same encrypted input records as Targets."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import importlib
import hashlib
import json
import uuid

import pytest

from runtime.credential_store import PostgresCredentialProfileStore, CredentialStoreError
from runtime.credentials import build_credential_secret, parse_credential_secret, public_credential_configuration
from runtime.request_collection_store import PostgresRequestCollectionStore
from targets.asset_inputs_migration import migrate_asset_inputs
from targets.asset_migration import migrate_target_assets
from tests.test_target_asset_migration_postgres import database


def encryption(monkeypatch):
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('AI_CREDENTIAL_ENC_KEY', key)
    stores = []
    for name in ('api.secret_store', 'secret_store'):
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        monkeypatch.setattr(module, '_loaded', False)
        monkeypatch.setattr(module, '_fernet', None)
        stores.append(module)
    return stores[0]


async def prepare(conn):
    await PostgresCredentialProfileStore().ensure_schema(conn)
    await PostgresRequestCollectionStore().ensure_schema(conn)
    # Use the real baseline authority DDL, not a reduced mock schema.
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'api/retest_contract.py').read_text()
    constants = [node.value for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    for table in ('scope_receipts', 'approval_receipts'):
        ddl = [sql for sql in constants if f'CREATE TABLE IF NOT EXISTS {table} (' in sql]
        assert len(ddl) == 1, f'Baseline schema for {table} changed'
        await conn.execute(ddl[0])


def test_device_input_migration_keeps_ids_and_one_ciphertext_source(monkeypatch):
    secret_store = encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Fixture','inputs.example.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://inputs.example.test:8443') RETURNING id")
            credential = await conn.fetchval("""INSERT INTO device_credential_profiles(device_target_id,name,auth_kind,username,secret_value,port)
                VALUES($1,'SSH','ssh_password','fixture-user',$2,2222) RETURNING id""",
                device,secret_store.encrypt_secret(json.dumps({'secret': 'fixture-secret','secondary_secret': None})))
            collection = uuid.uuid4()
            from scanner.scanner_tools.request_collections import validate_request_collection
            payload, summary = validate_request_collection({
                'info': {'name': 'API fixture', 'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},
                'item': [{'name': 'status', 'request': {'method': 'GET', 'url': 'https://inputs.example.test:8443/status'}}],
            })
            encoded_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))
            ciphertext = secret_store.encrypt_secret(encoded_payload)
            digest = hashlib.sha256(encoded_payload.encode()).hexdigest()
            await conn.execute("""INSERT INTO device_request_collections(id,device_target_id,name,format,document_sha256,encrypted_payload,summary_json)
                VALUES($1,$2,'API fixture',$3,$4,$5,$6)""",collection,device,summary['format'],digest,ciphertext,json.dumps(summary))
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_credential_profiles'::regclass") == 'v'
            assert await conn.fetchval("SELECT relkind::text FROM pg_class WHERE oid='device_request_collections'::regclass") == 'v'
            assert await conn.fetchval('SELECT count(*) FROM credential_profiles WHERE id=$1',credential) == 1
            assert await conn.fetchval('SELECT encrypted_payload FROM request_collections WHERE id=$1',collection) == ciphertext
            assert await conn.fetchval('SELECT count(*) FROM request_collection_requests WHERE collection_id=$1',collection) == 1
            # The web service and device are views of one canonical asset.
            assert await conn.fetchval('SELECT target_collection_visible($1,$2)',collection,origin) is True
            unrelated = await conn.fetchval("INSERT INTO targets(url) VALUES('https://unrelated.example.test') RETURNING id")
            assert await conn.fetchval('SELECT target_collection_visible($1,$2)',collection,unrelated) is False
            assert await conn.fetchval('SELECT port FROM device_credential_profiles WHERE id=$1 AND device_target_id=$2',credential,device) == 2222
            store = PostgresCredentialProfileStore()
            with pytest.raises(CredentialStoreError):
                await store.load_for_worker(conn,profile_id=credential,target_kind='network',target_id=origin,capability='device.ssh.propose')
            await store.grant_profile(conn,profile_id=credential,target_kind='network',target_id=origin,
                                      granted_by='fixture operator',now=datetime.now(timezone.utc))
            resolved = await store.load_for_worker(conn,profile_id=credential,target_kind='network',target_id=origin,capability='device.ssh.propose')
            material = parse_credential_secret(resolved.metadata.auth_kind,secret_store.decrypt_secret(resolved.encrypted_secret))
            assert material['secret'] == 'fixture-secret'
            assert material['username'] == 'fixture-user'
            assert resolved.metadata.granted_target_id == str(origin)
            assert resolved.metadata.service_port == 2222
            replacement = build_credential_secret('ssh_password',secret='replacement-secret',username='fixture-user')
            async with conn.transaction():
                updated = await store.rotate_profile(conn,profile_id=credential,target_kind='device',target_id=device,
                    expected_record_version=resolved.metadata.record_version,encrypted_secret=secret_store.encrypt_secret(replacement),
                    encrypted_metadata=secret_store.encrypt_secret('{}'),configuration=public_credential_configuration(json.loads(replacement)),
                    expires_at=None,created_by='test',now=datetime.now(timezone.utc))
            view = await conn.fetchrow('SELECT * FROM device_credential_profiles WHERE id=$1 AND device_target_id=$2',credential,device)
            assert view['current_version'] == updated.current_version
            assert parse_credential_secret('ssh_password',secret_store.decrypt_secret(view['secret_value']))['secret'] == 'replacement-secret'
            async with conn.transaction():
                await store.deactivate_profile(conn,profile_id=credential,target_kind='device',target_id=device,now=datetime.now(timezone.utc))
            assert await conn.fetchval('SELECT is_active FROM device_credential_profiles WHERE id=$1 AND device_target_id=$2',credential,device) is False
            async with conn.transaction():
                await migrate_asset_inputs(conn)
            assert await conn.fetchval('SELECT count(*) FROM credential_profile_versions WHERE profile_id=$1',credential) == 2
    asyncio.run(run())


def test_exact_grants_do_not_inherit_or_override_revocation(monkeypatch):
    secret_store = encryption(monkeypatch)
    async def run():
        async with database() as conn:
            await prepare(conn)
            device = await conn.fetchval("INSERT INTO device_targets(name,primary_locator) VALUES('Shared','shared.example.test') RETURNING id")
            origin = await conn.fetchval("INSERT INTO targets(url) VALUES('https://shared.example.test:8443') RETURNING id")
            other = await conn.fetchval("INSERT INTO targets(url) VALUES('https://other.example.test') RETURNING id")
            async with conn.transaction():
                await migrate_target_assets(conn)
                await migrate_asset_inputs(conn)
            encoded = build_credential_secret('bearer_token',secret='only-a-fixture')
            store = PostgresCredentialProfileStore()
            async with conn.transaction():
                profile = await store.create_profile(conn,target_kind='device',target_id=device,name='Shared token',auth_kind='bearer_token',
                    principal_slot='primary',principal_label=None,configuration=public_credential_configuration(json.loads(encoded)),
                    encrypted_secret=secret_store.encrypt_secret(encoded),encrypted_metadata=secret_store.encrypt_secret('{}'),
                    expires_at=None,allowed_capabilities=['http.request'],now=datetime.now(timezone.utc))
            assert not await store.has_active_grant(conn,profile_id=profile.profile_id,target_kind='web',target_id=origin)
            assert await conn.fetchval('SELECT count(*) FROM target_credential_grant($1,$2)',uuid.UUID(profile.profile_id),origin) == 0
            assert not await store.has_active_grant(conn,profile_id=profile.profile_id,target_kind='web',target_id=other)
            with pytest.raises(CredentialStoreError):
                await store.load_for_worker(conn,profile_id=profile.profile_id,target_kind='web',target_id=other,capability='http.request')
            await store.grant_profile(conn,profile_id=profile.profile_id,target_kind='web',target_id=origin,
                                      granted_by='fixture operator',now=datetime.now(timezone.utc))
            assert await store.has_active_grant(conn,profile_id=profile.profile_id,target_kind='web',target_id=origin)
            await store.revoke_grant(conn,profile_id=profile.profile_id,target_id=origin,now=datetime.now(timezone.utc))
            assert not await store.has_active_grant(conn,profile_id=profile.profile_id,target_kind='web',target_id=origin)
            assert await store.list_profiles(conn,target_kind='web',target_id=origin) == []
            with pytest.raises(CredentialStoreError):
                await store.load_for_worker(conn,profile_id=profile.profile_id,target_kind='web',target_id=origin,capability='http.request')
    asyncio.run(run())
