"""Real asyncpg + full ASGI stack + real upload route. No Scan/Hunt traffic.

Only COLLECTION_TEST_DATABASE_URL on localhost/shakerscan_collection_retry_test
is permitted. This dedicated database's public schema is RESET at module setup.
The app lifespan is deliberately not started: no schedulers or workers run.
"""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from tests.disposable_postgres import require_disposable_database
from tests.collection_upload_fixtures import collection_upload_fixture

DSN = os.environ.get('COLLECTION_TEST_DATABASE_URL')
REQUIRED = os.environ.get('COLLECTION_POSTGRES_REQUIRED') == '1'
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip('asyncpg')
ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not DSN and not REQUIRED, reason='Requires explicit disposable collection PostgreSQL database')


@pytest.fixture(scope='module', autouse=True)
def initialized():
    dsn = require_disposable_database(DSN or '', 'shakerscan_collection_retry_test')
    async def bootstrap():
        from retest_contract import run_schema_migrations
        async with asyncpg.create_pool(dsn, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                await conn.execute('DROP SCHEMA public CASCADE; CREATE SCHEMA public')
                await conn.execute((ROOT / 'db/init.sql').read_text())
            await run_schema_migrations(pool)
    asyncio.run(bootstrap())


async def counts(pool, target, key):
    async with pool.acquire() as c:
        result = [await c.fetchval('SELECT COUNT(*) FROM request_collections WHERE target_id=$1', target)]
        for table in ('request_collection_requests','request_collection_environments','request_collection_bindings'):
            result.append(await c.fetchval(f'SELECT COUNT(*) FROM {table} r JOIN request_collections c ON c.id=r.collection_id WHERE c.target_id=$1', target))
        result.append(await c.fetchval("SELECT COUNT(*) FROM public_api_idempotency WHERE method='POST' AND path='/request-collections' AND key_sha256=$1", hashlib.sha256(key.encode()).hexdigest()))
        assert await c.fetchval('SELECT COUNT(*) FROM scans WHERE target_id=$1', target) == 0
        return result


def exercise(monkeypatch, scenario):
    async def run():
        from api import api as api_module
        import request_collection_api as collection_module
        import public_retry_atomic as atomic
        async with asyncpg.create_pool(DSN, min_size=1, max_size=5) as pool:
            with monkeypatch.context() as patch:
                patch.setattr(api_module, 'db_pool', pool)
                patch.setattr(api_module.app.state, 'db_pool', pool, raising=False)
                patch.setattr(collection_module, '_pool_provider', lambda: pool)
                secrets = sys.modules[collection_module.encrypt_secret.__module__]
                patch.setenv('AI_CREDENTIAL_ENC_KEY', Fernet.generate_key().decode())
                patch.setattr(secrets, '_loaded', False)
                patch.setattr(secrets, '_fernet', None)
                target, key = uuid4(), 'collection-test:' + uuid4().hex
                origin, payload = collection_upload_fixture(target)
                async with pool.acquire() as c:
                    await c.execute('INSERT INTO targets(id,url,root_domain) VALUES($1,$2,$3)', target,
                                    origin, target.hex + '.collection.example.invalid')
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api_module.app), base_url='http://testserver') as client:
                    await asyncio.wait_for(scenario(pool, api_module.app, atomic, patch, client, target, key, payload), 30)
    asyncio.run(run())


def test_real_upload_replays_all_rows_and_keeps_secrets_encrypted(monkeypatch):
    async def scenario(pool, app, atomic, patch, client, target, key, payload):
        headers = {'Idempotency-Key':key}
        first = await client.post('/request-collections', json=payload, headers=headers)
        assert first.status_code == 200, first.text
        second = await client.post('/request-collections', json=payload, headers=headers)
        assert second.status_code == 200 and second.json() == first.json()
        assert second.headers['idempotency-replayed'] == 'true'
        assert await counts(pool, target, key) == [1,1,1,1,1]
        assert 'fixture-not-a-real-secret' not in first.text
        async with pool.acquire() as c:
            assert (await c.fetchval('SELECT encrypted_payload FROM request_collections WHERE target_id=$1',target)).startswith('enc:fernet:')
            stored_environment = await c.fetchval('SELECT e.encrypted_payload FROM request_collection_environments e JOIN request_collections c ON c.id=e.collection_id WHERE c.target_id=$1', target)
            assert stored_environment.startswith('enc:fernet:') and 'fixture-not-a-real-secret' not in stored_environment
        different = await client.post('/request-collections', json={**payload, 'name':'different'}, headers=headers)
        assert different.status_code == 409
    exercise(monkeypatch, scenario)


@pytest.mark.parametrize('fault', ['reject', 'cancel', 'disconnect'])
def test_real_transaction_rolls_back_rows_and_receipt_before_commit(monkeypatch, fault):
    async def scenario(pool, app, atomic, patch, client, target, key, payload):
        original = atomic.acquire_for_atomic_retry
        entered, release = asyncio.Event(), asyncio.Event()
        @asynccontextmanager
        async def after_effect(pool_arg):
            async with original(pool_arg) as conn:
                yield conn
                # The real handler inserted all rows and released its savepoint;
                # the outer real PostgreSQL transaction has not yet committed.
                entered.set()
                if fault == 'reject': raise HTTPException(422, 'synthetic post-write rejection')
                if fault == 'disconnect': conn.terminate(); return
                await release.wait()
        patch.setattr(atomic, 'acquire_for_atomic_retry', after_effect)
        task = asyncio.create_task(client.post('/request-collections', json=payload, headers={'Idempotency-Key':key}))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            if fault == 'cancel': task.cancel()
            if fault == 'reject':
                result = await asyncio.wait_for(task, 10)
                assert result.status_code == 422
            else:
                with pytest.raises((asyncio.CancelledError, Exception)):
                    await asyncio.wait_for(task, 10)
        finally:
            if not task.done(): task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert await counts(pool, target, key) == [0,0,0,0,0]
        patch.setattr(atomic, 'acquire_for_atomic_retry', original)
        result = await client.post('/request-collections', json=payload, headers={'Idempotency-Key':key})
        assert result.status_code == 200, result.text
        assert await counts(pool, target, key) == [1,1,1,1,1]
    exercise(monkeypatch, scenario)


def test_real_advisory_lock_serializes_concurrent_identical_uploads(monkeypatch):
    async def scenario(pool, app, atomic, patch, client, target, key, payload):
        original = atomic.acquire_for_atomic_retry
        entered, release = asyncio.Event(), asyncio.Event()
        @asynccontextmanager
        async def pause(pool_arg):
            async with original(pool_arg) as conn:
                yield conn
                entered.set()
                await release.wait()
        patch.setattr(atomic, 'acquire_for_atomic_retry', pause)
        first = asyncio.create_task(client.post('/request-collections', json=payload, headers={'Idempotency-Key':key}))
        try:
            await asyncio.wait_for(entered.wait(), 10)
            duplicate = await asyncio.wait_for(client.post('/request-collections', json=payload, headers={'Idempotency-Key':key}), 5)
            assert duplicate.status_code == 409
            assert await counts(pool, target, key) == [0,0,0,0,0]
        finally:
            release.set()
            # Also release/await the first request when a duplicate assertion fails,
            # otherwise a borrowed connection can hang pool teardown.
            result = await asyncio.wait_for(first, 10)
        assert result.status_code == 200
        assert await counts(pool, target, key) == [1,1,1,1,1]
    exercise(monkeypatch, scenario)


def test_lost_response_after_real_commit_replays_without_duplicate_effects(monkeypatch):
    async def scenario(pool, app, atomic, patch, client, target, key, payload):
        async def dropped_app(scope, receive, send):
            async def dropped_send(message):
                if message['type'] == 'http.response.body':
                    raise ConnectionError('synthetic lost response after commit')
                await send(message)
            await app(scope, receive, dropped_send)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=dropped_app), base_url='http://testserver') as broken:
            with pytest.raises(Exception):
                await broken.post('/request-collections', json=payload, headers={'Idempotency-Key':key})
        assert await counts(pool, target, key) == [1,1,1,1,1]
        response = await client.post('/request-collections', json=payload, headers={'Idempotency-Key':key})
        assert response.status_code == 200 and response.headers['idempotency-replayed'] == 'true'
        assert await counts(pool, target, key) == [1,1,1,1,1]
    exercise(monkeypatch, scenario)


def test_unkeyed_upload_and_rejected_input_use_the_same_real_route(monkeypatch):
    async def scenario(pool, app, atomic, patch, client, target, key, payload):
        invalid = await client.post('/request-collections', json={**payload,'extra':'rejected'})
        assert invalid.status_code == 422
        assert await counts(pool, target, key) == [0,0,0,0,0]
        response = await client.post('/request-collections', json=payload)
        assert response.status_code == 200, response.text
        assert await counts(pool, target, key) == [1,1,1,1,0]
    exercise(monkeypatch, scenario)
