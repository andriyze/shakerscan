"""Real PostgreSQL/process-crash fixture; no scanner or external network execution."""

import asyncio
import multiprocessing
import os
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.public_api_contract import PublicV2IdempotencyMiddleware


async def exchange(pool, endpoint):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b'{"target":"fixture"}', "more_body": False}

    async def send(message):
        sent.append(message)

    await PublicV2IdempotencyMiddleware(endpoint)({
        "type": "http", "method": "POST", "path": "/scans",
        "headers": [(b"idempotency-key", b"crash-fixture-key")],
        "app": SimpleNamespace(state=SimpleNamespace(db_pool=pool)),
    }, receive, send)
    return sent


def accepted_then_process_exit(dsn, schema):
    import asyncpg

    async def run():
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2,
                                        server_settings={"search_path": schema + ",public"})

        async def endpoint(scope, receive, send):
            async with pool.acquire() as conn:
                # Synthetic durable side effect, not a real Scan submission.
                await conn.execute("INSERT INTO accepted_fixture DEFAULT VALUES")
            os._exit(17)

        await exchange(pool, endpoint)

    asyncio.run(run())


def test_processing_reservation_survives_process_death_and_age():
    dsn = os.environ.get("SHAKERSCAN_TEST_PUBLIC_RETRY_DSN")
    if not dsn:
        pytest.skip("requires an explicitly selected disposable PostgreSQL instance")
    asyncpg = pytest.importorskip("asyncpg")
    schema = "public_retry_test_" + uuid.uuid4().hex

    async def prepare():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET search_path TO "{schema}",public')
            source = (Path(__file__).resolve().parents[1] / "api/retest_contract.py").read_text()
            ddl = re.search(r"CREATE TABLE IF NOT EXISTS public_api_idempotency \(.*?\n\s*\)",
                            source, re.DOTALL)
            assert ddl is not None
            await conn.execute(ddl[0])
            await conn.execute("CREATE TABLE accepted_fixture(id BIGSERIAL PRIMARY KEY)")
        finally:
            await conn.close()

    async def verify_and_cleanup():
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2,
                                        server_settings={"search_path": schema + ",public"})
        try:
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT COUNT(*) FROM accepted_fixture") == 1
                await conn.execute("UPDATE public_api_idempotency SET updated_at=NOW() "
                                   "- INTERVAL '1 day'")

            async def forbidden_endpoint(scope, receive, send):
                pytest.fail("retry reexecuted an accepted operation after process death")

            result = await exchange(pool, forbidden_endpoint)
            assert result[0]["status"] == 409
            async with pool.acquire() as conn:
                assert await conn.fetchval("SELECT state FROM public_api_idempotency") == "processing"
                assert await conn.fetchval("SELECT COUNT(*) FROM accepted_fixture") == 1
        finally:
            await pool.close()

    async def cleanup():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        finally:
            await conn.close()

    child = None
    try:
        asyncio.run(prepare())
        child = multiprocessing.get_context("spawn").Process(
            target=accepted_then_process_exit, args=(dsn, schema)
        )
        child.start()
        child.join(20)
        assert child.exitcode == 17, "fixture did not exit after durable acceptance"
        asyncio.run(verify_and_cleanup())
    finally:
        if child is not None and child.is_alive():
            child.terminate()
            child.join(5)
        asyncio.run(cleanup())
