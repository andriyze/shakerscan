"""Real PostgreSQL/process-crash fixture; no scanner or external network execution."""

import asyncio
import hashlib
import json
import multiprocessing
import os
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from api.public_api_contract import PublicV2IdempotencyMiddleware
from api.public_retry_receipts import router

try:
    from public_retry_context import bind_scan_acceptance
except ModuleNotFoundError:
    from api.public_retry_context import bind_scan_acceptance

SCAN_ID = "d2fbfe98-b5d7-41f9-83f1-5f1e4b8ba657"


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


def accepted_then_process_exit(dsn, schema, mode):
    import asyncpg

    async def run():
        pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2,
                                        server_settings={"search_path": schema + ",public"})

        async def endpoint(scope, receive, send):
            async with pool.acquire() as conn, conn.transaction():
                # Synthetic durable side effect, not a real Scan submission.
                await conn.execute("INSERT INTO accepted_fixture DEFAULT VALUES")
                await bind_scan_acceptance(conn, SCAN_ID)
            if mode == "crash":
                os._exit(17)
            body = json.dumps({"scan_id": SCAN_ID} if mode == "success"
                              else {"detail": "rejected after recording"}).encode()
            await send({"type": "http.response.start", "status": 200 if mode == "success" else 422,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})

        await exchange(pool, endpoint)
        await pool.close()

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["crash", "success", "rejection_after_recording"])
def test_processing_reservation_survives_process_death_and_age(mode):
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
            assert result[0]["status"] == (200 if mode == "success" else 409)
            app = FastAPI()
            app.include_router(router)
            app.state.db_pool = pool
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://fixture") as client:
                receipt_response = await client.get("/scans/dispatch-receipts/lookup", headers={
                    "Idempotency-Key": "crash-fixture-key",
                    "X-ShakerScan-Request-SHA256": hashlib.sha256(b'{"target":"fixture"}').hexdigest(),
                })
                assert receipt_response.status_code == 200
                assert receipt_response.json()["scan_id"] == SCAN_ID
                assert receipt_response.json()["state"] == "recorded"
            async with pool.acquire() as conn:
                state = await conn.fetchval("SELECT state FROM public_api_idempotency")
                assert state == ("completed" if mode == "success" else "processing")
                receipt = json.loads(await conn.fetchval(
                    "SELECT response_body FROM public_api_idempotency"
                ))
                assert receipt == ({"scan_id": SCAN_ID} if mode == "success" else {
                    "schema": "public-dispatch-acceptance/v1", "kind": "scan",
                    "id": SCAN_ID, "status": "recorded",
                })
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
            target=accepted_then_process_exit, args=(dsn, schema, mode)
        )
        child.start()
        child.join(20)
        assert child.exitcode == (17 if mode == "crash" else 0)
        asyncio.run(verify_and_cleanup())
    finally:
        if child is not None and child.is_alive():
            child.terminate()
            child.join(5)
        asyncio.run(cleanup())
