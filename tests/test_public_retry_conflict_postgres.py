"""A 409 refusal releases the public Idempotency-Key, so the same retry runs again.

``PublicV2IdempotencyMiddleware`` released a key on 4xx refusals except 409, so a 409 (a Hunt
action waiting for a permission, a budget refusal) left the key ``processing`` and every retry
with that key answered "in progress" forever. Real PostgreSQL; the endpoint is a labelled double.
Fails on a462871a.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import uuid

import pytest

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")
ROOT = Path(__file__).resolve().parents[1]


def test_a_409_releases_the_idempotency_key_so_the_same_retry_runs_again():
    import asyncpg

    from api.public_api_contract import PublicV2IdempotencyMiddleware

    schema = "public_retry_409_" + uuid.uuid4().hex

    async def scenario():
        conn = await asyncpg.connect(DSN)
        pool = None
        try:
            await conn.execute(f'CREATE SCHEMA "{schema}"; SET search_path TO "{schema}"')
            source = (ROOT / "api/retest_contract.py").read_text()
            ddl = re.search(r"CREATE TABLE IF NOT EXISTS public_api_idempotency \(.*?\n\s*\)", source, re.S)
            await conn.execute(ddl[0])
            pool = await asyncpg.create_pool(DSN, min_size=1, max_size=2, server_settings={"search_path": schema})
            calls = []

            async def endpoint(scope, receive, send):
                calls.append(1)
                status, body = (409, {"detail": {"code": "permission_required"}}) if len(calls) == 1 else (
                    200, {"hunt_id": "fixture"})
                encoded = json.dumps(body).encode()
                await send({"type": "http.response.start", "status": status,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": encoded})

            async def exchange():
                sent = []

                async def receive():
                    return {"type": "http.request", "body": b'{"goal":"fixture"}', "more_body": False}

                async def send(message):
                    sent.append(message)

                await PublicV2IdempotencyMiddleware(endpoint)({
                    "type": "http", "method": "POST", "path": "/hunts",
                    "headers": [(b"idempotency-key", b"retry-after-409")],
                    "app": SimpleNamespace(state=SimpleNamespace(db_pool=pool)),
                }, receive, send)
                return sent[0]["status"]

            assert await exchange() == 409
            # Before the fix: 409 idempotency_request_in_progress, and the endpoint never ran again.
            assert await exchange() == 200
            assert len(calls) == 2
            assert await exchange() == 200 and len(calls) == 2  # the success is replayed
        finally:
            if pool is not None:
                await pool.close()
            await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await conn.close()

    asyncio.run(scenario())
