"""Per-class statement timeouts on real PostgreSQL through an asyncpg pool.

Only REQUEST_GUARDS_TEST_DATABASE_URL on localhost/shakerscan_request_guards_test is permitted.
No tables are created; the tests only read session settings and sleep.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("REQUEST_GUARDS_TEST_DATABASE_URL")
REQUIRED = os.environ.get("REQUEST_GUARDS_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable request-guards PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402

import request_guards as rg  # noqa: E402


def _dsn() -> str:
    return require_disposable_database(DSN, "shakerscan_request_guards_test")


async def _pool(default_ms: int):
    return await asyncpg.create_pool(
        _dsn(), min_size=1, max_size=1, **rg.statement_timeout_pool_options(default_ms),
    )


def test_an_init_set_is_lost_after_the_first_release_and_the_session_default_is_not():
    """The regression: asyncpg's release reset (RESET ALL) undid an ``init`` SET."""
    async def run():
        async def init(connection):
            await connection.execute("SET statement_timeout = 1234")

        legacy = await asyncpg.create_pool(_dsn(), min_size=1, max_size=1, init=init)
        try:
            seen_legacy = []
            for _ in range(3):
                async with legacy.acquire() as conn:
                    seen_legacy.append(await conn.fetchval("SHOW statement_timeout"))
        finally:
            await legacy.close()
        pool = await _pool(1234)
        try:
            seen = []
            for _ in range(3):
                async with pool.acquire() as conn:
                    seen.append(await conn.fetchval("SHOW statement_timeout"))
                    await conn.execute("SET statement_timeout = 99")  # a handler's own SET
        finally:
            await pool.close()
        return seen_legacy, seen

    seen_legacy, seen = asyncio.run(run())
    assert seen_legacy == ["1234ms", "0", "0"]
    assert seen == ["1234ms"] * 3


def test_request_classes_narrow_and_widen_the_timeout_and_it_reverts_on_release():
    async def run():
        pool = await _pool(30_000)
        try:
            with rg.statement_timeout(150):
                async with pool.acquire() as conn:
                    narrowed = await conn.fetchval("SHOW statement_timeout")
                    with pytest.raises(asyncpg.exceptions.QueryCanceledError):
                        await conn.execute("SELECT pg_sleep(1)")
            with rg.unbounded_statements():
                unbounded = await pool.fetchval("SHOW statement_timeout")
            background = await pool.fetchval("SHOW statement_timeout")
        finally:
            await pool.close()
        return narrowed, unbounded, background

    assert asyncio.run(run()) == ("150ms", "0", "30s")


def test_a_slow_interactive_read_answers_504_and_a_write_keeps_the_longer_default():
    settings = rg.GuardSettings(default_timeout_ms=30_000, interactive_timeout_ms=200)

    async def run():
        pool = await _pool(settings.default_timeout_ms)
        app = FastAPI()

        @app.api_route("/slow", methods=["GET", "POST"])
        async def slow():
            await pool.execute("SELECT pg_sleep(0.6)")
            return {"ok": True}

        @app.get("/fast")
        async def fast():
            return {"timeout": await pool.fetchval("SHOW statement_timeout")}

        rg.configure_request_guards(app, settings)
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://api") as client:
                read = await client.get("/slow")
                write = await client.post("/slow")
                fast = await client.get("/fast")
                after = await pool.fetchval("SHOW statement_timeout")
        finally:
            await pool.close()
        return read, write, fast, after

    read, write, fast, after = asyncio.run(run())
    assert read.status_code == 504
    assert read.json()["detail"]["error"] == "statement_timeout"
    assert write.status_code == 200
    assert fast.json() == {"timeout": "200ms"}
    assert after == "30s"
