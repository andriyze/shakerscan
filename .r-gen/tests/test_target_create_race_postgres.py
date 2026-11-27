"""Concurrent creates of one target on real PostgreSQL answer with that one target, never 409.

TARGET_CREATE_TEST_DATABASE_URL must address localhost/shakerscan_target_create_test (the schema is
rebuilt from db/init.sql and the startup migrations). Hosts are under the reserved ``.invalid``
domain and name resolution is a fixture: nothing is contacted.

The upsert arbitrates on ``canonical_key`` only. ``targets.url`` is UNIQUE as well, and two inserts
of one URL whose conflict checks both ran before either row existed used to fail the second with a
unique violation on ``url``: POST /targets answered 409 "Target already exists" (seen on the lab
branch lane) and a Scan submission a 500, although the target existed.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import types

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("TARGET_CREATE_TEST_DATABASE_URL")
REQUIRED = os.environ.get("TARGET_CREATE_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_target_create_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable target-create PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

ROUNDS = 40
CONCURRENCY = 8


@pytest.fixture(scope="module", autouse=True)
def schema():
    require_disposable_database(DSN or "", DATABASE)

    async def initialize():
        from retest_contract import run_schema_migrations
        async with asyncpg.create_pool(DSN, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                await conn.execute((ROOT / "db/init.sql").read_text())
            await run_schema_migrations(pool)
    asyncio.run(initialize())


def _router(monkeypatch, pool):
    import target_resolution
    from targets import router

    async def no_twin(*_args, **_kwargs):
        return None  # the host "resolves": no www/apex swap, and no lookup is made

    monkeypatch.setattr(target_resolution, "prefer_resolving_twin", no_twin)
    monkeypatch.setattr(router, "_pool_provider", lambda: pool)
    monkeypatch.setitem(router._deps, "load_effective_automation_settings", lambda: {})
    monkeypatch.setitem(router._deps, "safe_default_asm_config", lambda value: {})
    return router


def test_concurrent_creates_of_one_target_all_answer_with_that_target(monkeypatch):
    async def scenario():
        async with asyncpg.create_pool(DSN, min_size=CONCURRENCY, max_size=CONCURRENCY) as pool:
            router = _router(monkeypatch, pool)
            outcomes = []
            for round_number in range(ROUNDS):
                url = f"https://race{round_number}.create.invalid"
                request = types.SimpleNamespace(url=url, name=None, scan_options={})
                results = await asyncio.gather(
                    *(router.create_target(request) for _ in range(CONCURRENCY)), return_exceptions=True)
                outcomes.append((url, results))
            async with pool.acquire() as conn:
                stored = {row["url"]: row["n"] for row in await conn.fetch(
                    "SELECT url, count(*) AS n FROM targets WHERE url LIKE '%.create.invalid' GROUP BY url")}
            return outcomes, stored

    outcomes, stored = asyncio.run(scenario())
    for url, results in outcomes:
        failures = [result for result in results if isinstance(result, BaseException)]
        assert not failures, (url, [getattr(f, "detail", repr(f)) for f in failures])
        assert len({result["id"] for result in results}) == 1, url
        statuses = sorted(result["status"] for result in results)
        assert statuses == ["already_exists"] * (CONCURRENCY - 1) + ["created"], (url, statuses)
        assert stored[url] == 1


def test_a_competing_insert_is_retried_into_the_conflict_path(monkeypatch):
    """Deterministic: the first attempt meets a url violation (as a concurrent insert produces); the
    retry, in a fresh savepoint of the caller's transaction, finds the committed row."""
    from targets import insert_race

    async def scenario():
        async with asyncpg.create_pool(DSN, min_size=2, max_size=2) as pool:
            async with pool.acquire() as conn:
                await conn.execute("INSERT INTO targets (url) VALUES ('https://first.create.invalid')")
                calls = []

                class Racing:
                    """The first statement raises what the url index raises; the rest run."""

                    def transaction(self):
                        return conn.transaction()

                    async def fetchrow(self, query, *args):
                        calls.append(query)
                        if len(calls) == 1:
                            raise asyncpg.UniqueViolationError("duplicate key value violates "
                                                               "unique constraint \"targets_url_key\"")
                        return await conn.fetchrow(query, *args)

                async with conn.transaction():
                    row = await insert_race.fetch_target_upsert(Racing(), """
                        INSERT INTO targets (url) VALUES ($1)
                        ON CONFLICT (canonical_key) DO UPDATE SET url = targets.url
                        RETURNING id, (xmax = 0) AS created""", "https://first.create.invalid")
                    # The caller's transaction is still usable after the failed savepoint.
                    assert await conn.fetchval("SELECT 1") == 1
                return row, len(calls)

    row, attempts = asyncio.run(scenario())
    assert row["created"] is False and attempts == 2


def test_a_violation_that_persists_still_fails():
    from targets import insert_race

    class Always:
        def transaction(self):
            class Savepoint:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_exc):
                    return False
            return Savepoint()

        async def fetchval(self, *_args):
            raise asyncpg.UniqueViolationError("still there")

    with pytest.raises(asyncpg.UniqueViolationError):
        asyncio.run(insert_race.fetch_target_upsert(Always(), "INSERT", method="fetchval"))
