"""Real PostgreSQL acceptance using an explicitly supplied disposable database."""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import asyncpg
import pytest
from schedules import managed_occurrences as store


def test_occurrence_survives_retry_restart_edits_and_stale_lease():
    dsn = os.environ.get("SHAKERSCAN_TEST_SCHEDULE_DATABASE_URL")
    if not dsn:
        pytest.skip("Requires an explicitly configured disposable PostgreSQL database")

    async def run():
        # A unique schema prevents interference with any other fixture run.
        schema = "schedule_test_" + uuid4().hex
        bootstrap = await asyncpg.connect(dsn)
        await bootstrap.execute(f"CREATE SCHEMA {schema}")
        pool = await asyncpg.create_pool(dsn, server_settings={"search_path": schema})
        try:
            async with pool.acquire() as conn:
                await conn.execute("CREATE TABLE targets (id UUID PRIMARY KEY, url TEXT)")
                await conn.execute("""CREATE TABLE schedules (
                    id UUID PRIMARY KEY,is_active BOOLEAN,next_run_at TIMESTAMPTZ,
                    last_run_at TIMESTAMPTZ,target_id UUID,
                    updated_at TIMESTAMPTZ DEFAULT NOW())""")
            await store.initialize(pool)
            now = datetime.now(timezone.utc)
            schedule = uuid4()
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO targets(id,url) VALUES($1,'https://example.test')", schedule
                )
                await conn.execute(
                    "INSERT INTO schedules(id,is_active,next_run_at,target_id) VALUES($1,true,$2,$1)",
                    schedule,
                    now,
                )
            payload = {
                "target": "https://example.test",
                "policy": {"active_testing": False},
            }
            claims = await asyncio.gather(
                *[
                    store.claim(
                        pool, schedule, "https://gateway.test", payload, now=now
                    )
                    for _ in range(2)
                ]
            )
            assert sum(x is not None for x in claims) == 1
            first = next(x for x in claims if x)
            await pool.close()
            pool = await asyncpg.create_pool(
                dsn, server_settings={"search_path": schema}
            )
            later = now + timedelta(minutes=3)
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE schedules SET next_run_at=$1 WHERE id=$2",
                    now + timedelta(days=1), schedule,
                )
            assert [s["id"] for s in await store.fetch_dispatchable(pool, now=later)] == [schedule]
            def invalid_edit():
                raise ValueError("New schedule configuration needs review")
            with pytest.raises(ValueError, match="original gateway"):
                await store.claim(pool, schedule, "https://changed.test", {}, now=later)
            second = await store.claim(
                pool, schedule, "https://gateway.test", invalid_edit, now=later
            )
            assert second["id"] == first["id"]
            assert second["payload"] == payload
            assert second["gateway_origin"] == "https://gateway.test"
            assert not await store.settle(
                pool, first["id"], first["lease_id"], state="retry"
            )
            assert await store.settle(
                pool, second["id"], second["lease_id"], state="retry"
            )
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT last_run_at FROM schedules WHERE id=$1", schedule
                ) is None
            third = await store.claim(
                pool, schedule, "https://gateway.test", {}, now=later
            )
            assert third["id"] == first["id"]
            next_due = now + timedelta(days=1)
            scan = uuid4()
            assert await store.settle(
                pool,
                third["id"],
                third["lease_id"],
                state="accepted",
                next_run_at=next_due,
                scan_id=scan,
            )
            assert (
                await store.claim(
                    pool, schedule, "https://gateway.test", payload, now=later
                )
                is None
            )
            async with pool.acquire() as conn:
                receipt = await conn.fetchrow(
                    "SELECT state,scan_id FROM managed_schedule_occurrences WHERE id=$1",
                    first["id"],
                )
                assert receipt["state"] == "accepted" and receipt["scan_id"] == scan
                last_run = await conn.fetchval(
                    "SELECT last_run_at FROM schedules WHERE id=$1", schedule
                )
                assert last_run is not None
            denied = await store.claim(
                pool, schedule, "https://gateway.test", payload, now=next_due
            )
            assert await store.settle(
                pool, denied["id"], denied["lease_id"], state="denied",
                next_run_at=next_due + timedelta(days=1),
            )
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT last_run_at FROM schedules WHERE id=$1", schedule
                ) == last_run
                # Replaying an obsolete accepted lease cannot stamp another run.
            assert not await store.settle(
                pool, third["id"], third["lease_id"], state="accepted",
                next_run_at=next_due, scan_id=scan,
            )
            async with pool.acquire() as conn:
                assert await conn.fetchval(
                    "SELECT last_run_at FROM schedules WHERE id=$1", schedule
                ) == last_run
                await conn.execute(
                    "UPDATE schedules SET is_active=false WHERE id=$1", schedule
                )
            assert await store.fetch_dispatchable(pool, now=next_due) == []
            assert (
                await store.claim(
                    pool, schedule, "https://gateway.test", payload, now=next_due
                )
                is None
            )
        finally:
            await pool.close()
            await bootstrap.execute(f"DROP SCHEMA {schema} CASCADE")
            await bootstrap.close()

    asyncio.run(run())
