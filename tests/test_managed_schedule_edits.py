"""Cadence edits must survive asynchronous receipt settlement; no target traffic."""
import asyncio
import ast
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_runner_calculates_cadence_from_locked_claim_not_enumeration():
    source = ast.parse((ROOT / "api/schedules/managed_runner.py").read_text())
    function = next(n for n in source.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "run_due")
    stamp = datetime.now(timezone.utc)
    stale = {"id": uuid4(), "frequency": "daily", "updated_at": stamp}
    locked = {**stale, "frequency": "weekly", "updated_at": stamp + timedelta(seconds=1)}
    occurrence = {"id": uuid4(), "lease_id": uuid4(), "payload": {}, "new_occurrence": True, "schedule": locked}
    occurrences = SimpleNamespace(initialize=AsyncMock(), fetch_dispatchable=AsyncMock(return_value=[stale]),
                                  claim=AsyncMock(return_value=occurrence), settle=AsyncMock())
    seen = []
    def cadence(schedule):
        seen.append(schedule)
        return stamp + timedelta(days=7)
    namespace = {"datetime": datetime, "timezone": timezone, "occurrences": occurrences,
                 "managed_recovery": SimpleNamespace(reconcile=AsyncMock()),
                 "schedule_ops": SimpleNamespace(schedule_next_run_at=cadence), "scan_payload": lambda _: {}}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<managed runner>", "exec"), namespace)
    dispatcher = SimpleNamespace(origin="https://gateway.test", dispatch=AsyncMock(
        return_value=SimpleNamespace(state="accepted", scan_id=str(uuid4()))))
    assert asyncio.run(namespace["run_due"](None, dispatcher=dispatcher, now=stamp))
    assert seen == [locked]
    assert occurrences.settle.await_args.kwargs["expected_updated_at"] == locked["updated_at"]


@pytest.mark.parametrize("edit", ["none", "cadence", "revision_only", "pause", "delete", "before_retry"])
def test_postgres_settlement_preserves_operator_changes(edit):
    dsn = os.environ.get("SHAKERSCAN_TEST_SCHEDULE_DATABASE_URL")
    if not dsn:
        pytest.skip("Requires an explicitly configured disposable PostgreSQL database")
    import asyncpg
    from schedules import managed_occurrences as store

    async def run():
        schema = "schedule_edits_" + uuid4().hex
        bootstrap = await asyncpg.connect(dsn)
        await bootstrap.execute(f"CREATE SCHEMA {schema}")
        pool = None
        try:
            pool = await asyncpg.create_pool(dsn, server_settings={"search_path": schema})
            now = datetime.now(timezone.utc)
            due, operator_next = now, now + timedelta(days=7)
            schedule_id, scan_id = uuid4(), uuid4()
            async with pool.acquire() as conn:
                await conn.execute("""CREATE TABLE schedules (
                    id UUID PRIMARY KEY, is_active BOOLEAN, next_run_at TIMESTAMPTZ,
                    last_run_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL)""")
                await conn.execute("INSERT INTO schedules VALUES($1,true,$2,NULL,$2)", schedule_id, now)
            await store.initialize(pool)
            claim = await store.claim(pool, schedule_id, "https://gateway.test", {}, now=now)
            assert claim["schedule"]["updated_at"] == now
            async with pool.acquire() as conn:
                if edit in {"cadence", "before_retry"}:
                    await conn.execute("UPDATE schedules SET next_run_at=$1,updated_at=$2 WHERE id=$3",
                                       operator_next, now + timedelta(seconds=1), schedule_id)
                elif edit == "revision_only":
                    await conn.execute("UPDATE schedules SET updated_at=$1 WHERE id=$2", now + timedelta(seconds=1), schedule_id)
                elif edit == "pause":
                    await conn.execute("UPDATE schedules SET is_active=false,next_run_at=NULL,updated_at=$1 WHERE id=$2",
                                       now + timedelta(seconds=1), schedule_id)
                elif edit == "delete":
                    await conn.execute("DELETE FROM schedules WHERE id=$1", schedule_id)
            if edit == "before_retry":
                assert await store.settle(pool, claim["id"], claim["lease_id"], state="retry")
                claim = await store.claim(pool, schedule_id, "https://gateway.test", {}, now=now + timedelta(seconds=2))
            assert await store.settle(pool, claim["id"], claim["lease_id"], state="accepted",
                                      scan_id=scan_id, next_run_at=now + timedelta(days=1),
                                      expected_updated_at=claim["schedule"]["updated_at"])
            async with pool.acquire() as conn:
                receipt = await conn.fetchrow("SELECT state,scan_id FROM managed_schedule_occurrences WHERE id=$1", claim["id"])
                assert receipt["state"] == "accepted" and receipt["scan_id"] == scan_id
                row = await conn.fetchrow("SELECT * FROM schedules WHERE id=$1", schedule_id)
                if edit == "delete":
                    assert row is None
                else:
                    expected = {"none": now + timedelta(days=1), "cadence": operator_next,
                                "before_retry": operator_next, "revision_only": due, "pause": None}[edit]
                    assert row["next_run_at"] == expected
                    assert row["last_run_at"] is not None
                    assert row["is_active"] == (edit != "pause")
            assert not await store.settle(pool, claim["id"], claim["lease_id"], state="accepted",
                                          scan_id=scan_id, next_run_at=now + timedelta(days=30))
        finally:
            if pool is not None:
                await pool.close()
            await bootstrap.execute(f"DROP SCHEMA {schema} CASCADE")
            await bootstrap.close()
    asyncio.run(run())
