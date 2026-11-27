"""Two overlapping ASM dispatcher ticks dispatch a target once (real PostgreSQL).

ASM_DISPATCH_TEST_DATABASE_URL must address localhost/shakerscan_asm_dispatch_test (the schema is
rebuilt from db/init.sql and the startup migrations). The enqueue is a fixture: no Scan runs and
nothing is contacted (``.invalid`` hosts).

Leadership runs one dispatcher at a time, but a leader whose tick hung past the tick timeout can
still be finishing it when the next leader's first tick starts. Both then read the same target as
due. Before 2.11 both dispatched it; the per-target claim (a compare-and-set on the stamp the
dispatch writes) lets exactly one through.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("ASM_DISPATCH_TEST_DATABASE_URL")
REQUIRED = os.environ.get("ASM_DISPATCH_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_asm_dispatch_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable ASM dispatch PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import api as api_module  # noqa: E402
import asm_dispatch_selection as asm_selection  # noqa: E402


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


def test_a_hung_ticks_late_dispatch_never_repeats_the_next_leaders(monkeypatch):
    monkeypatch.setattr(api_module, "get_redis", lambda: object())
    enqueued: list[str] = []

    async def enqueue_recon(_conn, _redis, target_id, _url, _options):
        enqueued.append(target_id)
        return {"scan_id": str(uuid.uuid4())}

    monkeypatch.setattr(api_module, "_enqueue_asm_recon", enqueue_recon)
    original_counts = asm_selection.load_counts
    hung = asyncio.Event()
    resume = asyncio.Event()
    calls = {"counts": 0}

    async def counts(*args, **kwargs):
        result = await original_counts(*args, **kwargs)
        calls["counts"] += 1
        if calls["counts"] == 1:
            # The first tick has read its targets and their counts, then hangs.
            hung.set()
            await resume.wait()
        return result

    monkeypatch.setattr(asm_selection, "load_counts", counts)

    async def scenario():
        async with asyncpg.create_pool(DSN, min_size=2, max_size=4) as pool:
            async with pool.acquire() as conn:
                target = await conn.fetchval(
                    """INSERT INTO targets (url, root_domain, asm_enabled) VALUES
                       ('https://claim.asm.invalid', 'asm.invalid', true) RETURNING id""")
            monkeypatch.setattr(api_module, "_ASM_DUE", asm_selection.AsmDueSchedule())
            first = asyncio.ensure_future(api_module.run_asm_dispatch(pool))
            await asyncio.wait_for(hung.wait(), 30)
            # Another process takes over and runs its first tick (its own due schedule).
            monkeypatch.setattr(api_module, "_ASM_DUE", asm_selection.AsmDueSchedule())
            await asyncio.wait_for(api_module.run_asm_dispatch(pool), 30)
            assert enqueued == [str(target)]
            resume.set()
            await asyncio.wait_for(first, 30)
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT asm_last_recon_at, metadata_json->'asm_last_decision' AS decision FROM targets WHERE id = $1",
                    target)
            return target, row

    target, row = asyncio.run(scenario())
    assert enqueued == [str(target)], "the hung tick dispatched the target a second time"
    assert row["asm_last_recon_at"] is not None


def test_a_failed_dispatch_gives_its_claim_back(monkeypatch):
    monkeypatch.setattr(api_module, "get_redis", lambda: object())

    async def unreachable(*_args, **_kwargs):
        raise RuntimeError("enqueue refused")

    monkeypatch.setattr(api_module, "_enqueue_asm_recon", unreachable)

    async def scenario():
        async with asyncpg.create_pool(DSN, min_size=1, max_size=3) as pool:
            async with pool.acquire() as conn:
                target = await conn.fetchval(
                    """INSERT INTO targets (url, root_domain, asm_enabled) VALUES
                       ('https://refused.asm.invalid', 'asm.invalid', true) RETURNING id""")
            monkeypatch.setattr(api_module, "_ASM_DUE", asm_selection.AsmDueSchedule())
            await api_module.run_asm_dispatch(pool)
            async with pool.acquire() as conn:
                return await conn.fetchrow(
                    """SELECT asm_last_recon_at, metadata_json->'asm_last_decision'->>'blocked_by' AS blocked
                       FROM targets WHERE id = $1""", target)

    row = asyncio.run(scenario())
    assert row["asm_last_recon_at"] is None  # not reported as reconned
    assert row["blocked"] == "dispatch_failed"  # parked by the failure backoff, as before
