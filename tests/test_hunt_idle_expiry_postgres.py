"""A Hunt nobody drives is ended after a generous idle limit (PostgreSQL).

A Hunt advances only when its driver calls the next capability; when the agent session ended
without finishing or cancelling it, the Hunt stayed ``active`` forever (one engine held 738 live
Hunts, most untouched for weeks). ``expire_idle_hunts`` ends a live Hunt with no activity for the
limit exactly as a cancellation does, with stop reason ``idle_expired``. A Hunt still being driven,
one whose action is reserved or running, one with a recent action, and a finished Hunt are left
alone. The schema is db/init.sql plus every startup migration. Requires
``TARGET_ASSET_TEST_DATABASE_URL``.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "scanner"))

from hunt import idle_expiry  # noqa: E402
from hunt.idle_expiry import IDLE_STOP_REASON, expire_idle_hunts, idle_expiry_hours  # noqa: E402
from tests.test_scan_local_revocation_postgres import scan_database  # noqa: E402

pytest_plugins = ["tests.test_scan_local_revocation_postgres"]


async def _hunt(conn, target, *, status="active", idle_hours=0, completed=False):
    return await conn.fetchval(
        """INSERT INTO hunt_runs (target_kind, target_id, status, created_at, updated_at, completed_at)
           VALUES ('web', $1, $2, NOW() - make_interval(hours => $3 + 1), NOW() - make_interval(hours => $3),
                   CASE WHEN $4 THEN NOW() END)
           RETURNING id""", target, status, idle_hours, completed)


async def _action(conn, hunt, *, status, hours_ago):
    await conn.execute(
        """INSERT INTO hunt_actions (hunt_run_id, capability_name, status, started_at, completed_at)
           VALUES ($1, 'http.request', $2, NOW() - make_interval(hours => $3),
                   CASE WHEN $2 IN ('reserved','running') THEN NULL ELSE NOW() - make_interval(hours => $3) END)""",
        hunt, status, hours_ago)


def test_only_live_hunts_idle_past_the_limit_are_ended(template_database):
    async def run():
        async with scan_database(template_database) as pool:
            async with pool.acquire() as conn:
                target = await conn.fetchval("INSERT INTO targets(url) VALUES('http://10.10.10.150:8081') RETURNING id")
                abandoned = await _hunt(conn, target, idle_hours=100)
                never_started = await _hunt(conn, target, status="created", idle_hours=100)
                exhausted = await _hunt(conn, target, status="budget_exhausted", idle_hours=100)
                recent = await _hunt(conn, target, idle_hours=2)
                long_action = await _hunt(conn, target, idle_hours=100)
                await _action(conn, long_action, status="running", hours_ago=90)
                recent_action = await _hunt(conn, target, idle_hours=100)
                await _action(conn, recent_action, status="completed", hours_ago=1)
                old_action = await _hunt(conn, target, idle_hours=100)
                await _action(conn, old_action, status="completed", hours_ago=99)
                finished = await _hunt(conn, target, status="completed", idle_hours=100, completed=True)

            expired = set(await expire_idle_hunts(pool, None, hours=72))
            assert expired == {str(abandoned), str(never_started), str(exhausted), str(old_action)}

            async with pool.acquire() as conn:
                rows = {str(r["id"]): r for r in await conn.fetch(
                    "SELECT id, status, stop_reason, completed_at FROM hunt_runs")}
            for hunt in expired:
                assert rows[hunt]["status"] == "cancelled"
                assert rows[hunt]["stop_reason"] == IDLE_STOP_REASON and rows[hunt]["completed_at"] is not None
            for hunt in (recent, long_action, recent_action):
                assert rows[str(hunt)]["status"] == "active" and rows[str(hunt)]["stop_reason"] is None
            assert rows[str(finished)]["status"] == "completed"

            # A second pass finds nothing more to end.
            assert await expire_idle_hunts(pool, None, hours=72) == []
    asyncio.run(run())


def test_the_limit_is_generous_by_default_and_set_in_whole_hours():
    assert idle_expiry_hours({}) == 72
    assert idle_expiry_hours({idle_expiry.IDLE_EXPIRY_ENV: "168"}) == 168
    for bad in ("0", "-5", "2.5", "soon"):
        assert idle_expiry_hours({idle_expiry.IDLE_EXPIRY_ENV: bad}) == 72


def test_a_failing_sweep_never_breaks_the_maintenance_tick():
    class BrokenPool:
        def acquire(self):
            raise ConnectionError("database unavailable")

    assert asyncio.run(expire_idle_hunts(BrokenPool(), None)) == []
