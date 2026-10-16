"""The research autopilot runs its maintenance and claims only where this process leads them."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from research_routes import autopilot_loop as loop  # noqa: E402


class _Stop(BaseException):  # not an Exception: the loop handles those and keeps going
    pass


class _Pool:
    def __init__(self):
        self.acquired = 0

    def acquire(self):
        pool = self

        class Ctx:
            async def __aenter__(self_inner):
                pool.acquired += 1
                return SimpleNamespace()

            async def __aexit__(self_inner, *exc):
                return False
        return Ctx()


def _run_loop(monkeypatch, *, leads: set[str], iterations: int = 3):
    calls: list[str] = []
    pool = _Pool()

    async def lead(_pool, name):
        calls.append(f"lead:{name}")
        return name in leads

    async def run_tick(_pool, name, tick, *, timeout):
        calls.append(f"tick:{name}")
        if name in leads:
            await tick()
        return name in leads

    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= iterations:
            raise _Stop

    async def claim(conn, hub, owner, cursor, *, batch=loop.CLAIM_BATCH):
        calls.append("claim")
        return None

    async def maintenance(_pool, hub, clock):
        calls.append("maintenance")

    monkeypatch.setattr(loop.loop_leader, "lead", lead)
    monkeypatch.setattr(loop.loop_leader, "run_tick", run_tick)
    monkeypatch.setattr(loop.asyncio, "sleep", sleep)
    monkeypatch.setattr(loop, "claim_episode", claim)
    monkeypatch.setattr(loop, "maintenance_tick", maintenance)
    with pytest.raises(_Stop):
        asyncio.run(loop.run_research_autopilot(pool, SimpleNamespace()))
    return calls, sleeps


def test_a_follower_neither_maintains_nor_claims_and_polls_slowly(monkeypatch):
    calls, sleeps = _run_loop(monkeypatch, leads=set())
    assert "claim" not in calls and "maintenance" not in calls
    assert sleeps == [loop.FOLLOWER_POLL_SECONDS] * 3


def test_the_leader_maintains_claims_and_backs_off_while_idle(monkeypatch):
    calls, sleeps = _run_loop(monkeypatch, leads={loop.MAINTENANCE_LOOP, loop.CLAIM_LOOP}, iterations=5)
    assert calls.count("maintenance") == 5 and calls.count("claim") == 5
    assert sleeps == [1.0, 2.0, 4.0, loop.IDLE_MAX_SECONDS, loop.IDLE_MAX_SECONDS]


def test_maintenance_runs_each_periodic_pass_on_its_own_interval(monkeypatch):
    ran: list[str] = []

    class Conn:
        def transaction(self):
            class Tx:
                async def __aenter__(self_inner):
                    return None

                async def __aexit__(self_inner, *exc):
                    return False
            return Tx()

    class Pool:
        def acquire(self):
            class Ctx:
                async def __aenter__(self_inner):
                    return Conn()

                async def __aexit__(self_inner, *exc):
                    return False
            return Ctx()

    def record(name):
        async def call(*_args):
            ran.append(name)
            return 0
        return call

    hub = SimpleNamespace(
        _continue_autonomous_research_campaigns=record("campaigns"),
        _reconcile_stale_research_dispatches=record("stale"),
        _reconcile_unconfirmed_queue_handoffs=record("handoffs"),
        _reconcile_research_orphaned_queue_work=record("orphans"),
        _reap_abandoned_research_episodes=record("reap"),
    )
    now = [1000.0]
    monkeypatch.setattr(loop.time, "monotonic", lambda: now[0])
    clock = loop.MaintenanceClock()
    asyncio.run(loop.maintenance_tick(Pool(), hub, clock))
    assert ran == ["campaigns", "stale", "handoffs", "orphans", "reap"]
    ran.clear()
    now[0] += 1
    asyncio.run(loop.maintenance_tick(Pool(), hub, clock))
    assert ran == ["stale"]
    now[0] += loop.QUEUE_INTERVAL
    ran.clear()
    asyncio.run(loop.maintenance_tick(Pool(), hub, clock))
    assert ran == ["campaigns", "stale", "handoffs", "orphans"]
