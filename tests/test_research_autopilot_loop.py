"""The research autopilot: one leader maintains, every process claims and runs bounded steps."""
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


def _fast(monkeypatch):
    monkeypatch.setattr(loop, "MAINTENANCE_INTERVAL", 0.001)
    monkeypatch.setattr(loop, "BUSY_POLL_SECONDS", 0.001)
    monkeypatch.setattr(loop, "IDLE_MAX_SECONDS", 0.001)


def _hub(released: list):
    async def release(_pool, episode_id, owner, error=None):
        released.append((episode_id, error))
    return SimpleNamespace(_release_research_autopilot_lease=release)


async def _until(predicate, *, seconds=2.0):
    deadline = asyncio.get_running_loop().time() + seconds
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.002)


def _setup(monkeypatch, *, leads: set[str], episodes: int):
    """Leadership per loop name, ``episodes`` claimable rows, and steps that block until released."""
    _fast(monkeypatch)
    calls = {"maintenance": 0, "claims": 0, "steps": [], "cancelled": []}
    gate = asyncio.Event()

    async def lead(_pool, name):
        return name in leads

    async def maintenance(_pool, hub, clock):
        calls["maintenance"] += 1

    async def claim(conn, hub, owner, cursor, *, batch=loop.CLAIM_BATCH):
        calls["claims"] += 1
        if len(calls["steps"]) + len(calls["cancelled"]) >= episodes or calls["claims"] > episodes:
            return None
        return {"id": f"episode-{calls['claims']}", "status": "awaiting_planner"}

    async def advance(_pool, hub, row, episode_id, owner):
        calls["steps"].append(episode_id)
        try:
            await gate.wait()
        except asyncio.CancelledError:
            calls["cancelled"].append(episode_id)
            raise

    monkeypatch.setattr(loop.loop_leader, "lead", lead)
    monkeypatch.setattr(loop, "claim_episode", claim)
    monkeypatch.setattr(loop, "maintenance_tick", maintenance)
    monkeypatch.setattr(loop, "_advance", advance)
    return calls, gate


def test_maintenance_keeps_running_while_planner_steps_are_in_flight(monkeypatch):
    released: list = []

    async def scenario():
        calls, _gate = _setup(monkeypatch, leads={loop.MAINTENANCE_LOOP}, episodes=5)
        task = asyncio.create_task(loop.run_research_autopilot(_Pool(), _hub(released), concurrency=2))
        await _until(lambda: len(calls["steps"]) == 2)
        before = calls["maintenance"]
        await _until(lambda: calls["maintenance"] >= before + 5)
        # Both slots stay busy: nothing more is claimed while they run.
        claims = calls["claims"]
        await asyncio.sleep(0.02)
        assert calls["claims"] == claims and len(calls["steps"]) == 2
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Shutdown cancels the in-flight steps (each releases its own lease in _advance).
        assert sorted(calls["cancelled"]) == sorted(calls["steps"])

    asyncio.run(scenario())


def test_a_maintenance_follower_still_claims_and_runs_its_own_steps(monkeypatch):
    released: list = []

    async def scenario():
        calls, gate = _setup(monkeypatch, leads=set(), episodes=3)
        gate.set()
        task = asyncio.create_task(loop.run_research_autopilot(_Pool(), _hub(released), concurrency=2))
        await _until(lambda: len(calls["steps"]) == 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert calls["maintenance"] == 0 and calls["cancelled"] == []

    asyncio.run(scenario())


def test_a_failed_step_releases_its_lease_and_frees_its_slot(monkeypatch):
    released: list = []

    async def scenario():
        calls, _gate = _setup(monkeypatch, leads=set(), episodes=2)

        async def broken(_pool, hub, row, episode_id, owner):
            calls["steps"].append(episode_id)
            raise RuntimeError("release raced")

        monkeypatch.setattr(loop, "_advance", broken)
        task = asyncio.create_task(loop.run_research_autopilot(_Pool(), _hub(released), concurrency=1))
        await _until(lambda: len(released) == 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert released == [("episode-1", "autopilot_controller_error"), ("episode-2", "autopilot_controller_error")]

    asyncio.run(scenario())


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
