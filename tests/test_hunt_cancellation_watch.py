"""Cancelling a Hunt must stop work the Hunt already admitted.

The capability executor refuses to start when ``cancelled()`` is true and adapters poll the same
predicate between requests, but API-managed inline dispatch passed ``lambda: False`` for it. So
cancellation updated ``hunt_runs.status`` and nothing else: an admitted action ran to completion
against the target, and the pre-execution barrier could never fire. These pin the predicate that
makes the existing machinery reachable.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from tests.api_sources import definition_source

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.cancellation import HuntCancellationWatch  # noqa: E402


class _Pool:
    def __init__(self, statuses, *, fail=False):
        self._statuses = list(statuses)
        self._fail = fail
        self.reads = 0

    def acquire(self):
        pool = self

        class _Ctx:
            async def __aenter__(self):
                return pool

            async def __aexit__(self, *exc):
                return False

        return _Ctx()

    async def fetchval(self, query, *args):
        self.reads += 1
        if self._fail:
            raise RuntimeError("database unavailable")
        assert "hunt_runs" in query
        return self._statuses.pop(0) if self._statuses else "active"


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_an_active_hunt_is_not_cancelled():
    pool = _Pool(["active"])
    watch = HuntCancellationWatch(lambda: pool, "hunt-1")
    assert watch.cancelled() is False
    assert asyncio.run(watch.refresh(force=True)) is False
    assert watch.cancelled() is False


def test_a_cancelled_hunt_is_observed_and_stays_observed():
    pool = _Pool(["cancelled", "active"])
    watch = HuntCancellationWatch(lambda: pool, "hunt-1")
    assert asyncio.run(watch.refresh(force=True)) is True
    assert watch.cancelled() is True

    # Sticky: a later read that says otherwise must not resurrect the action. Once cancellation is
    # observed the work is already refused, and un-observing it would resume traffic.
    assert asyncio.run(watch.refresh(force=True)) is True
    assert pool.reads == 1, "a cancelled watch must stop querying"


def test_refresh_is_rate_limited_between_heartbeats():
    clock = _Clock()
    pool = _Pool(["active"] * 10)
    watch = HuntCancellationWatch(lambda: pool, "hunt-1", refresh_seconds=2.0, monotonic=clock)

    asyncio.run(watch.refresh())
    assert pool.reads == 1
    for _ in range(5):          # heartbeats are frequent; they must not become a query storm
        asyncio.run(watch.refresh())
    assert pool.reads == 1

    clock.now = 2.5
    asyncio.run(watch.refresh())
    assert pool.reads == 2


def test_a_database_error_is_not_treated_as_a_cancellation():
    # Fail-open is correct here and only here: a transient read failure is not evidence that an
    # operator cancelled, and aborting authorized work on it would turn a blip into an outage.
    pool = _Pool([], fail=True)
    watch = HuntCancellationWatch(lambda: pool, "hunt-1")
    assert asyncio.run(watch.refresh(force=True)) is False
    assert watch.cancelled() is False


def test_heartbeat_refreshes_the_state_and_runs_the_inner_beat():
    pool = _Pool(["cancelled"])
    watch = HuntCancellationWatch(lambda: pool, "hunt-1")
    beats = []

    async def inner():
        beats.append(1)

    asyncio.run(watch.heartbeat(inner)())
    assert watch.cancelled() is True
    assert beats == [1]


def test_only_an_explicit_cancellation_stops_admitted_work():
    # Reaching a terminal state some other way is not a signal to abort traffic already admitted;
    # treating it as one would kill actions that are legitimately finishing.
    for status in ("active", "completed", "awaiting_planner", "created", "failed"):
        watch = HuntCancellationWatch(lambda: _Pool([status]), "hunt-1")
        assert asyncio.run(watch.refresh(force=True)) is False, status


def test_inline_dispatch_no_longer_hardcodes_a_false_predicate():
    router = Path("api/hunt/interaction_router.py").read_text(encoding="utf-8")
    assert "cancelled=lambda: False" not in router, (
        "inline Hunt dispatch must pass a real cancellation predicate"
    )
    dispatch = definition_source("dispatch_registered_adapter")
    assert "HuntCancellationWatch" in dispatch
    assert "cancelled=watch.cancelled" in dispatch
    # Primed before dispatch: the pre-execution barrier is the only chance to stop an adapter that
    # never heartbeats, so a Hunt cancelled while the action queued must not reach the target.
    assert "await watch.refresh(force=True)" in dispatch
    assert dispatch.index("refresh(force=True)") < dispatch.index("HUNT_ACTION_DISPATCHER.execute")
