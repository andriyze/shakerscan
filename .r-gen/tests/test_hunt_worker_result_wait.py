"""The API's wait for a queued Hunt capability counts from when a worker starts its work.

The API answers a Hunt capability call once the worker publishes its result. It waited the call's
own timeout plus 30 s from enqueue, so a call that first waited for a worker slot lost that time:
an ``http.request`` (30 s timeout) queued behind other work for a minute ended
``worker_result_timeout`` without ever running, and a long action that waited for one of the long
slots was cancelled before its wall was up. The wait now counts that allowance from the worker's
``work_started_at`` stamp (api/worker.py, written after any wait for a long slot). Until a worker
starts the job the API waits as long as its reservation could still start: its admission lease,
plus the same 30 s; a worker refuses a job whose lease ran out before it started.

Unit fixtures: the event-loop clock and Redis are labelled doubles; the wait loops are the
router's own enqueue functions.
"""
from __future__ import annotations

import ast
import asyncio
import json
import uuid
from pathlib import Path

import pytest

from api.hunt import interaction_router as router

ROOT = Path(__file__).resolve().parents[1]


class _Clock:
    """Labelled double: the event-loop clock and sleep the API wait reads."""

    CancelledError = asyncio.CancelledError

    def __init__(self):
        self.now = 0.0

    def get_running_loop(self):
        return self

    def time(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds


class _WorkerRedis:
    """Labelled double: Redis, with a worker that starts the job's work at ``starts_at`` (never,
    when None) and publishes its result ``runs_for`` seconds later."""

    def __init__(self, clock, *, starts_at, runs_for):
        self.clock, self.starts_at, self.runs_for = clock, starts_at, runs_for
        self.cancelled: list[str] = []
        self.enqueued: list[dict] = []
        self.started_reads = 0

    def hset(self, *_args, **_kwargs):
        return 1

    def expire(self, *_args, **_kwargs):
        return True

    def exists(self, *_keys):
        return 1

    def hget(self, key, field):
        assert key.startswith("job:") and field == "work_started_at"
        self.started_reads += 1
        if self.starts_at is None or self.clock.now < self.starts_at:
            return None
        return b"2026-10-23T00:00:00+00:00"

    def get(self, key):
        assert key.startswith("agent_tool_result:")
        if self.starts_at is None or self.clock.now < self.starts_at + self.runs_for:
            return None
        return json.dumps({"status": "success", "finished_at": self.clock.now}).encode()

    def delete(self, *_keys):
        return 1

    def set(self, key, _value, ex=None):
        self.cancelled.append(key)


ENQUEUE = {
    "http": lambda: (router._enqueue_canonical_http_capability, {
        "capability_name": "http.request", "capability_input": {"method": "GET", "path": "/"},
        "expected_budget": {"http_requests": 1, "tool_wall_seconds": 15}}),
    "browser": lambda: (router._enqueue_canonical_browser_capability, {
        "capability_name": "browser.navigate", "capability_input": {"path": "/"},
        "expected_input_digest": "b" * 64, "expected_budget": {"tool_wall_seconds": 30}}),
    "network": lambda: (router._enqueue_canonical_network_capability, {
        "capability_name": "service.fingerprint", "capability_input": {"ports": [8000]},
        "expected_input_digest": "c" * 64, "expected_budget": {"tool_wall_seconds": 30}}),
    "scanner": lambda: (router._enqueue_canonical_scanner_capability, {
        "capability_name": "web.probe", "capability_input": {"path": "/"}}),
}


def _wait(monkeypatch, kind, *, timeout_ms, queue_seconds, starts_at, runs_for):
    clock = _Clock()
    redis = _WorkerRedis(clock, starts_at=starts_at, runs_for=runs_for)

    async def record_job(*_args, **_kwargs):
        return None

    monkeypatch.setattr(router, "asyncio", clock)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "record_cancellable_job_durable", record_job)
    monkeypatch.setattr(router, "_pool", lambda: None)
    monkeypatch.setattr(router, "enqueue_job", lambda _redis, _queue, payload: redis.enqueued.append(payload))
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    function, arguments = ENQUEUE[kind]()
    result = asyncio.run(function(
        **arguments, timeout_ms=timeout_ms, hunt_id=str(uuid.UUID(int=1)),
        action_id=str(uuid.UUID(int=7)), reservation_id=str(uuid.UUID(int=8)),
        action_digest="a" * 64, queue_seconds=queue_seconds,
    ))
    return result, redis, clock


@pytest.mark.parametrize("kind", sorted(ENQUEUE))
def test_a_call_that_waited_a_minute_for_a_worker_still_gets_its_whole_time(monkeypatch, kind):
    """A 30 s call queued for 70 s (its admission lease is 90 s) runs 25 s and answers."""
    result, redis, clock = _wait(monkeypatch, kind, timeout_ms=30_000, queue_seconds=90,
                                 starts_at=70, runs_for=25)
    assert result["status"] == "success" and 95 <= clock.now < 96.5
    assert redis.cancelled == [] and len(redis.enqueued) == 1
    # The start is read about once a second, not on every result poll.
    assert redis.started_reads <= 75


@pytest.mark.parametrize("kind", sorted(ENQUEUE))
def test_the_calls_own_time_counts_from_its_start(monkeypatch, kind):
    """Started at once, a call that never answers is given up at its timeout plus 30 s, not at
    its queued bound."""
    result, redis, clock = _wait(monkeypatch, kind, timeout_ms=30_000, queue_seconds=90,
                                 starts_at=0, runs_for=10_000)
    assert result["status"] == "timeout" and result["error"] == "worker_result_timeout"
    assert 60 <= clock.now < 61.5
    assert len(redis.cancelled) == 1 and redis.cancelled[0].startswith("agent_tool_cancel:")


@pytest.mark.parametrize("kind", sorted(ENQUEUE))
def test_a_call_no_worker_starts_is_given_up_once_its_reservation_could_no_longer_start(monkeypatch, kind):
    result, redis, clock = _wait(monkeypatch, kind, timeout_ms=30_000, queue_seconds=90,
                                 starts_at=None, runs_for=0)
    assert result["status"] == "timeout" and result["error"] == "worker_result_timeout"
    assert 120 <= clock.now < 121
    assert len(redis.cancelled) == 1


def test_a_long_action_that_waited_for_a_long_slot_runs_its_whole_wall(monkeypatch):
    """A 1,200 s sqli.verify that waited 400 s for a long slot (its lease is 1,230 s) is not
    cancelled 1,230 s after enqueue but answers when it ends, 1,500 s after."""
    result, redis, clock = _wait(monkeypatch, "scanner", timeout_ms=1_200_000, queue_seconds=1_230,
                                 starts_at=400, runs_for=1_100)
    assert result["status"] == "success" and 1_500 <= clock.now < 1_501.5
    assert redis.cancelled == []
    # The scanner payload carries the wall it reserved, so the worker runs it in a long slot.
    assert redis.enqueued[0]["reserved_wall_seconds"] == 1_200


def test_without_a_queued_bound_the_wait_is_the_calls_own_time(monkeypatch):
    result, _redis, clock = _wait(monkeypatch, "http", timeout_ms=30_000, queue_seconds=None,
                                  starts_at=None, runs_for=0)
    assert result["error"] == "worker_result_timeout" and 60 <= clock.now < 61


def test_admission_gives_every_queued_call_its_reservation_lease_as_the_queued_bound():
    tree = ast.parse((ROOT / "api/hunt/interaction_router.py").read_text(encoding="utf-8"))
    lifecycle = next(node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef)
                     and node.name == "_execute_hunt_capability_lifecycle")
    calls = [call for call in ast.walk(lifecycle) if isinstance(call, ast.Call)
             and getattr(call.func, "id", "").startswith("_enqueue_canonical_")]
    assert sorted(call.func.id for call in calls) == sorted(
        f"_enqueue_canonical_{kind}_capability" for kind in ENQUEUE)
    for call in calls:
        bound = {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords}
        assert bound.get("queue_seconds") == "durable_lease_seconds", call.func.id
