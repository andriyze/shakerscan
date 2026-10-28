"""Bounded concurrency on the existing agent-tool worker and leased job path.

SSH log watches must not block external HTTP/scanner checks. This changes only
scheduling of ordinary leased jobs; each handler still owns its durable claim,
target validation, heartbeat, cancellation, budget settlement and acknowledgement.

Long actions must not block short ones either. A long action is a worker action whose wall, the
larger of the registry's and the one admission reserved for this call, exceeds
``LONG_ACTION_WALL_SECONDS`` (a verifier, a template or port scan, a crawl, a service
fingerprint). Long actions take at most ``MAX_CONCURRENT_LONG_AGENT_JOBS`` of the
``MAX_CONCURRENT_AGENT_JOBS`` slots, so a short call (``http.request``, ``artifact.inspect``, a
browser step) never waits behind them: it waits only for short work, each at most
``LONG_ACTION_WALL_SECONDS``, or an SSH command, which takes a slot without counting as long. The
API's wait for a queued call counts from when a worker starts it (``work_started_at``), and a
short call's reservation lease (at least 90 s) still lets it start behind one short action. A long
job leased while the long slots are taken waits inside its leased execution, so its queue lease
keeps its heartbeat, and it does not count against the slot short work needs. Admission keeps one
Hunt within that bound (``require_long_action_slot``), so a long job waits here only while other
Hunts' long actions hold the long slots. Once ``MAX_WAITING_LONG_AGENT_JOBS`` long jobs wait on one
worker, it leases nothing more, short work included, until one of them starts.
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
import math
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

MAX_CONCURRENT_AGENT_JOBS = 3
MAX_CONCURRENT_LONG_AGENT_JOBS = MAX_CONCURRENT_AGENT_JOBS - 1
# A worker action whose wall may exceed this is long. Short work shares the slot left to it, so a
# short call queued behind one short action starts within this; its reservation lease is at least
# 90 s from admission (hunt/capability_reservations.py), which leaves 30 s to spare, and the
# worker refuses a job whose lease ran out before it started.
LONG_ACTION_WALL_SECONDS = 60
# Long jobs leased while the long slots were taken wait at most this many at once; beyond that
# the worker leases nothing more, short work included, until one of them starts.
MAX_WAITING_LONG_AGENT_JOBS = 8
# Executors whose Hunt actions admission reserves durably and a worker runs from the queue.
_WORKER_EXECUTORS = frozenset({
    "worker_scanner", "worker_network", "worker_browser", "worker_auth", "worker_http",
})
# An SSH command runs on the worker that holds its session; it never waits for a long slot.
_SESSION_CAPABILITIES = frozenset({"ssh.connect", "ssh.exec", "ssh.close"})
# Queue jobs that carry one Hunt capability. Any other agent-tool job is long only when its own
# timeout is (a legacy agent scanner names one; a request-collection replay or an authentication
# validation does not, and each ends within about a minute).
_CAPABILITY_JOB_TYPES = frozenset({
    "canonical_scanner_capability", "canonical_browser_capability",
    "canonical_network_capability", "canonical_http_capability",
})

_tasks: set[asyncio.Task] = set()
_waiting = 0  # long jobs leased while the long slots were taken, waiting for one
_long_running = 0
_wakers: list[asyncio.Future] = []


def _registry():
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:  # package import in host-side tests
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    return CAPABILITY_REGISTRY


def _seconds(value: Any) -> float:
    """A wall in seconds from a queue payload or a reservation; anything else counts as none."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value) if math.isfinite(value) and value > 0 else 0.0


@functools.cache
def _registry_wall(name: str) -> float | None:
    """The registry wall of a worker action that takes a slot, or None for any other name."""
    try:
        spec = _registry().require(name)
    except KeyError:
        return None
    if spec.hunt_executor not in _WORKER_EXECUTORS or spec.name in _SESSION_CAPABILITIES:
        return None
    return max(int(spec.default_timeout_ms) / 1000, _seconds(spec.budget_cost.get("tool_wall_seconds")))


def long_action(name: str, reserved_wall_seconds: Any = None) -> bool:
    """Whether one call of a Hunt capability is a long worker action: its wall, the larger of the
    registry's and the one admission reserved for it, exceeds ``LONG_ACTION_WALL_SECONDS``."""
    wall = _registry_wall(str(name or "").strip().lower())
    if wall is None:
        return False
    return max(wall, _seconds(reserved_wall_seconds)) > LONG_ACTION_WALL_SECONDS


def long_capability(name: str) -> bool:
    """Whether every call of a Hunt capability is a long worker action (its registry wall)."""
    return long_action(name)


@functools.lru_cache(maxsize=1)
def long_capabilities() -> frozenset[str]:
    return frozenset(spec.name for spec in _registry().list() if long_capability(spec.name))


@functools.lru_cache(maxsize=1)
def slot_capabilities() -> frozenset[str]:
    """The Hunt capabilities a worker runs in one of its slots and that may be long."""
    return frozenset(spec.name for spec in _registry().list() if _registry_wall(spec.name) is not None)


def long_job(job: Any) -> bool:
    if not isinstance(job, Mapping):
        return False
    if job.get("type") in _CAPABILITY_JOB_TYPES:
        # The network, browser and HTTP payloads carry the reserved budget the worker checks; the
        # scanner payload carries its reserved wall for scheduling only.
        expected = job.get("expected_budget")
        reserved = max(
            _seconds(expected.get("tool_wall_seconds")) if isinstance(expected, Mapping) else 0.0,
            _seconds(job.get("reserved_wall_seconds")),
        )
        return long_action(str(job.get("capability_name") or ""), reserved)
    return _seconds(job.get("timeout_ms")) / 1000 > LONG_ACTION_WALL_SECONDS


def _wake() -> None:
    while _wakers:
        waker = _wakers.pop(0)
        if not waker.done():
            waker.set_result(None)


async def _next_change() -> None:
    """Return once a job finishes, a long job starts waiting, or a long slot frees."""
    waker = asyncio.get_running_loop().create_future()
    _wakers.append(waker)
    try:
        await asyncio.wait((*_tasks, waker), return_when=asyncio.FIRST_COMPLETED)
    finally:
        with contextlib.suppress(ValueError):
            _wakers.remove(waker)
        waker.cancel()


def _no_slot() -> bool:
    return (len(_tasks) - _waiting >= MAX_CONCURRENT_AGENT_JOBS
            or _waiting >= MAX_WAITING_LONG_AGENT_JOBS)


async def lease_when_ready(operation, *, enabled):
    # Wait BEFORE leasing: a job waiting for capacity must never lose its Redis
    # fencing lease while the preceding SSH watch still occupies a slot.
    if enabled:
        while _no_slot():
            await _next_change()
    return await asyncio.to_thread(operation)


async def dispatch(redis, lease, job, *, execute, enabled):
    if not enabled:
        return await execute(redis, lease, job)
    while _no_slot():
        await _next_change()
    task = asyncio.create_task(execute(redis, lease, job))
    _tasks.add(task)
    def done(finished):
        _tasks.discard(finished)
        _wake()
        if not finished.cancelled():
            error = finished.exception()
            if error:
                # Job content and commands must never be printed by the scheduler.
                print('[agent-worker] leased job failed: '+type(error).__name__,flush=True)
    task.add_done_callback(done)


async def in_lane(job: Any, run: Callable[[Any], Awaitable[Any]]) -> Any:
    """Run one leased job's work; a long job first takes one of the long slots.

    The worker calls it inside the leased execution (``_run_job_under_lease``), so a job waiting
    here keeps its queue lease's heartbeat. While it waits it does not count against the slots
    short work runs in."""
    global _waiting, _long_running
    if not long_job(job):
        return await run(job)
    if _long_running >= MAX_CONCURRENT_LONG_AGENT_JOBS:
        _waiting += 1
        _wake()  # the slot this job was leased into is free for short work again
        try:
            while _long_running >= MAX_CONCURRENT_LONG_AGENT_JOBS:
                await _next_change()
        finally:
            _waiting -= 1
    _long_running += 1
    try:
        return await run(job)
    finally:
        _long_running -= 1
        _wake()


async def require_long_action_slot(
    conn: Any, run: Mapping[str, Any], name: str, reserved_wall_seconds: Any = None,
) -> None:
    """Refuse a Hunt's long action while the Hunt already has the long slots' worth in flight.

    A call is long by its own reserved wall (``long_action``), and so is each live reservation it
    is counted against. Runs in admission's transaction after the Hunt row is locked, so two calls
    cannot both take the last one. A refused call reserves and records nothing: the same key may
    be sent again once one of them settles."""
    if not long_action(name, reserved_wall_seconds):
        return
    rows = await conn.fetch(
        """SELECT capability_name, action_id FROM budget_reservations
           WHERE owner_kind='hunt' AND owner_id=$1 AND capability_name = ANY($2::text[])
             AND (capability_name = ANY($3::text[])
                  OR (jsonb_typeof(requested_json->'tool_wall_seconds') = 'number'
                      AND (requested_json->>'tool_wall_seconds')::numeric > $4))
             AND status IN ('reserved','running') AND lease_expires_at > NOW()
           ORDER BY created_at, id""",
        str(run["id"]), sorted(slot_capabilities()), sorted(long_capabilities()),
        LONG_ACTION_WALL_SECONDS,
    )
    if len(rows) < MAX_CONCURRENT_LONG_AGENT_JOBS:
        return
    try:
        from hunt.permission_reasons import HuntRefusal
    except ModuleNotFoundError:  # package import in host-side tests
        from .permission_reasons import HuntRefusal
    names = ", ".join(str(row["capability_name"]) for row in rows)
    raise HuntRefusal(
        "long_actions_in_flight",
        f"This Hunt already has {len(rows)} long actions in flight ({names}), the most that run "
        "at once, so that short calls (http.request, artifact.inspect, a browser step) do not "
        "wait behind them. Nothing was reserved or recorded. Work with short capabilities or "
        "collect one of them (call it again with its idempotency_key and unchanged input), then "
        "send this call again with the same idempotency_key once one has settled.",
        extra={
            "in_flight": [{"capability_name": str(row["capability_name"]),
                           "action_id": str(row["action_id"])} for row in rows],
            "max_long_actions_in_flight": MAX_CONCURRENT_LONG_AGENT_JOBS,
        },
        headers={"Retry-After": "60"},
    )


async def close():
    global _waiting, _long_running
    running = tuple(_tasks)
    for task in running:
        task.cancel()
    await asyncio.gather(*running,return_exceptions=True)
    _tasks.clear()
    _waiting = _long_running = 0
    _wake()
