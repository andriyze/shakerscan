"""Bounded concurrency on the existing agent-tool worker and leased job path.

SSH log watches must not block external HTTP/scanner checks. This changes only
scheduling of ordinary leased jobs; each handler still owns its durable claim,
target validation, heartbeat, cancellation, budget settlement and acknowledgement.

Long actions must not block short ones either. A long action (a wall over
``LONG_ACTION_WALL_SECONDS``: a verifier, a template or port scan, a browser crawl) takes at
most ``MAX_CONCURRENT_LONG_AGENT_JOBS`` of the ``MAX_CONCURRENT_AGENT_JOBS`` slots, so one slot
always runs short work (``http.request``, ``artifact.inspect``, a browser step). The API waits
for a queued short call for its own timeout plus 30 s, which long actions holding every slot
for up to 20 minutes would use up. A long job leased while the long slots are taken waits inside
its leased execution, so its queue lease keeps its heartbeat, and it does not count against the
slot short work needs. Admission keeps one Hunt within that bound (``require_long_action_slot``),
so a long job waits here only while other Hunts' long actions hold the long slots.
"""
from __future__ import annotations

import asyncio
import contextlib
import functools
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

MAX_CONCURRENT_AGENT_JOBS = 3
MAX_CONCURRENT_LONG_AGENT_JOBS = MAX_CONCURRENT_AGENT_JOBS - 1
# A worker action whose wall may exceed this holds its slot longer than a queued short call can
# wait for one, and outlasts the MCP adapter's progress hold (120 s, less its 10 s settle
# reserve), so it may answer outcome=running and stay in flight while the agent works on.
LONG_ACTION_WALL_SECONDS = 90
# Long jobs leased while the long slots were taken wait at most this many at once; beyond that
# the worker leases nothing more until one of them starts.
MAX_WAITING_LONG_AGENT_JOBS = 8
# Executors whose Hunt actions admission reserves durably and a worker runs from the queue.
_WORKER_EXECUTORS = frozenset({
    "worker_scanner", "worker_network", "worker_browser", "worker_auth", "worker_http",
})
# An SSH command runs on the worker that holds its session; it never waits for a slot.
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


@functools.cache
def long_capability(name: str) -> bool:
    """Whether a Hunt capability is a long worker action (see the module docstring)."""
    try:
        spec = _registry().require(name)
    except KeyError:
        return False
    if spec.hunt_executor not in _WORKER_EXECUTORS or spec.name in _SESSION_CAPABILITIES:
        return False
    wall = max(int(spec.default_timeout_ms) / 1000, float(spec.budget_cost.get("tool_wall_seconds") or 0))
    return wall > LONG_ACTION_WALL_SECONDS


@functools.lru_cache(maxsize=1)
def long_capabilities() -> frozenset[str]:
    return frozenset(spec.name for spec in _registry().list() if long_capability(spec.name))


def long_job(job: Any) -> bool:
    if not isinstance(job, Mapping):
        return False
    if job.get("type") in _CAPABILITY_JOB_TYPES:
        return long_capability(str(job.get("capability_name") or "").strip().lower())
    timeout_ms = job.get("timeout_ms")
    return (isinstance(timeout_ms, (int, float)) and not isinstance(timeout_ms, bool)
            and timeout_ms / 1000 > LONG_ACTION_WALL_SECONDS)


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


async def require_long_action_slot(conn: Any, run: Mapping[str, Any], name: str) -> None:
    """Refuse a Hunt's long action while the Hunt already has the long slots' worth in flight.

    Runs in admission's transaction after the Hunt row is locked, so two calls cannot both take
    the last one. A refused call reserves and records nothing: the same key may be sent again
    once one of them settles."""
    if not long_capability(name):
        return
    rows = await conn.fetch(
        """SELECT capability_name, action_id FROM budget_reservations
           WHERE owner_kind='hunt' AND owner_id=$1 AND capability_name = ANY($2::text[])
             AND status IN ('reserved','running') AND lease_expires_at > NOW()
           ORDER BY created_at, id""",
        str(run["id"]), sorted(long_capabilities()),
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
        "at once, so that a short call (http.request, artifact.inspect, a browser step) always "
        "finds a worker. Nothing was reserved or recorded. Work with short capabilities or "
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
