"""Bounded concurrency on the existing agent-tool worker and leased job path.

SSH log watches must not block external HTTP/scanner checks. This changes only
scheduling of ordinary leased jobs; each handler still owns its durable claim,
target validation, heartbeat, cancellation, budget settlement and acknowledgement.
"""
from __future__ import annotations
import asyncio

MAX_CONCURRENT_AGENT_JOBS = 3
_tasks: set[asyncio.Task] = set()


async def lease_when_ready(operation, *, enabled):
    # Wait BEFORE leasing: a job waiting for capacity must never lose its Redis
    # fencing lease while the preceding SSH watch still occupies a slot.
    if enabled:
        while len(_tasks) >= MAX_CONCURRENT_AGENT_JOBS:
            await asyncio.wait(tuple(_tasks), return_when=asyncio.FIRST_COMPLETED)
    return await asyncio.to_thread(operation)


async def dispatch(redis, lease, job, *, execute, enabled):
    if not enabled:
        return await execute(redis, lease, job)
    while len(_tasks) >= MAX_CONCURRENT_AGENT_JOBS:
        await asyncio.wait(tuple(_tasks), return_when=asyncio.FIRST_COMPLETED)
    task = asyncio.create_task(execute(redis, lease, job))
    _tasks.add(task)
    def done(finished):
        _tasks.discard(finished)
        if not finished.cancelled():
            error = finished.exception()
            if error:
                # Job content and commands must never be printed by the scheduler.
                print('[agent-worker] leased job failed: '+type(error).__name__,flush=True)
    task.add_done_callback(done)


async def close():
    running = tuple(_tasks)
    for task in running:
        task.cancel()
    await asyncio.gather(*running,return_exceptions=True)
    _tasks.clear()
