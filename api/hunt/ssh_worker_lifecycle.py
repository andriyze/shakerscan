"""Keep SSH owner liveness and idle cleanup independent of queue blocking."""
from __future__ import annotations

import asyncio
from uuid import UUID

from .ssh_routing import worker_key, session_key, WORKER_TTL
try:
    from capabilities.ssh_transport import SSH_TRANSPORTS
except ModuleNotFoundError:
    from ..capabilities.ssh_transport import SSH_TRANSPORTS


async def maintain_ssh_sessions(redis, pool, worker_id, *, transports=SSH_TRANSPORTS):
    key = worker_key(worker_id)
    try:
        while True:
            try:
                redis.set(key, '1', ex=WORKER_TTL)
                active = None
                if transports.sessions:
                    identifiers = list({UUID(item.binding[0]) for item in transports.sessions.values()})
                    async with pool.acquire() as conn:
                        rows = await conn.fetch("SELECT id FROM hunt_runs WHERE id=ANY($1::uuid[]) "
                            "AND status IN ('active','awaiting_planner','budget_exhausted') "
                            "AND completed_at IS NULL", identifiers)
                    active = {str(row['id']) for row in rows}
                for identifier in transports.reap(active):
                    redis.delete(session_key(identifier))
            except Exception:
                transports.close_all()
            await asyncio.sleep(1)
    finally:
        transports.close_all()
        redis.delete(key)


def start_ssh_sessions(redis, pool, worker_id, queues, base_queue, enabled):
    """Only agent-tool workers own direct SSH sessions and their private route."""
    if not enabled:
        return None
    from .ssh_routing import worker_queue
    queues.insert(0, worker_queue(base_queue, worker_id))
    return asyncio.create_task(maintain_ssh_sessions(redis, pool, worker_id))
