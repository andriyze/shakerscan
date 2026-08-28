"""Let an in-flight Hunt action observe that its Hunt was cancelled.

The capability executor already has the machinery: it refuses to start when ``cancelled()`` is
true, and adapters poll the same predicate between requests. API-managed inline dispatch passed
``lambda: False`` for it, so neither the pre-execution barrier nor any mid-flight poll could ever
fire -- cancelling a Hunt updated ``hunt_runs.status`` and nothing else, and an action already
admitted ran to completion against the target.

``cancelled()`` is synchronous by contract while the Hunt's state lives in Postgres, so the state is
refreshed on the ``heartbeat`` the executor and adapters already call between units of work, and
read from cache in the predicate. The refresh is rate-limited because heartbeats are frequent, and
the watch is primed once before dispatch so the pre-execution barrier is meaningful even for an
adapter that never heartbeats.

Only an explicit ``cancelled`` status stops work. Reaching a terminal state some other way is not a
signal to abort traffic already admitted, and treating it as one would abort actions that are
legitimately finishing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable


CANCELLING_STATUSES: frozenset[str] = frozenset({"cancelled"})

DEFAULT_REFRESH_SECONDS = 2.0


class HuntCancellationWatch:
    """Cache a Hunt's cancellation state for the synchronous ``cancelled()`` contract."""

    def __init__(
        self,
        pool_factory: Callable[[], Any],
        hunt_run_id: Any,
        *,
        refresh_seconds: float = DEFAULT_REFRESH_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._pool_factory = pool_factory
        self._hunt_run_id = hunt_run_id
        self._refresh_seconds = max(0.0, float(refresh_seconds))
        self._monotonic = monotonic
        self._cancelled = False
        self._last_refresh: float | None = None

    @property
    def hunt_run_id(self) -> Any:
        return self._hunt_run_id

    def cancelled(self) -> bool:
        """Return the last observed cancellation state. Never blocks."""
        return self._cancelled

    async def refresh(self, *, force: bool = False) -> bool:
        """Re-read the Hunt's status, at most once per refresh interval unless forced.

        A read failure fails closed. Once the server can no longer revalidate the Hunt's durable
        authority, target traffic must pause rather than continue on a stale cached grant.
        """
        if self._cancelled:
            return True
        now = self._monotonic()
        if not force and self._last_refresh is not None:
            if now - self._last_refresh < self._refresh_seconds:
                return self._cancelled
        self._last_refresh = now
        try:
            pool = self._pool_factory()
            async with pool.acquire() as connection:
                status = await connection.fetchval(
                    "SELECT status FROM hunt_runs WHERE id=$1", self._hunt_run_id,
                )
        except Exception:  # noqa: BLE001 - authority cannot be revalidated; stop target traffic
            self._cancelled = True
            return True
        if str(status or "").strip().lower() in CANCELLING_STATUSES:
            self._cancelled = True
        return self._cancelled

    def heartbeat(self, inner: Callable[[], Awaitable[None]] | None = None) -> Callable[[], Awaitable[None]]:
        """Wrap a heartbeat so every beat also refreshes the cancellation state."""

        async def _beat() -> None:
            await self.refresh()
            if inner is not None:
                await inner()
            else:
                await asyncio.sleep(0)

        return _beat


# --- Worker-placed capability jobs ------------------------------------------------------------
# Not every Hunt capability runs inline. A worker-placed one polls `agent_tool_cancel:{job_id}`
# with a job id minted fresh at queue time, so a Hunt cancellation cannot reconstruct it -- and
# `HuntRunService.cancel` therefore left queued capability traffic running while the Hunt itself
# read as cancelled. The ids are recorded against the Hunt when queued so cancellation can reach
# them. Redis holds them because the job and the key already live there and share its lifetime.

JOB_SET_PREFIX = "hunt_cancel_jobs:"
JOB_CANCEL_PREFIX = "agent_tool_cancel:"
JOB_SET_TTL_SECONDS = 86_400


# A missing method or a misspelled name is a broken feature, not an unreachable Redis.
# Catching both alike is what hid the fact that `signal_cancelled_jobs` was never imported
# into the cancel path: every cancellation raised NameError, reported nothing signalled,
# and looked exactly like a Hunt that had queued no jobs.
_CODING_ERRORS = (AttributeError, NameError, TypeError)


def record_cancellable_job(redis_client: Any, hunt_id: Any, job_id: Any, *, ttl: int = JOB_SET_TTL_SECONDS) -> None:
    """Remember one queued capability job so a Hunt cancellation can signal it."""
    hunt = str(hunt_id or "").strip()
    job = str(job_id or "").strip()
    if not redis_client or not hunt or not job:
        return
    key = f"{JOB_SET_PREFIX}{hunt}"
    try:
        redis_client.sadd(key, job)
        redis_client.expire(key, max(60, int(ttl)))
    except _CODING_ERRORS:
        raise
    except Exception:  # noqa: BLE001 - bookkeeping must never fail the queue path
        return


async def record_cancellable_job_durable(
    pool: Any,
    redis_client: Any,
    hunt_id: Any,
    job_id: Any,
    *,
    ttl: int = JOB_SET_TTL_SECONDS,
) -> None:
    """Persist a queued job before publishing it, then populate the fast Redis index.

    Redis is deliberately only an accelerator here.  If it is unavailable the durable row lets a
    later cancellation reconstruct the exact job ids; if Postgres is unavailable the caller must
    not enqueue work that it can no longer cancel.
    """
    hunt = str(hunt_id or "").strip()
    job = str(job_id or "").strip()
    if not hunt or not job:
        raise ValueError("hunt_id and job_id are required")
    async with pool.acquire() as connection:
        await connection.execute(
            """INSERT INTO hunt_cancellable_jobs(hunt_id, job_id)
               VALUES($1::uuid, $2::uuid)
               ON CONFLICT (hunt_id, job_id) DO UPDATE
               SET updated_at=NOW()""",
            hunt,
            job,
        )
    record_cancellable_job(redis_client, hunt, job, ttl=ttl)


def signal_cancelled_jobs(
    redis_client: Any,
    hunt_id: Any,
    *,
    job_ids: Any = (),
    ttl: int = 3_600,
) -> list[str]:
    """Set the cancel flag every worker-placed job of this Hunt polls. Returns the ids signalled.

    Idempotent by construction: setting an already-set flag is harmless, and a job that has since
    finished simply never reads it.
    """
    hunt = str(hunt_id or "").strip()
    if not redis_client or not hunt:
        return []
    key = f"{JOB_SET_PREFIX}{hunt}"
    members: set[Any] = set(job_ids or ())
    try:
        members.update(redis_client.smembers(key) or ())
    except _CODING_ERRORS:
        raise
    except Exception:  # noqa: BLE001 - durable ids can still be signalled without the Redis set
        pass
    signalled: list[str] = []
    for raw in members:
        job = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
        if not job:
            continue
        try:
            redis_client.set(f"{JOB_CANCEL_PREFIX}{job}", "1", ex=max(60, int(ttl)))
        except _CODING_ERRORS:
            raise
        except Exception:  # noqa: BLE001 - signal as many as possible
            continue
        signalled.append(job)
    return sorted(signalled)


__all__ = [
    "CANCELLING_STATUSES",
    "DEFAULT_REFRESH_SECONDS",
    "HuntCancellationWatch",
    "JOB_CANCEL_PREFIX",
    "JOB_SET_PREFIX",
    "record_cancellable_job",
    "record_cancellable_job_durable",
    "signal_cancelled_jobs",
]
