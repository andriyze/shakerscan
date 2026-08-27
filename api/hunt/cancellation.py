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

        A read failure leaves the previous state untouched: a transient database error is not
        evidence that a Hunt was cancelled, and inventing one would abort authorized work.
        Cancellation, once observed, is never un-observed.
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
        except Exception:  # noqa: BLE001 - see docstring: a read failure is not a cancellation
            return self._cancelled
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


__all__ = ["CANCELLING_STATUSES", "DEFAULT_REFRESH_SECONDS", "HuntCancellationWatch"]
