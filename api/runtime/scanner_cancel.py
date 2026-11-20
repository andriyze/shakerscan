"""Cancellation reads for a running scanner process, kept off the worker's event loop.

Every running scanner action polled for cancellation every 50 ms with blocking Redis reads on
the worker's event loop, and the Scan check built a new Redis client and pool on each read.
With many actions on one host that starved the loop's own heartbeat until the action's budget
hold went stale and recovery failed it.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable

#: How often a running scanner process checks for cancellation (in a thread).
CANCEL_CHECK_SECONDS = 1.0

_SHARED: tuple[Callable[[], Any], Any] | None = None


def shared_client(factory: Callable[[], Any]) -> Any:
    """One client per factory for cancellation reads (a replaced factory gets its own)."""
    global _SHARED
    if _SHARED is None or _SHARED[0] is not factory:
        _SHARED = (factory, factory())
    return _SHARED[1]


class ThrottledCancelCheck:
    """``check`` at most once per ``interval`` seconds of ``now``, run in a thread."""

    def __init__(self, check: Callable[[], bool], interval: float = CANCEL_CHECK_SECONDS) -> None:
        self._check, self._interval, self._next = check, interval, float("-inf")

    async def requested(self, now: float) -> bool:
        if now < self._next:
            return False
        self._next = now + self._interval
        return bool(await asyncio.to_thread(self._check))
