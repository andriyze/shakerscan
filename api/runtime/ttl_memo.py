"""A process-local memo of a zero-argument function's answer, valid for a fixed number of seconds.

For answers that are expensive to compute, change rarely, and may be a little stale: the API's
expected build fingerprint hashes about 800 deployed source files (tens of milliseconds of CPU,
on the event loop) and only changes when the deployed source changes.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class TtlMemo(Generic[T]):
    """``memo()`` returns ``compute()``'s answer, recomputed once it is ``ttl_seconds`` old.

    A failed computation is not remembered (the next call computes again). Two threads that
    find the answer expired at the same moment may both compute; that is harmless here and
    keeps the lock off the slow path.
    """

    def __init__(self, compute: Callable[[], T], ttl_seconds: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._compute = compute
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._value: T | None = None
        self._at: float | None = None

    def __call__(self) -> T:
        now = self._clock()
        with self._lock:
            if self._at is not None and now - self._at < self._ttl:
                return self._value  # type: ignore[return-value]
        value = self._compute()
        with self._lock:
            self._value, self._at = value, now
        return value

    def clear(self) -> None:
        with self._lock:
            self._value, self._at = None, None
