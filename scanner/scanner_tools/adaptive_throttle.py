"""Adaptive request throttle for the active scan phase.

Detection depends on clean responses (DBMS fingerprint, SQLi error/differential,
content validation). A single-process target degrades under high-concurrency
active probing — it starts returning timeouts / 5xx / very slow responses — and
those degraded responses make deterministic detectors flake run-to-run.

This module is a shared, process-global (== per-scan, since each scan runs in its
own scanner subprocess) throttle that the shared ``run()`` curl path consults. It
watches a rolling window of request outcomes and, when the degradation rate rises,
widens an inter-request delay so the aggregate request rate drops until the target
recovers; when responses go clean again it relaxes back toward zero. It is a no-op
until explicitly enabled (non-active scans keep today's behavior exactly).
"""

from __future__ import annotations

import asyncio
from collections import deque


class AdaptiveThrottle:
    """AIMD-style backoff on target-degradation signals.

    Cheap and asyncio-safe (single-threaded event loop; only plain deque/float
    ops). ``before()`` sleeps the current delay ahead of a request; ``record()``
    feeds an outcome back and adjusts the delay.
    """

    def __init__(
        self,
        *,
        window: int = 20,
        slow_seconds: float = 6.0,
        high_watermark: float = 0.30,
        low_watermark: float = 0.10,
        max_delay: float = 2.0,
        base_step: float = 0.10,
    ) -> None:
        self._window = deque(maxlen=max(4, window))
        self._slow_seconds = slow_seconds
        self._high = high_watermark
        self._low = low_watermark
        self._max_delay = max_delay
        self._base_step = base_step
        self._delay = 0.0
        self.enabled = False
        # telemetry
        self.max_delay_reached = 0.0
        self.backoff_events = 0
        self.degraded_total = 0
        self.observed_total = 0

    @staticmethod
    def is_degraded(rc: int | None, elapsed: float | None, slow_seconds: float) -> bool:
        """A request degraded if it errored/timed out (curl rc != 0, e.g. exit 28)
        or came back suspiciously slow (a target under stress)."""
        if rc is not None and rc != 0:
            return True
        if elapsed is not None and elapsed >= slow_seconds:
            return True
        return False

    async def before(self) -> None:
        if self.enabled and self._delay > 0.0:
            await asyncio.sleep(self._delay)

    def record(self, *, rc: int | None = None, elapsed: float | None = None) -> None:
        if not self.enabled:
            return
        degraded = self.is_degraded(rc, elapsed, self._slow_seconds)
        self._window.append(1 if degraded else 0)
        self.observed_total += 1
        if degraded:
            self.degraded_total += 1
        if len(self._window) < self._window.maxlen // 2:
            return  # need a minimum sample before reacting
        rate = sum(self._window) / len(self._window)
        if rate >= self._high:
            # Multiplicative increase (bounded).
            new_delay = min(self._max_delay, (self._delay * 1.5) + self._base_step)
            if new_delay > self._delay:
                self.backoff_events += 1
            self._delay = new_delay
            self.max_delay_reached = max(self.max_delay_reached, self._delay)
        elif rate <= self._low:
            # Additive/relative decrease back toward zero.
            self._delay = max(0.0, (self._delay * 0.7) - (self._base_step / 5.0))

    @property
    def delay(self) -> float:
        return self._delay

    def telemetry(self) -> dict:
        return {
            "enabled": self.enabled,
            "current_delay": round(self._delay, 3),
            "max_delay_reached": round(self.max_delay_reached, 3),
            "backoff_events": self.backoff_events,
            "degraded_total": self.degraded_total,
            "observed_total": self.observed_total,
        }


# Process-global singleton (per-scan, since each scan is its own subprocess).
_throttle = AdaptiveThrottle()


def get_throttle() -> AdaptiveThrottle:
    return _throttle


def configure_throttle(enabled: bool = True, **kwargs) -> AdaptiveThrottle:
    """Enable/reconfigure the shared throttle for the active phase."""
    global _throttle
    _throttle = AdaptiveThrottle(**kwargs)
    _throttle.enabled = enabled
    return _throttle


def reset_throttle() -> None:
    global _throttle
    _throttle = AdaptiveThrottle()
