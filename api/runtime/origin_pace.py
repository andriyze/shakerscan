"""One request rate at each target origin for everything the engine sends there for Hunts.

Hunt work reaches a target through several senders at once: the planner's calls, the engine's
own discovery and sweep, request.verify and the proof adapters, and scanners (Nuclei, katana,
sqlmap, Dalfox, ffuf, the browser) through the pinned SOCKS proxy. Each was held to its own rate,
and nothing held their sum: measured at a range, several of them together sent 40-47 requests in
one second where the fastest executor is held to 10. This module is the aggregate: one token
bucket per target origin (scheme, host and port), kept in the workers' shared Redis, so every
worker, every Hunt and every sender on that origin draw from it.

* The rate is the Hunt wire rate (``hunt.budget_pace.wire_requests_per_second``, the rate the
  Hunt budget profiles are paced on), with one burst allowance equal to that per-second rate.
* A request is never dropped: a sender waits until its token comes due (GCRA reservation: the
  bucket hands each caller the time its request may start, computed atomically in Redis on the
  Redis clock).
* Only Hunt work is paced here (``activate`` is entered for a Hunt job); a Scan keeps its own
  adaptive pacing (``target_pacing``).
* The wait is recorded: ``waited_seconds`` on the active pace, which the worker writes into the
  job's record with the action's timings.

Without Redis (a broker-leased remote worker without the shared store) the pace is
process-local, which still bounds that worker's own sum.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import time
from typing import Any, Iterator
import urllib.parse

KEY = "hunt:origin_pace:{origin}"
# GCRA on the Redis clock: KEYS[1] holds the theoretical arrival time (seconds, float). ARGV:
# cost (seconds of rate this call takes), burst (seconds of tolerance). Returns the wait.
_RESERVE = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local tat = tonumber(redis.call('GET', KEYS[1]) or '0')
if tat < now then tat = now end
local cost = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local nexttat = tat + cost
local wait = nexttat - now - burst
if wait < 0 then wait = 0 end
redis.call('SET', KEYS[1], tostring(nexttat), 'PX', math.ceil((nexttat - now) * 1000) + 60000)
return tostring(wait)
"""


def origin_of(url: str) -> str | None:
    """``scheme://host:port`` of a URL (default ports explicit), or None."""
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower().rstrip(".")
        if not scheme or not host:
            return None
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    return f"{scheme}://{host}:{port}"


class OriginPace:
    """The aggregate request rate for Hunt traffic, per target origin."""

    def __init__(self, redis_client: Any, rate: float) -> None:
        self.redis = redis_client
        self.rate = max(1.0, float(rate))
        self.waited_seconds = 0.0
        self.requests = 0
        self._local: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _reserve_local(self, origin: str, cost: float, burst: float) -> float:
        now = time.monotonic()
        tat = max(self._local.get(origin, now), now)
        self._local[origin] = tat + cost
        return max(0.0, tat + cost - now - burst)

    def _reserve(self, origin: str, requests: int) -> float:
        cost = max(1, int(requests)) / self.rate
        burst = 1.0  # one second of the rate: a burst allowance equal to the per-second rate
        if self.redis is not None:
            try:
                raw = self.redis.eval(_RESERVE, 1, KEY.format(origin=origin), repr(cost), repr(burst))
                return float(raw.decode() if isinstance(raw, bytes) else raw)
            except Exception:  # noqa: BLE001 - the shared store failed: pace this process alone
                pass
        return self._reserve_local(origin, cost, burst)

    async def take(self, url: str, requests: int = 1) -> float:
        """Wait until ``requests`` requests to ``url``'s origin may start; returns the wait."""
        origin = origin_of(url)
        if origin is None or requests <= 0:
            return 0.0
        wait = await asyncio.to_thread(self._reserve, origin, requests)
        self.requests += int(requests)
        if wait > 0:
            self.waited_seconds += wait
            await asyncio.sleep(wait)
        return wait


_ACTIVE: ContextVar[OriginPace | None] = ContextVar("hunt_origin_pace", default=None)


def current() -> OriginPace | None:
    """The pace of the Hunt job this code runs for, or None (not Hunt work)."""
    return _ACTIVE.get()


@contextmanager
def activate(redis_client: Any, rate: float) -> Iterator[OriginPace]:
    """Pace every Hunt request sent inside this block (one Hunt job's execution)."""
    pace = OriginPace(redis_client, rate)
    token = _ACTIVE.set(pace)
    try:
        yield pace
    finally:
        _ACTIVE.reset(token)


async def take(url: str, requests: int = 1) -> float:
    """Wait for the active Hunt pace, if any; a no-op outside Hunt work."""
    pace = _ACTIVE.get()
    return await pace.take(url, requests) if pace is not None else 0.0


__all__ = ["KEY", "OriginPace", "activate", "current", "origin_of", "take"]
