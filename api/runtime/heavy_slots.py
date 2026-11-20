"""A host-wide limit on CPU-heavy scanner processes, shared by every worker on the host.

Worker count and active Scans are sized from memory. Twenty-two thorough Scans on an 8-CPU host
each started a Nuclei template batch at once: the batches starved the workers' event loops, the
actions missed their budget-hold renewals, and recovery failed 17 of the 22. This limit queues
heavy processes instead: the host never runs more than its slots (two per CPU by default) at once, and nothing
cuts workers or active Scans.

Slots live in the workers' shared Redis as self-expiring keys holding one token each, so a worker
that dies frees its slot when the key expires. A worker without Redis (a broker-leased remote
worker) is not limited here.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import time
from typing import Any, Awaitable, Callable

#: Scanner tools whose processes are CPU-heavy (template engines loading thousands of templates).
HEAVY_SCANNER_TOOLS = frozenset({"nuclei"})
SLOTS_ENV = "SHAKERSCAN_HEAVY_SCANNER_SLOTS"
SLOT_KEY = "heavy_scanner_slot:{index}"
WAIT_POLL_SECONDS = 2.0
HEARTBEAT_SECONDS = 15.0
#: How long a scanner process may queue for a slot. The wait is not tool time and must not be
#: bounded by the process's own wall budget: a small attempt (a passive template batch of a few
#: endpoints) reserves only seconds, so ten Scans on a 4-CPU host gave up after 12 s of queueing
#: and the batch ended adapter_failed with nothing run. The queued action keeps its heartbeat and
#: honours cancellation meanwhile; the Scan's own duration limit still applies.
MAX_WAIT_SECONDS = 1800.0
# Compare and delete in one step: a slot that expired and was retaken is never freed by its
# earlier holder.
_RELEASE_IF_OWNED = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end return 0"


class HeavySlotUnavailable(RuntimeError):
    """No slot became free within the action's time budget."""


#: Default heavy processes per CPU. Measured on a 4-CPU host: ten thorough Scans ran about 1.75
#: Nuclei batches per CPU without starving the workers, while the failures this limit prevents
#: were seen near 2.75 per CPU. One per CPU queued so much that late proof checks ran into the
#: Scan's own time limit.
SLOTS_PER_CPU = 2


def host_slots(environ: dict[str, str] | None = None, cpu_count: int | None = None) -> int:
    """An explicit SHAKERSCAN_HEAVY_SCANNER_SLOTS wins; otherwise two slots per CPU."""
    raw = str((os.environ if environ is None else environ).get(SLOTS_ENV) or "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return max(1, SLOTS_PER_CPU * int(cpu_count if cpu_count is not None else (os.cpu_count() or 1)))


class HeavyScannerSlot:
    """One heavy process's hold on a host slot (a no-op for other tools or without Redis)."""

    def __init__(self, redis_client: Any | None, tool: str, *, slots: int | None = None) -> None:
        self._redis = redis_client if str(tool or "").lower() in HEAVY_SCANNER_TOOLS else None
        self._slots = slots or host_slots()
        self._token = secrets.token_hex(16)
        self._key: str | None = None

    @property
    def held(self) -> bool:
        return self._key is not None

    def _try_take(self, ttl_seconds: int) -> bool:
        for index in range(self._slots):
            key = SLOT_KEY.format(index=index)
            if self._redis.set(key, self._token, nx=True, ex=ttl_seconds):
                self._key = key
                return True
        return False

    async def acquire(
        self, *, ttl_seconds: int, max_wait_seconds: float,
        heartbeat: Callable[[], Awaitable[None]] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> float:
        """Take a slot; return the seconds spent waiting. While waiting the action keeps its
        heartbeat and honours cancellation, so a queued action never goes stale."""
        if self._redis is None:
            return 0.0
        ttl = max(60, int(ttl_seconds))
        if await asyncio.to_thread(self._try_take, ttl):
            return 0.0
        started = time.monotonic()
        next_heartbeat = started + HEARTBEAT_SECONDS
        while not await asyncio.to_thread(self._try_take, ttl):
            now = time.monotonic()
            if cancelled is not None and await asyncio.to_thread(cancelled):
                raise HeavySlotUnavailable("cancelled while waiting for a heavy scanner slot")
            if now - started >= max_wait_seconds:
                raise HeavySlotUnavailable(
                    f"all {self._slots} heavy scanner slots on this host stayed busy for "
                    f"{int(now - started)} s; the action was not started")
            if heartbeat is not None and now >= next_heartbeat:
                await heartbeat()
                next_heartbeat = now + HEARTBEAT_SECONDS
            await asyncio.sleep(WAIT_POLL_SECONDS)
        return time.monotonic() - started

    async def acquire_for_process(
        self, *, process_timeout_ms: int,
        heartbeat: Callable[[], Awaitable[None]] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> float:
        """Take a slot for one scanner process: held for the process's timeout plus a margin,
        waited for up to ``MAX_WAIT_SECONDS`` whatever the process's own wall budget."""
        return await self.acquire(
            ttl_seconds=int(process_timeout_ms) // 1000 + 120, max_wait_seconds=MAX_WAIT_SECONDS,
            heartbeat=heartbeat, cancelled=cancelled)

    def release(self) -> None:
        """Free the slot only while it still holds this token (an expired, retaken slot stays)."""
        if self._redis is None or self._key is None:
            return
        key, self._key = self._key, None
        try:
            self._redis.eval(_RELEASE_IF_OWNED, 1, key, self._token)
        except Exception:  # noqa: BLE001 - an unreleased slot expires on its own
            pass
