"""The host-wide heavy scanner limit (api/runtime/heavy_slots.py), against a fake Redis.

Twenty-two thorough Scans on an 8-CPU host started their Nuclei batches at once; the workers'
event loops starved, the actions missed their budget-hold renewals and recovery failed 17 of them.
Heavy processes now queue behind one slot per CPU, keeping their heartbeat while they wait.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from runtime import heavy_slots
from runtime.heavy_slots import HeavyScannerSlot, HeavySlotUnavailable, host_slots


class FakeRedis:
    def __init__(self):
        self.values: dict[str, tuple[str, float]] = {}

    def _live(self, key):
        item = self.values.get(key)
        if item and item[1] <= time.monotonic():
            self.values.pop(key, None)
            return None
        return item

    def set(self, key, value, nx=False, ex=None):
        if nx and self._live(key):
            return None
        self.values[key] = (value, time.monotonic() + (ex or 3600))
        return True

    def eval(self, _script, _numkeys, key, token):
        item = self._live(key)
        if item and item[0] == token:
            del self.values[key]
            return 1
        return 0


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(heavy_slots, "WAIT_POLL_SECONDS", 0.01)
    monkeypatch.setattr(heavy_slots, "HEARTBEAT_SECONDS", 0.02)


def test_slots_are_one_per_cpu_unless_set_explicitly():
    assert host_slots({}, cpu_count=8) == 8
    assert host_slots({heavy_slots.SLOTS_ENV: "3"}, cpu_count=8) == 3
    assert host_slots({heavy_slots.SLOTS_ENV: "0"}, cpu_count=8) == 8
    assert host_slots({heavy_slots.SLOTS_ENV: "many"}, cpu_count=None) >= 1


def test_heavy_processes_beyond_the_slots_wait_with_their_heartbeat_and_then_run():
    redis = FakeRedis()
    holders = [HeavyScannerSlot(redis, "nuclei", slots=2) for _ in range(2)]
    for holder in holders:
        assert asyncio.run(holder.acquire(ttl_seconds=60, max_wait_seconds=5)) == 0.0
        assert holder.held
    beats = []

    async def heartbeat():
        beats.append(1)

    async def scenario():
        waiting = HeavyScannerSlot(redis, "nuclei", slots=2)
        task = asyncio.create_task(waiting.acquire(ttl_seconds=60, max_wait_seconds=5, heartbeat=heartbeat))
        await asyncio.sleep(0.1)
        assert not task.done()  # both slots taken: the third waits
        holders[0].release()
        waited = await task
        assert waiting.held and waited >= 0.1
        waiting.release()
    asyncio.run(scenario())
    assert beats, "a queued action keeps renewing its hold"


def test_a_wait_ends_on_cancellation_or_on_the_time_budget():
    redis = FakeRedis()
    asyncio.run(HeavyScannerSlot(redis, "nuclei", slots=1).acquire(ttl_seconds=60, max_wait_seconds=5))
    with pytest.raises(HeavySlotUnavailable, match="cancelled while waiting"):
        asyncio.run(HeavyScannerSlot(redis, "nuclei", slots=1).acquire(
            ttl_seconds=60, max_wait_seconds=5, cancelled=lambda: True))
    with pytest.raises(HeavySlotUnavailable, match="all 1 heavy scanner slots on this host stayed busy"):
        asyncio.run(HeavyScannerSlot(redis, "nuclei", slots=1).acquire(ttl_seconds=60, max_wait_seconds=0.05))


def test_a_slot_is_freed_only_by_its_holder_and_other_tools_are_not_limited():
    redis = FakeRedis()
    first = HeavyScannerSlot(redis, "nuclei", slots=1)
    asyncio.run(first.acquire(ttl_seconds=60, max_wait_seconds=1))
    # The slot expired and another worker took it: the first holder's release leaves it.
    redis.values["heavy_scanner_slot:0"] = ("someone-else", time.monotonic() + 60)
    first.release()
    assert redis.values["heavy_scanner_slot:0"][0] == "someone-else"
    for light in (HeavyScannerSlot(redis, "katana", slots=1), HeavyScannerSlot(None, "nuclei", slots=1)):
        assert asyncio.run(light.acquire(ttl_seconds=60, max_wait_seconds=0)) == 0.0
        assert not light.held
        light.release()


def test_a_process_queues_past_its_own_short_wall_budget_until_a_slot_frees(monkeypatch):
    # Ten thorough Scans on a 4-CPU host: a passive template attempt reserving 12 s of tool time
    # gave up after 12 s in the queue ("all 4 heavy scanner slots ... stayed busy for 12 s") and
    # the batch ended adapter_failed with nothing run. The wait is bounded by MAX_WAIT_SECONDS,
    # never by the process's own wall budget or timeout.
    monkeypatch.setattr(heavy_slots, "MAX_WAIT_SECONDS", 5.0)
    redis = FakeRedis()
    holder = HeavyScannerSlot(redis, "nuclei", slots=1)
    asyncio.run(holder.acquire(ttl_seconds=60, max_wait_seconds=1))

    async def scenario():
        queued = HeavyScannerSlot(redis, "nuclei", slots=1)
        task = asyncio.create_task(queued.acquire_for_process(process_timeout_ms=50))
        await asyncio.sleep(0.3)  # far longer than the process's 50 ms timeout
        assert not task.done()
        holder.release()
        waited = await task
        assert queued.held and waited >= 0.3
        queued.release()
    asyncio.run(scenario())
