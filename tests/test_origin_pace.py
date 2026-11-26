"""The aggregate Hunt request rate per target origin (runtime/origin_pace)."""
from __future__ import annotations

import asyncio
import time

import pytest

from api.runtime import origin_pace
from api.runtime.origin_pace import OriginPace, activate, origin_of, take


def test_origin_keys_scheme_host_and_port():
    assert origin_of("http://App.Example.test/x?y=1") == "http://app.example.test:80"
    assert origin_of("https://app.example.test:8443/") == "https://app.example.test:8443"
    assert origin_of("/relative") is None


def test_requests_never_start_faster_than_the_rate_after_one_second_of_burst():
    pace = OriginPace(None, 20)  # no shared store: the process-local bucket, same rule

    async def burst():
        started = time.monotonic()
        stamps = []

        async def one():
            await pace.take("http://t.test/a")
            stamps.append(time.monotonic() - started)
        await asyncio.gather(*(one() for _ in range(60)))
        return sorted(stamps)

    stamps = asyncio.run(burst())
    # 20 a second with a 20-request burst: 60 requests need at least (60 - 20) / 20 = 2 s.
    assert stamps[-1] >= 1.9
    for second in range(1, 3):
        window = [s for s in stamps if second <= s < second + 1]
        assert len(window) <= 21
    assert pace.requests == 60 and pace.waited_seconds > 0


def test_origins_are_paced_apart_and_nothing_is_dropped():
    pace = OriginPace(None, 5)

    async def run():
        await asyncio.gather(*(pace.take("http://a.test/") for _ in range(5)),
                             *(pace.take("http://b.test/") for _ in range(5)))
    started = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - started < 0.5  # each origin within its own burst
    assert pace.requests == 10


def test_the_shared_store_decides_the_wait():
    class Store:
        calls = []

        def eval(self, script, numkeys, key, cost, burst):
            self.calls.append((key, float(cost), float(burst)))
            return b"0.0"

    store = Store()
    pace = OriginPace(store, 10)
    asyncio.run(pace.take("http://t.test/x", 3))
    assert store.calls == [("hunt:origin_pace:http://t.test:80", pytest.approx(0.3), 1.0)]


def test_outside_hunt_work_nothing_waits_and_inside_the_active_pace_counts():
    assert asyncio.run(take("http://t.test/")) == 0.0
    with activate(None, 1000) as pace:
        asyncio.run(take("http://t.test/"))
        assert origin_pace.current() is pace and pace.requests == 1
    assert origin_pace.current() is None
