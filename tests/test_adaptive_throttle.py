"""Adaptive active-phase throttle: backs off on target-degradation signals
(timeouts / slow responses) and recovers when responses go clean again, so a
single-process target under scan load stops flaking deterministic detectors.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.adaptive_throttle import (  # noqa: E402
    AdaptiveThrottle,
    configure_throttle,
    get_throttle,
    reset_throttle,
)


def test_disabled_by_default_is_noop():
    t = AdaptiveThrottle()
    assert t.enabled is False
    # record does nothing while disabled
    for _ in range(50):
        t.record(rc=124, elapsed=30.0)
    assert t.delay == 0.0
    asyncio.run(t.before())  # returns immediately


def test_degradation_signal_classification():
    slow = 6.0
    # curl timeout / connection error
    assert AdaptiveThrottle.is_degraded(124, None, slow) is True
    assert AdaptiveThrottle.is_degraded(7, None, slow) is True
    # slow-but-succeeded
    assert AdaptiveThrottle.is_degraded(0, 9.0, slow) is True
    # healthy
    assert AdaptiveThrottle.is_degraded(0, 0.2, slow) is False
    assert AdaptiveThrottle.is_degraded(0, None, slow) is False


def test_backs_off_under_sustained_degradation():
    t = AdaptiveThrottle(window=20)
    t.enabled = True
    for _ in range(40):
        t.record(rc=124, elapsed=30.0)  # all timeouts
    assert t.delay > 0.0
    assert t.delay <= 2.0  # bounded by max_delay
    assert t.backoff_events > 0


def test_recovers_when_responses_go_clean():
    t = AdaptiveThrottle(window=20)
    t.enabled = True
    for _ in range(40):
        t.record(rc=124, elapsed=30.0)
    backed_off = t.delay
    assert backed_off > 0.0
    for _ in range(80):
        t.record(rc=0, elapsed=0.1)  # all clean
    assert t.delay < backed_off
    assert t.delay == 0.0


def test_stays_calm_on_healthy_traffic():
    t = AdaptiveThrottle(window=20)
    t.enabled = True
    for _ in range(60):
        t.record(rc=0, elapsed=0.15)
    assert t.delay == 0.0


def test_before_sleeps_when_backed_off(monkeypatch):
    t = AdaptiveThrottle(window=8)
    t.enabled = True
    for _ in range(20):
        t.record(rc=124, elapsed=30.0)
    assert t.delay > 0.0
    slept = {}

    async def fake_sleep(d):
        slept["d"] = d

    monkeypatch.setattr("scanner_tools.adaptive_throttle.asyncio.sleep", fake_sleep)
    asyncio.run(t.before())
    assert slept.get("d") == t.delay


def test_configure_and_reset_singleton():
    configure_throttle(enabled=True, window=10)
    assert get_throttle().enabled is True
    reset_throttle()
    assert get_throttle().enabled is False
