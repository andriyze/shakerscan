"""An in-flight exact-SHA image build is reused or fails without a duplicate build."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "wait_for_running_prebuild.py"
spec = importlib.util.spec_from_file_location("wait_for_running_prebuild", SCRIPT)
assert spec and spec.loader
waiter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(waiter)


def test_running_build_waits_until_success():
    states = iter([("queued", ""), ("in_progress", ""), ("completed", "success")])
    polls = []
    pauses = []

    waiter.wait_for_completion(
        "123", lambda run_id: (polls.append(run_id), next(states))[1],
        pauses.append, max_polls=3, interval_seconds=5,
    )

    assert polls == ["123", "123", "123"]
    assert pauses == [5, 5]


def test_failed_build_stops_without_waiting_or_rebuilding():
    with pytest.raises(waiter.PrebuildWaitError, match="failure"):
        waiter.wait_for_completion(
            "123", lambda _: ("completed", "failure"),
            lambda _: pytest.fail("completed build must not sleep"),
        )


def test_stalled_build_has_bounded_wait():
    pauses = []
    with pytest.raises(waiter.PrebuildWaitError, match="still queued"):
        waiter.wait_for_completion(
            "123", lambda _: ("queued", ""), pauses.append,
            max_polls=3, interval_seconds=5,
        )
    assert pauses == [5, 5]
