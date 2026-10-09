"""D40 wait bounds, without a database: the poll interval, the lease and cancellation.

The verifier is a labelled double that answers the real 409 "Finding verification is already in
progress" a set number of times; ``verify_after_concurrent_verifier`` is the production function.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from api.hunt import concurrent_verification
from api.hunt.capability_reservations import hunt_capability_lease_seconds
from api.hunt.concurrent_verification import (
    VERIFICATION_IN_PROGRESS, verification_start_by, verify_after_concurrent_verifier,
)


class Busy:
    """Labelled double: the verifier, refused while another Hunt holds the finding."""

    def __init__(self, busy_calls: int) -> None:
        self.busy_calls = busy_calls
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        if self.calls <= self.busy_calls:
            raise HTTPException(status_code=409, detail=VERIFICATION_IN_PROGRESS)
        return {"verified": True}


def test_the_module_poll_interval_is_the_one_in_force(monkeypatch):
    """POLL_SECONDS was bound as a default argument, so patching the module changed nothing."""
    monkeypatch.setattr(concurrent_verification, "POLL_SECONDS", 0.02)
    verify = Busy(busy_calls=10_000)

    async def scenario():
        with pytest.raises(HTTPException):
            await verify_after_concurrent_verifier(verify, wait_seconds=0.4)

    asyncio.run(scenario())
    assert verify.calls >= 8, verify.calls


def test_no_retry_starts_that_the_lease_cannot_cover():
    verify = Busy(busy_calls=1)

    async def scenario():
        start_by = asyncio.get_running_loop().time() - 1  # the lease cannot cover another proof
        with pytest.raises(HTTPException) as refused:
            await verify_after_concurrent_verifier(verify, wait_seconds=30, poll_seconds=0.01, start_by=start_by)
        return refused.value

    refused = asyncio.run(scenario())
    assert refused.detail["reason_code"] == "verification_in_progress"
    assert verify.calls == 1, "the second proof never started"


def test_a_cancelled_hunt_is_refused_before_the_retry():
    verify = Busy(busy_calls=1)
    checks: list[int] = []

    async def cancelled():
        checks.append(verify.calls)
        return True

    async def scenario():
        with pytest.raises(HTTPException) as refused:
            await verify_after_concurrent_verifier(verify, wait_seconds=30, poll_seconds=0.01, cancelled=cancelled)
        return refused.value

    refused = asyncio.run(scenario())
    assert refused.status_code == 409 and refused.detail == "Hunt is cancelled"
    assert verify.calls == 1 and checks == [1]


def _watch(read):
    from api.hunt.cancellation import HuntCancellationWatch

    class Pool:  # labelled double: the Hunt status read
        def acquire(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def fetchval(self, _query, *_args):
            return read()

    return HuntCancellationWatch(lambda: Pool(), "hunt-1")


def test_an_unreadable_hunt_state_refuses_the_retry_without_calling_it_cancelled():
    """The watch fails closed when its read fails; the refusal used to say "Hunt is cancelled"."""
    verify = Busy(busy_calls=1)

    def unreadable():
        raise ConnectionError("database unavailable")

    watch = _watch(unreadable)

    async def scenario():
        with pytest.raises(HTTPException) as refused:
            await verify_after_concurrent_verifier(
                verify, wait_seconds=30, poll_seconds=0.01,
                cancelled=lambda: watch.refresh(force=True), stop_reason=lambda: watch.stop_reason,
            )
        return refused.value

    refused = asyncio.run(scenario())
    assert refused.status_code == 503
    assert refused.detail["reason_code"] == "cancellation_state_unavailable"
    assert "not cancelled" in refused.detail["message"]
    assert verify.calls == 1, "no proof started after the failed read"


def test_a_cancelled_hunt_read_by_the_watch_is_still_reported_as_cancelled():
    verify = Busy(busy_calls=1)
    watch = _watch(lambda: "cancelled")

    async def scenario():
        with pytest.raises(HTTPException) as refused:
            await verify_after_concurrent_verifier(
                verify, wait_seconds=30, poll_seconds=0.01,
                cancelled=lambda: watch.refresh(force=True), stop_reason=lambda: watch.stop_reason,
            )
        return refused.value

    refused = asyncio.run(scenario())
    assert refused.status_code == 409 and refused.detail == "Hunt is cancelled"
    assert watch.stop_reason == "cancelled" and verify.calls == 1


def test_the_hunt_verify_path_passes_the_stop_reason():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "api" / "hunt" / "interaction_router.py").read_text()
    assert "stop_reason=lambda: watch.stop_reason" in source


def test_the_verify_lease_covers_the_wait_and_the_proof():
    verify_budget = {"tool_wall_seconds": 180}
    assert hunt_capability_lease_seconds(verify_budget) == 210
    lease = hunt_capability_lease_seconds(verify_budget, concurrent_wait=True)
    assert lease == 180 + int(concurrent_verification.CONCURRENT_VERIFICATION_WAIT_SECONDS) + 30
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)

    async def scenario():
        loop_now = asyncio.get_running_loop().time()
        start_by = verification_start_by(now + timedelta(seconds=lease), verify_budget, now=now)
        return start_by - loop_now

    # The last start leaves the whole proof wall time inside the lease, and the full wait fits.
    margin = asyncio.run(scenario())
    assert concurrent_verification.CONCURRENT_VERIFICATION_WAIT_SECONDS <= margin <= lease - 180 + 1
    assert verification_start_by(None, verify_budget) is None
