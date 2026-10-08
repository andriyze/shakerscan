"""Two Hunts verifying the same candidate at the same moment (D40).

The web verifier holds a finding-scoped PostgreSQL advisory lock for the whole proof
(``_agent_finding_verification_lock`` in api.py), so two callers never send the proof's traffic
for one finding at once. It takes the lock without waiting and refuses the second caller with
409 "Finding verification is already in progress". Live (plan-hunt-opencode-acceptance-673, D21
concurrent), that refusal was recorded as the loser's ``candidate.verify`` action under its fixed
key, every later call replayed it, and the loser's Hunt never listed the finding the winner
verified a moment later.

A Hunt now waits for the other verifier, within a bound, and then verifies exactly as a later,
sequential verifier does: it runs its own deterministic proof (the lock is free), the proof
re-proves the same finding, and attribution appends this Hunt to ``finding_hunt_verifications``
with role ``additional`` while the first verifier keeps ownership, so both Hunts list the finding.
The lock still serializes the two proofs: nothing is ever sent for one finding twice at once.

The wait is bounded by ``CONCURRENT_VERIFICATION_WAIT_SECONDS``, well inside the action's own
timeout and reservation lease. If the other verifier still holds the lock then, the refusal is
``verification_in_progress``, before any traffic (the reservation is released), and it names the
way on: call again with the next ``attempt``, which is a fresh action, so the Hunt is never
blocked for good.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from fastapi import HTTPException

# The verifier's own refusal text (api.py ``_agent_finding_verification_lock``).
VERIFICATION_IN_PROGRESS = "Finding verification is already in progress"
CONCURRENT_VERIFICATION_WAIT_SECONDS = 90.0
POLL_SECONDS = 0.5


def verification_in_progress(exc: BaseException) -> bool:
    return (
        isinstance(exc, HTTPException) and exc.status_code == 409
        and str(exc.detail) == VERIFICATION_IN_PROGRESS
    )


async def verify_after_concurrent_verifier(
    verify: Callable[[], Awaitable[Mapping[str, Any]]],
    *,
    wait_seconds: float | None = None,
    poll_seconds: float = POLL_SECONDS,
) -> Mapping[str, Any]:
    """Run ``verify``; while another verifier holds the finding, wait for it and run again."""
    bound = CONCURRENT_VERIFICATION_WAIT_SECONDS if wait_seconds is None else float(wait_seconds)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + bound
    while True:
        try:
            return await verify()
        except HTTPException as exc:
            if not verification_in_progress(exc):
                raise
        if loop.time() >= deadline:
            raise HTTPException(status_code=409, detail={
                "error": "verification_in_progress",
                "reason_code": "verification_in_progress",
                "message": (
                    f"Another verification of this finding was still running after {int(bound)} s, "
                    "so this one did not start and nothing was sent. Call verify again with the next "
                    "attempt (attempt=2, then 3): when the other verification has finished, this "
                    "Hunt runs its own proof and lists the finding too."
                ),
            })
        await asyncio.sleep(max(0.01, min(poll_seconds, deadline - loop.time())))


__all__ = [
    "CONCURRENT_VERIFICATION_WAIT_SECONDS", "VERIFICATION_IN_PROGRESS",
    "verification_in_progress", "verify_after_concurrent_verifier",
]
