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

The wait is bounded by ``CONCURRENT_VERIFICATION_WAIT_SECONDS``, and by the action's
reservation lease: the inline lease of ``candidate.verify`` adds the wait to the proof's own wall
time, and the caller passes ``start_by``, the last moment a proof can start and still finish inside
that lease, so a proof is never started that the lease cannot cover. If the other verifier still
holds the lock then, the refusal is ``verification_in_progress``, before any traffic (the
reservation is released), and it names the way on: call again with the next ``attempt``, which is
a fresh action, so the Hunt is never blocked for good.

A Hunt cancelled during the wait starts no proof: ``cancelled`` is read again before every retry,
and a cancelled Hunt is refused before any traffic ("Hunt is cancelled", as at dispatch).
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
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


def verification_start_by(
    lease_expires_at: datetime | None, requested: Mapping[str, Any], *, now: datetime | None = None,
) -> float | None:
    """The last event-loop moment a proof may start and still end inside the lease, or None.

    A proof may take the action's whole wall budget (``tool_wall_seconds``).
    """
    if lease_expires_at is None:
        return None
    current = now or datetime.now(timezone.utc)
    remaining = (lease_expires_at - current).total_seconds()
    proof = int(dict(requested or {}).get("tool_wall_seconds") or 0)
    return asyncio.get_running_loop().time() + remaining - proof


async def verify_after_concurrent_verifier(
    verify: Callable[[], Awaitable[Mapping[str, Any]]],
    *,
    wait_seconds: float | None = None,
    poll_seconds: float = POLL_SECONDS,
    cancelled: Callable[[], Awaitable[bool]] | None = None,
    start_by: float | None = None,
) -> Mapping[str, Any]:
    """Run ``verify``; while another verifier holds the finding, wait for it and run again.

    ``cancelled`` is awaited before every retry: a cancelled Hunt is refused before any traffic.
    ``start_by`` (event-loop time) is the last moment a retry may start, so its proof still ends
    inside the action's reservation lease.
    """
    bound = CONCURRENT_VERIFICATION_WAIT_SECONDS if wait_seconds is None else float(wait_seconds)
    poll = float(poll_seconds)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + bound
    if start_by is not None:
        deadline = min(deadline, float(start_by))
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
                    "Another verification of this finding was still running when this one had to "
                    "start, so it did not start and nothing was sent. Call verify again with the next "
                    "attempt (attempt=2, then 3): when the other verification has finished, this "
                    "Hunt runs its own proof and lists the finding too."
                ),
            })
        await asyncio.sleep(max(0.01, min(poll, deadline - loop.time())))
        if cancelled is not None and await cancelled():
            raise HTTPException(status_code=409, detail="Hunt is cancelled")


__all__ = [
    "CONCURRENT_VERIFICATION_WAIT_SECONDS", "VERIFICATION_IN_PROGRESS",
    "verification_in_progress", "verification_start_by", "verify_after_concurrent_verifier",
]
