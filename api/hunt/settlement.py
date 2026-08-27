"""Settle a blocked Hunt action without refunding traffic that may already have happened."""

from __future__ import annotations

from typing import Mapping


def blocked_actual_charges(
    charges: Mapping[str, int],
    actual_charges: Mapping[str, int],
    *,
    executed: bool,
    enqueued: bool,
    device_http_attempted: bool,
    elapsed_wall: int,
) -> dict[str, int]:
    """Settle a blocked action without refunding traffic that may already have happened.

    A blocked status covers two very different situations. Admission refused the action before any
    adapter ran, in which case the holds are genuinely unused and releasing them is right. Or the
    action executed -- or queued downstream work -- and then failed in a way that cannot prove what
    reached the target. Zeroing every non-agent dimension for both refunded HTTP, port and fragility
    holds after real traffic, which is precisely what `conservative_full_budget` on candidate
    verification exists to prevent: the executor charges the full hold when an exception leaves the
    outcome uncertain, and this then gave it straight back.

    So the release applies only when the server can show nothing ran. When an executor produced an
    accounting, that accounting is authoritative; when downstream work was enqueued, the holds stay
    charged because the work is real even though this action is over.
    """
    settled = dict(actual_charges)
    if executed or enqueued:
        return settled
    for dimension in charges:
        if dimension not in {"agent_actions", "active_actions"}:
            settled[dimension] = 0
    if device_http_attempted:
        settled["http_requests"] = min(1, int(charges.get("http_requests") or 0))
        settled["device_fragility_points"] = min(
            1, int(charges.get("device_fragility_points") or 0),
        )
        settled["tool_wall_seconds"] = min(
            int(charges.get("tool_wall_seconds") or 0), max(1, elapsed_wall),
        )
    return settled


__all__ = ["blocked_actual_charges"]
