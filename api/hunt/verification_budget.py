"""Admission costs for the existing server-materialized HTTP proof workflows."""

from typing import Any, Mapping


def web_candidate_budget(family: str) -> dict[str, int]:
    # The existing candidate bridge materializes HTTP steps only, with a second
    # proof run and restoration for mutations. Preserve its conservative HTTP
    # envelope, but never invent browser traffic for an HTTP-only verifier.
    amounts = {"http_requests": 24, "browser_actions": 0}
    if family in {"mass_assignment", "field_constraint", "workflow"}:
        amounts["state_changing_requests"] = 12
    return amounts


def reservation_exhausted(
    limits: Mapping[str, Any], used: Mapping[str, Any], shortages: Mapping[str, Any],
) -> bool:
    """An oversized action is not exhaustion while its dimensions have headroom.

    Zero is an intentionally disabled dimension, not a reason to kill an otherwise
    usable run. Authority and budget enforcement still reject the requested action.
    """
    return any(
        int(limits.get(key) or 0) > 0
        and int(used.get(key) or 0) >= int(limits[key])
        for key in shortages
    )


async def record_budget_shortage(
    conn: Any, *, hunt_id: Any, limits: Mapping[str, Any],
    used: Mapping[str, Any], shortages: Mapping[str, Any],
) -> dict[str, Any]:
    exhausted = reservation_exhausted(limits, used, shortages)
    dimension = next(iter(shortages), "unknown")
    code = "budget_exhausted" if exhausted else "budget_insufficient_for_action"
    if exhausted:
        await conn.execute(
            "UPDATE hunt_runs SET status='budget_exhausted', stop_reason=$2, updated_at=NOW() WHERE id=$1",
            hunt_id, f"{code}:{dimension}",
        )
    return {
        "error": f"{code}:{dimension}", "retryable_with_smaller_action": not exhausted,
        "shortages": {key: int(value) for key, value in shortages.items()},
        "remaining": {key: max(0, int(limits.get(key) or 0) - int(used.get(key) or 0)) for key in shortages},
    }
