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


def verification_traffic_charge(result: Mapping[str, Any]) -> dict[str, int] | None:
    """The traffic a completed web candidate verification reports it sent, to settle its hold to.

    The server-run workflow counts every request of both runs and its probe
    (``workflow_experiment.workflow_traffic``); a verification that reports none (a device
    verification, a browser step, an error) keeps its conservative whole hold.
    """
    verification = result.get("verification") if isinstance(result.get("verification"), Mapping) else {}
    traffic = verification.get("traffic")
    if not isinstance(traffic, Mapping):
        return None
    return {
        key: int(traffic[key]) for key in ("http_requests", "state_changing_requests")
        if isinstance(traffic.get(key), int) and not isinstance(traffic.get(key), bool) and traffic[key] >= 0
    } or None


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


# The duration is the Hunt's clock (the ``tool_wall_seconds`` ledger, bounded by
# ``max_duration_seconds``), and only the clock running out ends a Hunt as ``budget_exhausted``.
# Every other used-up limit -- a safety ceiling (state-changing requests, TCP ports, hosts, UDP
# ports, out-of-band interactions, device fragility) or a call or traffic limit -- refuses only
# the actions that need it, with a budget.raise request a person can grant; the Hunt keeps its
# status and every action that needs none of that dimension carries on.
CLOCK_DIMENSION = "tool_wall_seconds"


def clock_exhausted(
    limits: Mapping[str, Any], used: Mapping[str, Any], shortages: Mapping[str, Any],
) -> bool:
    """Whether this shortage is the Hunt's clock running out, the one shortage that ends it."""
    return CLOCK_DIMENSION in shortages and reservation_exhausted(
        limits, used, {CLOCK_DIMENSION: shortages[CLOCK_DIMENSION]},
    )


async def record_budget_shortage(
    conn: Any, *, hunt_id: Any, limits: Mapping[str, Any],
    used: Mapping[str, Any], shortages: Mapping[str, Any],
) -> dict[str, Any]:
    exhausted = reservation_exhausted(limits, used, shortages)
    dimension = next(iter(shortages), "unknown")
    code = "budget_exhausted" if exhausted else "budget_insufficient_for_action"
    if clock_exhausted(limits, used, shortages):
        await conn.execute(
            "UPDATE hunt_runs SET status='budget_exhausted', stop_reason=$2, updated_at=NOW() WHERE id=$1",
            hunt_id, f"budget_exhausted:{CLOCK_DIMENSION}",
        )
    return {
        "error": f"{code}:{dimension}", "retryable_with_smaller_action": not exhausted,
        "shortages": {key: int(value) for key, value in shortages.items()},
        "remaining": {key: max(0, int(limits.get(key) or 0) - int(used.get(key) or 0)) for key in shortages},
    }
