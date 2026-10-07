"""Bind Hunt coverage claims to same-Hunt actions that actually ran.

Evidence rules (documented in docs/hunt-architecture.md and skills/hunt/SKILL.md):

* Every cited action must belong to this exact Hunt and be settled
  (``completed``, ``partial`` or ``blocked``).
* A queue handoff is never evidence. An action whose result only says that
  downstream work was ``queued`` (device posture queue, confirmed SSH plan) has
  not examined anything yet, whatever its action status says.
* An action *executed* when it is ``completed`` or ``partial`` and its settled
  budget records target traffic (requests, browser actions, ports, hosts or OOB
  interactions). Admission-only, refused and analysis-only actions sent none.
* ``negative`` needs every cited action completed and executed, and no
  contradictory evidence. ``partial`` needs at least one executed action.
  ``blocked`` may be recorded from its blocker text alone; when it cites actions,
  at least one must have executed. A pure policy refusal is a blocker sentence,
  not evidence. ``candidate`` may not cite a refused (``blocked``) action.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from typing import Any
from uuid import UUID

TERMINAL_ACTION_STATUSES = frozenset({"completed", "partial", "blocked"})
EXECUTED_ACTION_STATUSES = frozenset({"completed", "partial"})
# Settled budget dimensions that can only be spent by sending something to a target.
# tool_wall_seconds, agent_actions and active_actions are admission/runtime charges.
EXECUTED_TRAFFIC_DIMENSIONS = frozenset({
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "udp_ports_attempted",
    "hosts_attempted",
    "oob_interactions",
})


class CoverageLedgerError(ValueError):
    """A coverage event is structurally invalid or overclaims its evidence."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 422,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.details = dict(details or {})


def _decoded(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None
    return value


def is_queue_handoff(result_summary: Any) -> bool:
    """True when the action only handed work to a queue that has not reported back."""
    summary = _decoded(result_summary)
    if not isinstance(summary, Mapping):
        return False
    if str(summary.get("status") or "").strip().lower() == "queued":
        return True
    if isinstance(summary.get("queued"), Mapping) or summary.get("queued_scan"):
        return True
    observations = summary.get("receipt_observations")
    if isinstance(observations, Sequence) and not isinstance(observations, (str, bytes)):
        for item in observations:
            if isinstance(item, Mapping) and str(item.get("status") or "").lower() == "queued":
                return True
    return False


def measured_target_traffic(result_summary: Any) -> int:
    """Return settled target-traffic units; unknown or legacy accounting counts as none."""
    summary = _decoded(result_summary)
    if not isinstance(summary, Mapping):
        return 0
    accounting = summary.get("budget_accounting")
    actual = accounting.get("actual") if isinstance(accounting, Mapping) else None
    if not isinstance(actual, Mapping):
        actual = summary.get("budget_consumed")
    if not isinstance(actual, Mapping):
        return 0
    total = 0
    for name, amount in actual.items():
        if str(name) not in EXECUTED_TRAFFIC_DIMENSIONS or isinstance(amount, bool):
            continue
        if isinstance(amount, (int, float)) and amount > 0:
            total += int(amount)
    return total


async def owned_action_evidence(
    conn: Any, *, hunt_run_id: str, action_ids: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Load cited actions from this exact Hunt and classify what each one did."""
    if not action_ids:
        return {}
    rows = await conn.fetch(
        """SELECT id, status, result_summary
           FROM hunt_actions
           WHERE hunt_run_id=$1::uuid AND id = ANY($2::uuid[])""",
        hunt_run_id,
        [UUID(item) for item in action_ids],
    )
    evidence: dict[str, dict[str, Any]] = {}
    for row in rows:
        status = str(row["status"])
        summary = row.get("result_summary") if hasattr(row, "get") else row["result_summary"]
        evidence[str(row["id"])] = {
            "status": status,
            "queue_handoff": is_queue_handoff(summary),
            "executed": (
                status in EXECUTED_ACTION_STATUSES
                and not is_queue_handoff(summary)
                and measured_target_traffic(summary) > 0
            ),
        }
    if set(action_ids) - set(evidence):
        raise CoverageLedgerError(
            "coverage_evidence_not_owned",
            "Coverage evidence must be actions from this exact Hunt",
        )
    if any(item["status"] not in TERMINAL_ACTION_STATUSES for item in evidence.values()):
        raise CoverageLedgerError(
            "coverage_evidence_not_terminal",
            "Coverage evidence must be a completed, partial, or blocked Hunt action",
        )
    if any(item["queue_handoff"] for item in evidence.values()):
        raise CoverageLedgerError(
            "coverage_evidence_queued_handoff",
            "A queue handoff is not evidence: its downstream work has not reported a result",
        )
    return evidence


def validate_evidence_claim(
    angle: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]],
) -> None:
    status = str(angle["status"])
    cited = [evidence[item] for item in angle.get("evidence_action_ids") or [] if item in evidence]
    if status == "negative":
        if any(item["status"] != "completed" for item in cited):
            raise CoverageLedgerError(
                "coverage_negative_requires_completed_actions",
                "Negative coverage may cite only completed actions; partial/blocked work is a gap",
            )
        if any(not item["executed"] for item in cited):
            raise CoverageLedgerError(
                "coverage_negative_requires_executed_actions",
                "Negative coverage may cite only actions that sent target traffic",
            )
        if angle.get("contradictory_evidence_action_ids"):
            raise CoverageLedgerError(
                "coverage_negative_has_contradictory_evidence",
                "Negative coverage cannot close an angle while contradictory evidence remains",
            )
    if status in {"partial", "blocked"} and cited and not any(item["executed"] for item in cited):
        raise CoverageLedgerError(
            "coverage_evidence_not_executed",
            f"{status} coverage must cite at least one same-Hunt action that sent target traffic",
        )
    if status == "candidate" and any(item["status"] == "blocked" for item in cited):
        raise CoverageLedgerError(
            "coverage_candidate_requires_executed_evidence",
            "Candidate coverage cannot cite a blocked (refused) action",
        )


__all__ = [
    "EXECUTED_ACTION_STATUSES",
    "EXECUTED_TRAFFIC_DIMENSIONS",
    "TERMINAL_ACTION_STATUSES",
    "CoverageLedgerError",
    "is_queue_handoff",
    "measured_target_traffic",
    "owned_action_evidence",
    "validate_evidence_claim",
]
