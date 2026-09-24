"""Durable public HTTP action summaries; the canonical receipt retains observations."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .worker_accounting import worker_hunt_budget_accounting


def http_action_result(
    *, status: str, error: Any, partial: bool, timed_out: bool,
    observations: Sequence[Mapping[str, Any]], parser_errors: Sequence[str],
    requested: Mapping[str, Any], terminal: Any, reconciled: Mapping[str, Any],
    reservation_id: str, receipt_id: Any, session: Any,
    verified_finding_ids: Sequence[str],
) -> dict[str, Any]:
    """Keep settled usage, session metadata and actual finding IDs together.

    Extracted from the HTTP worker so adding a proof family does not grow the
    worker monolith or copy its accounting into another execution path.
    """
    return {
        "status": status, "ok": status == "success", "error": error,
        "partial": partial, "timed_out": timed_out,
        "record_count": len(observations), "parser_errors": list(parser_errors[:20]),
        "budget_consumed": dict(terminal.actual),
        "budget_accounting": worker_hunt_budget_accounting(
            requested, terminal.actual, reconciled,
            reservation_id=reservation_id, settlement_status="succeeded",
        ),
        "budget_reservation_id": reservation_id,
        "budget_reservation_state": terminal.status,
        "receipt_id": str(receipt_id),
        "session": session.public_dict() if session is not None else None,
        "verified_finding_ids": list(verified_finding_ids),
    }
