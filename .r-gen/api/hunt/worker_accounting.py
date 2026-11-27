"""Content-safe accounting for worker-settled Hunt actions."""

from __future__ import annotations

import json
from typing import Any, Mapping


def worker_hunt_budget_accounting(
    reserved: Mapping[str, Any],
    actual: Mapping[str, Any],
    used_after_reconciliation: Mapping[str, Any],
    *,
    reservation_id: str,
    settlement_status: str,
    charge_basis: str = "capability_reported_settlement",
) -> dict[str, Any]:
    normalized_reserved = {
        str(key): max(0, int(value)) for key, value in reserved.items()
    }
    normalized_actual = {
        str(key): max(0, int(value)) for key, value in actual.items()
    }
    return {
        "schema_version": "hunt-budget-settlement/v1",
        "charge_basis": charge_basis,
        "reservation_id": reservation_id,
        "settlement_status": settlement_status,
        "reserved": normalized_reserved,
        "actual": normalized_actual,
        "released": {
            key: max(0, amount - int(normalized_actual.get(key) or 0))
            for key, amount in normalized_reserved.items()
        },
        "used_after_reconciliation": {
            str(key): max(0, int(value))
            for key, value in used_after_reconciliation.items()
        },
    }


def worker_replay_settlement_matches(
    payload: Mapping[str, Any],
    stored: Any,
    action: Mapping[str, Any] | None,
    *,
    action_digest: str,
) -> bool:
    """Check that replay's worker-owned action and reservation settled together."""
    if (
        stored is None or action is None or not stored.record.terminal
        or payload.get("durable_budget_settled") is not True
        or str(action.get("status") or "") not in {
            "completed", "partial", "blocked", "cancelled", "failed",
        }
    ):
        return False
    receipt = dict(stored.receipt or {})
    summary = action.get("result_summary")
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except ValueError:
            return False
    if not isinstance(summary, Mapping):
        return False
    accounting = summary.get("budget_accounting")
    reservation_id = stored.record.reservation_id
    receipt_id = str(receipt.get("receipt_id") or "")
    return bool(
        receipt_id
        and reservation_id
        and stored.action_digest == action_digest
        and str(payload.get("reservation_id") or "") == reservation_id
        and str(payload.get("receipt_id") or "") == receipt_id
        and str(action.get("receipt_id") or "") == receipt_id
        and str(summary.get("budget_reservation_id") or "") == reservation_id
        and str(summary.get("budget_reservation_state") or "") == stored.record.status
        and isinstance(accounting, Mapping)
        and accounting.get("reservation_id") == reservation_id
        and accounting.get("settlement_status") == "succeeded"
        and dict(accounting.get("actual") or {}) == dict(stored.record.actual)
    )
