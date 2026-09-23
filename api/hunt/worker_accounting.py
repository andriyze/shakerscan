"""Content-safe accounting for worker-settled Hunt actions."""

from __future__ import annotations

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
