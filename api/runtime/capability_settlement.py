"""Shared terminal settlement for durable Scan and Hunt capabilities."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .budget_reservations import DurableBudgetReservation
from .receipts import CapabilityReceipt


def terminalize_capability_reservation(
    running: DurableBudgetReservation,
    *,
    action_digest: str,
    capability_name: str,
    adapter_name: str,
    adapter_version: str,
    target_id: Any,
    target_kind: str,
    capability_input: Mapping[str, Any],
    action_status: str,
    actual_budget: Mapping[str, int],
    worker_id: str,
    started_at: str,
    finished_at: str,
    receipt_id: str,
    parser_version: str | None = None,
    scope_receipt_id: Any = None,
    approval_receipt_id: Any = None,
    result: Mapping[str, Any] | None = None,
    fallback_observation_kind: str = "capability_result",
) -> tuple[DurableBudgetReservation, CapabilityReceipt]:
    """Build one matching terminal reservation and owner-bound public receipt."""
    if running.status != "running":
        raise ValueError("capability settlement requires a running reservation")
    status = str(action_status or "failed").strip().lower()
    successful = status in {"completed", "partial"}
    reservation_state = "committed" if successful else "failed"
    receipt_status = {
        "completed": "succeeded",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(status, "failed")
    result_item = dict(result or {})
    error = str(result_item.get("error") or "").strip()
    receipt_errors = result_item.get("receipt_errors")
    if isinstance(receipt_errors, (list, tuple)):
        errors = tuple(str(item) for item in receipt_errors if str(item))[:20]
    else:
        errors = (error,) if error else ()
    receipt_observations = result_item.get("receipt_observations")
    if isinstance(receipt_observations, (list, tuple)):
        observations = tuple(
            dict(item) for item in receipt_observations if isinstance(item, Mapping)
        )
    else:
        observations = ({
            "kind": str(fallback_observation_kind or "capability_result"),
            "status": status,
            "ok": bool(result_item.get("ok")),
        },)
    owner = (
        {"scan_id": running.owner_id}
        if running.owner_kind == "scan"
        else {"hunt_id": running.owner_id}
    )
    terminal_at = datetime.fromisoformat(str(finished_at).replace("Z", "+00:00"))
    receipt = CapabilityReceipt(
        receipt_id=str(receipt_id),
        capability_name=str(capability_name),
        adapter_name=str(adapter_name),
        adapter_version=str(adapter_version),
        target_id=str(target_id),
        worker_id=str(worker_id),
        scope_receipt_id=str(scope_receipt_id or "") or None,
        approval_receipt_id=str(approval_receipt_id or "") or None,
        status=receipt_status,
        partial=status == "partial",
        timed_out=bool(status == "partial" and result_item.get("timed_out")),
        input_digest=str(action_digest),
        parser_version=str(parser_version or adapter_version),
        started_at=started_at,
        finished_at=finished_at,
        redacted_execution={
            "target_kind": str(target_kind),
            "capability": str(capability_name),
            "input": dict(capability_input or {}),
        },
        budget_reservation_id=running.reservation_id,
        budget_reservation_state=reservation_state,
        budget_reserved=running.requested,
        budget_consumed=dict(actual_budget or {}),
        observations=observations,
        errors=errors,
        **owner,
    )
    if successful:
        terminal = running.commit(
            actual=actual_budget,
            execution_receipt_hash=receipt.receipt_hash,
            now=terminal_at,
            worker_id=worker_id,
        )
    else:
        terminal = running.fail(
            reason=(
                "capability_blocked" if status == "blocked"
                else "capability_cancelled" if status == "cancelled"
                else "capability_failed"
            ),
            actual=actual_budget,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=bool(result_item.get("execution_started", True)),
            now=terminal_at,
        )
    return terminal, receipt
