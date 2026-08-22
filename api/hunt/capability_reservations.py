"""Durable reservation contracts for inline canonical Hunt capabilities."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Mapping

try:
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.receipts import CapabilityReceipt
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.budget_reservations import DurableBudgetReservation
    from ..runtime.receipts import CapabilityReceipt


DURABLE_INLINE_HUNT_CAPABILITIES = frozenset({
    "collections.inspect",
    "collections.select",
    "http.request",
    "tls.inspect",
})

DURABLE_DEVICE_CONTROL_HUNT_CAPABILITIES = frozenset({
    "device.capabilities.inspect",
    "device.inspect",
})

DURABLE_DEVICE_HTTP_HUNT_CAPABILITIES = frozenset({
    "device.http.probe",
})

DURABLE_WORKER_HUNT_CAPABILITIES = frozenset({
    "ports.discover",
    "service.fingerprint",
    "subdomains.discover",
})

DURABLE_SCANNER_HUNT_CAPABILITIES = frozenset({
    "sqli.verify",
    "templates.scan",
    "web.content_discover",
    "web.crawl",
    "web.probe",
    "xss.verify",
})


def hunt_capability_action_digest(
    *,
    hunt_id: Any,
    action_id: Any,
    capability_name: str,
    target_kind: str,
    target_id: Any,
    capability_input: Mapping[str, Any],
    requested_budget: Mapping[str, int],
    scope_receipt_id: Any = None,
    approval_receipt_id: Any = None,
) -> str:
    """Hash the exact server-authorized action persisted beside its reservation."""
    payload = {
        "schema_version": "hunt-capability-action/v1",
        "hunt_id": str(hunt_id),
        "action_id": str(action_id),
        "capability_name": str(capability_name or "").strip().lower(),
        "target_kind": str(target_kind or "").strip().lower(),
        "target_id": str(target_id),
        "input": dict(capability_input or {}),
        "requested_budget": {
            str(name): int(amount)
            for name, amount in sorted(dict(requested_budget or {}).items())
        },
        "scope_receipt_id": str(scope_receipt_id or "") or None,
        "approval_receipt_id": str(approval_receipt_id or "") or None,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hunt_capability_lease_seconds(requested_budget: Mapping[str, int]) -> int:
    """Give inline execution a bounded lease derived from server-owned wall budget."""
    wall = max(1, int(dict(requested_budget or {}).get("tool_wall_seconds") or 1))
    return max(90, min(3_600, wall + 30))


def terminalize_hunt_capability(
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
) -> tuple[DurableBudgetReservation, CapabilityReceipt]:
    """Build one matching terminal reservation and content-addressed receipt."""
    status = str(action_status or "failed").strip().lower()
    successful = status in {"completed", "partial"}
    reservation_state = "committed" if successful else "failed"
    receipt_status = {
        "completed": "succeeded",
        "partial": "partial",
        "blocked": "blocked",
    }.get(status, "failed")
    result_item = dict(result or {})
    error = str(result_item.get("error") or "").strip()
    receipt_observations = result_item.get("receipt_observations")
    if isinstance(receipt_observations, (list, tuple)):
        observations = tuple(
            dict(item) for item in receipt_observations if isinstance(item, Mapping)
        )
    else:
        observations = ({
            "kind": "hunt_capability_result",
            "status": status,
            "ok": bool(result_item.get("ok")),
        },)
    terminal_at = datetime.fromisoformat(str(finished_at).replace("Z", "+00:00"))
    receipt = CapabilityReceipt(
        receipt_id=str(receipt_id),
        capability_name=str(capability_name),
        adapter_name=str(adapter_name),
        adapter_version=str(adapter_version),
        target_id=str(target_id),
        hunt_id=running.owner_id,
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
        errors=(error,) if error else (),
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
            reason="capability_blocked" if status == "blocked" else "capability_failed",
            actual=actual_budget,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=True,
            now=terminal_at,
        )
    return terminal, receipt
