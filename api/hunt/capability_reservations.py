"""Durable reservation contracts for inline canonical Hunt capabilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

try:
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from runtime.capability_settlement import terminalize_capability_reservation
    from runtime.receipts import CapabilityReceipt
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.budget_reservations import DurableBudgetReservation
    from ..runtime.capability_registry import CAPABILITY_REGISTRY
    from ..runtime.capability_settlement import terminalize_capability_reservation
    from ..runtime.receipts import CapabilityReceipt


def _hunt_executor_names(executor: str) -> frozenset[str]:
    return frozenset(
        spec.name for spec in CAPABILITY_REGISTRY.for_hunt_executor(executor)
    )


# Compatibility constant names remain local to the implementation, but their membership is
# derived exclusively from the canonical registry instead of forming a second routing catalog.
DURABLE_INLINE_HUNT_CAPABILITIES = _hunt_executor_names("inline")
DURABLE_DEVICE_CONTROL_HUNT_CAPABILITIES = _hunt_executor_names("device_control")
DURABLE_DEVICE_HTTP_HUNT_CAPABILITIES = _hunt_executor_names("device_http")
DURABLE_DEVICE_QUEUE_HUNT_CAPABILITIES = _hunt_executor_names("device_queue")
DURABLE_DEVICE_SSH_PROPOSAL_HUNT_CAPABILITIES = _hunt_executor_names(
    "device_ssh_proposal"
)
DURABLE_WORKER_HUNT_CAPABILITIES = _hunt_executor_names("worker_network")
DURABLE_BROWSER_HUNT_CAPABILITIES = _hunt_executor_names("worker_browser")
DURABLE_SCANNER_HUNT_CAPABILITIES = _hunt_executor_names("worker_scanner")
DURABLE_AUTH_HUNT_CAPABILITIES = _hunt_executor_names("worker_auth")
DURABLE_HTTP_HUNT_CAPABILITIES = _hunt_executor_names("worker_http")


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
    if running.owner_kind != "hunt":
        raise ValueError("Hunt capability settlement requires a Hunt reservation")
    return terminalize_capability_reservation(
        running,
        action_digest=action_digest,
        capability_name=capability_name,
        adapter_name=adapter_name,
        adapter_version=adapter_version,
        target_id=target_id,
        target_kind=target_kind,
        capability_input=capability_input,
        action_status=action_status,
        actual_budget=actual_budget,
        worker_id=worker_id,
        started_at=started_at,
        finished_at=finished_at,
        receipt_id=receipt_id,
        parser_version=parser_version,
        scope_receipt_id=scope_receipt_id,
        approval_receipt_id=approval_receipt_id,
        result=result,
        fallback_observation_kind="hunt_capability_result",
    )
