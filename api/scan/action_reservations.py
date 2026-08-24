"""Transactional budget authority for one immutable canonical Scan action."""

from __future__ import annotations

from dataclasses import replace
import json
from typing import Any, Mapping
import uuid

try:
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.budgets import BudgetExceeded
    from runtime.receipts import CapabilityReceipt
    from runtime.reservation_store import (
        PostgresBudgetReservationStore,
        StoredBudgetReservation,
    )
except ModuleNotFoundError:  # package imports in host-side tests
    from ..runtime.budget_reservations import DurableBudgetReservation
    from ..runtime.budgets import BudgetExceeded
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.reservation_store import (
        PostgresBudgetReservationStore,
        StoredBudgetReservation,
    )

from .action_plan import ScanAction, ScanActionPlan
from .capability_execution import scan_budget_ledger_limits


class ScanActionReservationError(RuntimeError):
    """Action and shared budget authority could not transition together."""


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ScanActionReservationError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ScanActionReservationError(f"{name} must be an object")
    return dict(value)


def _validate_stored(
    stored: StoredBudgetReservation,
    *,
    plan: ScanActionPlan,
    action: ScanAction,
) -> None:
    if (
        stored.record.owner_kind != "scan"
        or stored.record.owner_id != plan.scan_id
        or stored.action_id != action.action_id
        or stored.action_digest != action.action_digest
        or stored.record.capability_name != action.capability_name
        or dict(stored.record.requested) != dict(action.requested_budget)
    ):
        raise ScanActionReservationError(
            "Scan action reservation conflicts with immutable plan authority"
        )


def _aggregate_owner_uuid(
    aggregate_owner_id: str | None,
    *,
    plan: ScanActionPlan,
) -> uuid.UUID | None:
    if not aggregate_owner_id:
        return None
    try:
        owner_id = uuid.UUID(str(aggregate_owner_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanActionReservationError(
            "parallel aggregate Scan owner is invalid"
        ) from exc
    if str(owner_id) == plan.scan_id:
        raise ScanActionReservationError(
            "parallel aggregate Scan owner must differ from its child"
        )
    return owner_id


def _ledger(
    owner: Mapping[str, Any],
    *,
    budget_required: bool,
) -> tuple[dict[str, int], dict[str, Any]]:
    limits = (
        scan_budget_ledger_limits(
            _json_object(owner.get("budget_json"), name="Scan budget"),
            allow_zero=True,
        )
        if budget_required else {}
    )
    used = _json_object(owner.get("budget_used_json"), name="Scan budget ledger")
    return limits, used


async def admit_and_start_scan_action_reservation(
    conn: Any,
    *,
    plan: ScanActionPlan,
    action: ScanAction,
    worker_id: str,
    lease_seconds: int,
    aggregate_owner_id: str | None = None,
    store: PostgresBudgetReservationStore | None = None,
) -> StoredBudgetReservation:
    """Apply a hold and start its worker lease under the Scan owner lock."""
    repository = store or PostgresBudgetReservationStore()
    aggregate_uuid = _aggregate_owner_uuid(aggregate_owner_id, plan=plan)
    aggregate_owner = None
    if aggregate_uuid is not None:
        aggregate_owner = await conn.fetchrow(
            "SELECT status, budget_json, budget_used_json "
            "FROM scans WHERE id=$1 FOR UPDATE",
            aggregate_uuid,
        )
        if not aggregate_owner or str(aggregate_owner.get("status") or "") not in {
            "pending", "queued", "running", "cancelling", "cancelled",
        }:
            raise ScanActionReservationError(
                "parallel parent Scan stopped before action budget admission"
            )
    owner = await conn.fetchrow(
        "SELECT status, budget_json, budget_used_json "
        "FROM scans WHERE id=$1 FOR UPDATE",
        uuid.UUID(plan.scan_id),
    )
    if not owner or str(owner.get("status") or "") not in {
        "pending", "queued", "running", "cancelling", "cancelled",
    }:
        raise ScanActionReservationError(
            "Scan stopped before action budget admission"
        )
    limits, used = _ledger(owner, budget_required=True)
    ledger = {name: int(used.get(name) or 0) for name in limits}
    aggregate_limits: dict[str, int] = {}
    aggregate_used: dict[str, Any] = {}
    aggregate_ledger: dict[str, int] = {}
    if aggregate_owner is not None:
        aggregate_limits, aggregate_used = _ledger(
            aggregate_owner, budget_required=True,
        )
        aggregate_ledger = {
            name: int(aggregate_used.get(name) or 0)
            for name in aggregate_limits
        }
    stored = await repository.load_by_action(
        conn,
        owner_kind="scan",
        owner_id=plan.scan_id,
        action_id=action.action_id,
        for_update=True,
    )
    if stored is None:
        requested = DurableBudgetReservation.request(
            owner_kind="scan",
            owner_id=plan.scan_id,
            capability_name=action.capability_name,
            amounts=action.requested_budget,
            reservation_id=str(uuid.uuid4()),
            allow_empty=not bool(action.requested_budget),
        )
        stored = await repository.create_requested(
            conn,
            action_id=action.action_id,
            action_digest=action.action_digest,
            record=requested,
        )
    _validate_stored(stored, plan=plan, action=action)
    if stored.record.terminal:
        return stored
    if stored.record.status == "requested":
        try:
            reserved, held_ledger = stored.record.reserve_against(
                limits=limits,
                consumed=ledger,
                lease_seconds=lease_seconds,
            )
            aggregate_held = None
            if aggregate_owner is not None:
                _aggregate_reserved, aggregate_held = stored.record.reserve_against(
                    limits=aggregate_limits,
                    consumed=aggregate_ledger,
                    lease_seconds=lease_seconds,
                )
        except BudgetExceeded as exc:
            raise ScanActionReservationError(
                "Scan action exceeds the remaining durable budget: "
                + ",".join(sorted(exc.shortages))
            ) from exc
        stored = await repository.persist_transition(
            conn,
            previous=stored,
            current=reserved,
            ledger_after_hold=held_ledger,
        )
        used.update(held_ledger)
        await conn.execute(
            "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
            uuid.UUID(plan.scan_id),
            json.dumps(used, sort_keys=True, separators=(",", ":")),
        )
        if aggregate_owner is not None and aggregate_held is not None:
            aggregate_used.update(aggregate_held)
            await conn.execute(
                "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
                aggregate_uuid,
                json.dumps(
                    aggregate_used, sort_keys=True, separators=(",", ":"),
                ),
            )
    if stored.record.status != "reserved":
        raise ScanActionReservationError(
            "Scan action already has an active budget execution lease"
        )
    try:
        running = stored.record.start(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )
    except ValueError as exc:
        raise ScanActionReservationError(
            "Scan action budget lease expired before execution"
        ) from exc
    return await repository.persist_transition(
        conn, previous=stored, current=running,
    )


async def heartbeat_scan_action_reservation(
    conn: Any,
    *,
    plan: ScanActionPlan,
    action: ScanAction,
    worker_id: str,
    lease_seconds: int,
    aggregate_owner_id: str | None = None,
    store: PostgresBudgetReservationStore | None = None,
) -> StoredBudgetReservation:
    """Renew the reservation while holding the same Scan owner lock order."""
    repository = store or PostgresBudgetReservationStore()
    aggregate_uuid = _aggregate_owner_uuid(aggregate_owner_id, plan=plan)
    if aggregate_uuid is not None:
        aggregate_status = await conn.fetchval(
            "SELECT status FROM scans WHERE id=$1 FOR UPDATE",
            aggregate_uuid,
        )
        if str(aggregate_status or "") not in {"running", "cancelled"}:
            raise ScanActionReservationError(
                "parallel parent Scan is no longer executable"
            )
    status = await conn.fetchval(
        "SELECT status FROM scans WHERE id=$1 FOR UPDATE",
        uuid.UUID(plan.scan_id),
    )
    if str(status or "") not in {"running", "cancelled"}:
        raise ScanActionReservationError("Scan owner is no longer executable")
    stored = await repository.load_by_action(
        conn,
        owner_kind="scan",
        owner_id=plan.scan_id,
        action_id=action.action_id,
        for_update=True,
    )
    if stored is None:
        raise ScanActionReservationError("Scan action reservation is missing")
    _validate_stored(stored, plan=plan, action=action)
    try:
        heartbeat = stored.record.heartbeat(
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )
    except ValueError as exc:
        raise ScanActionReservationError(
            "Scan action budget heartbeat lost durable authority"
        ) from exc
    return await repository.persist_transition(
        conn, previous=stored, current=heartbeat,
    )


async def settle_scan_action_reservation(
    conn: Any,
    *,
    plan: ScanActionPlan,
    action: ScanAction,
    worker_id: str,
    receipt: CapabilityReceipt,
    aggregate_owner_id: str | None = None,
    store: PostgresBudgetReservationStore | None = None,
) -> tuple[StoredBudgetReservation, CapabilityReceipt]:
    """Terminalize a raw worker receipt and reconcile its hold atomically."""
    if receipt.budget_reservation_id or receipt.budget_reservation_state:
        raise ScanActionReservationError(
            "worker receipt may not claim control-plane budget settlement"
        )
    repository = store or PostgresBudgetReservationStore()
    aggregate_uuid = _aggregate_owner_uuid(aggregate_owner_id, plan=plan)
    aggregate_owner = None
    if aggregate_uuid is not None:
        aggregate_owner = await conn.fetchrow(
            "SELECT status, budget_used_json FROM scans WHERE id=$1 FOR UPDATE",
            aggregate_uuid,
        )
        if not aggregate_owner or str(aggregate_owner.get("status") or "") not in {
            "running", "cancelled",
        }:
            raise ScanActionReservationError(
                "parallel parent Scan no longer accepts action results"
            )
    owner = await conn.fetchrow(
        "SELECT status, budget_used_json FROM scans WHERE id=$1 FOR UPDATE",
        uuid.UUID(plan.scan_id),
    )
    if not owner or str(owner.get("status") or "") not in {"running", "cancelled"}:
        raise ScanActionReservationError(
            "Scan owner no longer accepts action results"
        )
    stored = await repository.load_by_action(
        conn,
        owner_kind="scan",
        owner_id=plan.scan_id,
        action_id=action.action_id,
        for_update=True,
    )
    if stored is None:
        raise ScanActionReservationError("Scan action reservation is missing")
    _validate_stored(stored, plan=plan, action=action)
    if stored.record.status != "running" or stored.record.worker_id != worker_id:
        raise ScanActionReservationError(
            "Scan action reservation is no longer owned by this worker"
        )
    raw_status = receipt.status.strip().lower()
    successful = raw_status in {
        "completed", "partial", "success", "succeeded", "timed_out",
    } or receipt.timed_out
    reservation_state = "committed" if successful else "failed"
    linked_receipt = replace(
        receipt,
        budget_reservation_id=stored.record.reservation_id,
        budget_reservation_state=reservation_state,
    )
    try:
        if successful:
            terminal = stored.record.commit(
                actual=linked_receipt.budget_consumed,
                execution_receipt_hash=linked_receipt.receipt_hash,
                worker_id=worker_id,
            )
        else:
            failure_reason = {
                "blocked": "action_blocked",
                "cancelled": "action_cancelled",
                "skipped": "action_skipped",
            }.get(raw_status, "action_failed")
            terminal = stored.record.fail(
                reason=failure_reason,
                actual=linked_receipt.budget_consumed,
                execution_receipt_hash=linked_receipt.receipt_hash,
                execution_may_have_started=bool(
                    linked_receipt.redacted_execution.get(
                        "execution_started", True,
                    )
                ),
            )
    except ValueError as exc:
        raise ScanActionReservationError(
            "Scan action budget settlement lost durable authority"
        ) from exc
    used = _json_object(owner.get("budget_used_json"), name="Scan budget ledger")
    ledger = {
        name: int(used.get(name) or 0)
        for name in stored.record.requested
    }
    reconciled = terminal.reconcile_consumed(ledger)
    used.update(reconciled)
    aggregate_used: dict[str, Any] | None = None
    if aggregate_owner is not None:
        aggregate_used = _json_object(
            aggregate_owner.get("budget_used_json"),
            name="parallel parent Scan budget ledger",
        )
        aggregate_ledger = {
            name: int(aggregate_used.get(name) or 0)
            for name in stored.record.requested
        }
        aggregate_used.update(terminal.reconcile_consumed(aggregate_ledger))
    settled = await repository.persist_terminal(
        conn,
        previous=stored,
        terminal=terminal,
        ledger_after_settlement=used,
        receipt=linked_receipt,
    )
    await conn.execute(
        "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
        uuid.UUID(plan.scan_id),
        json.dumps(used, sort_keys=True, separators=(",", ":")),
    )
    if aggregate_used is not None:
        await conn.execute(
            "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
            aggregate_uuid,
            json.dumps(
                aggregate_used, sort_keys=True, separators=(",", ":"),
            ),
        )
    return settled, linked_receipt


__all__ = (
    "ScanActionReservationError",
    "admit_and_start_scan_action_reservation",
    "heartbeat_scan_action_reservation",
    "settle_scan_action_reservation",
)
