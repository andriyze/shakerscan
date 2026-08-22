"""Durable ``scan.execute`` authority for outbound-only broker workers.

The remote worker deliberately has no PostgreSQL credentials.  The control plane
therefore owns the reservation lifecycle and gives the worker only a lease-bound,
secret-free runtime envelope.  Transport heartbeats renew the same durable action;
result submission terminalizes its receipt and owner ledger transactionally.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Mapping
import uuid

try:
    from capabilities.scan import measure_deterministic_scan_result
    from runtime.budget_reservations import DurableBudgetReservation
    from runtime.budgets import BudgetExceeded
    from runtime.capability_settlement import terminalize_capability_reservation
    from runtime.receipts import CapabilityReceipt
    from runtime.reservation_store import (
        PostgresBudgetReservationStore,
        StoredBudgetReservation,
    )
except ModuleNotFoundError:  # package imports in host-side tests
    from ..capabilities.scan import measure_deterministic_scan_result
    from ..runtime.budget_reservations import DurableBudgetReservation
    from ..runtime.budgets import BudgetExceeded
    from ..runtime.capability_settlement import terminalize_capability_reservation
    from ..runtime.receipts import CapabilityReceipt
    from ..runtime.reservation_store import (
        PostgresBudgetReservationStore,
        StoredBudgetReservation,
    )

from .capability_execution import (
    prepare_scan_process_capability,
    scan_budget_ledger_limits,
    scan_capability_action_digest,
)


BROKER_SCAN_ACTION_ID = "deterministic_scan.execute"
BROKER_SCAN_EXECUTION_SCHEMA = "broker-scan-execution-reservation/v1"


class BrokerScanExecutionError(RuntimeError):
    """A remote deterministic Scan cannot safely use its durable authority."""


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise BrokerScanExecutionError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise BrokerScanExecutionError(f"{name} must be an object")
    return dict(value)


@dataclass(frozen=True)
class BrokerScanExecutionLease:
    reservation_id: str
    action_digest: str
    execution_plan_digest: str
    target_binding_digest: str
    worker_id: str
    runtime_budget: Mapping[str, int]
    requested_budget: Mapping[str, int]
    lease_seconds: int
    target_id: str
    target_kind: str
    scope_receipt_id: str | None
    approval_receipt_id: str | None
    capability_input: Mapping[str, Any]
    parser_version: str

    def remote_payload(self) -> dict[str, Any]:
        """Return the minimum secret-free envelope executable by the node."""
        return {
            "schema_version": BROKER_SCAN_EXECUTION_SCHEMA,
            "reservation_id": self.reservation_id,
            "action_id": BROKER_SCAN_ACTION_ID,
            "action_digest": self.action_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "target_binding_digest": self.target_binding_digest,
            "runtime_budget": dict(self.runtime_budget),
            "requested_budget": dict(self.requested_budget),
        }

    def storage_payload(self) -> dict[str, Any]:
        return {
            **self.remote_payload(),
            "worker_id": self.worker_id,
            "lease_seconds": self.lease_seconds,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "scope_receipt_id": self.scope_receipt_id,
            "approval_receipt_id": self.approval_receipt_id,
            "capability_input": dict(self.capability_input),
            "parser_version": self.parser_version,
        }


@dataclass(frozen=True)
class BrokerScanExecutionAdmission:
    lease: BrokerScanExecutionLease | None
    stored: StoredBudgetReservation
    idempotent_redelivery: bool = False


def _receipt_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: receipt.get(key)
        for key in (
            "receipt_id",
            "receipt_hash",
            "input_digest",
            "budget_reservation_id",
            "budget_reservation_state",
        )
        if receipt.get(key) is not None
    }


def broker_scan_execution_summary(
    stored: StoredBudgetReservation,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    return {
        "schema_version": "deterministic-scan-execution-receipt/v1",
        "capability_name": "scan.execute",
        "status": str(receipt.get("status") or "failed"),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "budget_consumed": dict(stored.record.actual),
        "receipt": _receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
        "transport": "broker",
    }


def _validate_stored(
    stored: StoredBudgetReservation,
    metadata: Mapping[str, Any],
    *,
    require_running: bool,
) -> None:
    expected_requested = {
        str(name): int(amount)
        for name, amount in _json_object(
            metadata.get("requested_budget"), name="requested_budget"
        ).items()
    }
    if (
        stored.record.owner_kind != "scan"
        or stored.record.capability_name != "scan.execute"
        or stored.action_id != BROKER_SCAN_ACTION_ID
        or stored.action_digest != str(metadata.get("action_digest") or "")
        or stored.record.reservation_id
        != str(metadata.get("reservation_id") or "")
        or dict(stored.record.requested) != expected_requested
    ):
        raise BrokerScanExecutionError(
            "broker Scan reservation does not match its server-owned lease"
        )
    if require_running and (
        stored.record.status != "running"
        or stored.record.worker_id != str(metadata.get("worker_id") or "")
    ):
        raise BrokerScanExecutionError(
            "broker Scan reservation is no longer owned by this worker"
        )


async def reserve_broker_scan_execution(
    conn: Any,
    *,
    scan_id: str,
    plan: Any,
    execution: Any,
    worker_id: str,
    lease_seconds: int,
    allocation_limits: Mapping[str, int] | None = None,
    store: PostgresBudgetReservationStore | None = None,
) -> BrokerScanExecutionAdmission:
    """Reserve and start one broker Scan before the lease reaches the node."""
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BrokerScanExecutionError("broker Scan owner ID is invalid") from exc
    repository = store or PostgresBudgetReservationStore()
    locked = await conn.fetchrow(
        "SELECT status, policy_json, budget_json, budget_used_json "
        "FROM scans WHERE id=$1 FOR UPDATE",
        scan_uuid,
    )
    if not locked or str(locked["status"] or "") not in {
        "pending", "queued", "running",
    }:
        raise BrokerScanExecutionError(
            "broker Scan stopped before durable capability admission"
        )
    canonical_plan = plan.canonical_dict()
    if (
        _json_object(locked["policy_json"], name="Scan policy")
        != canonical_plan["policy"]
        or _json_object(locked["budget_json"], name="Scan budget")
        != canonical_plan["budget"]
    ):
        raise BrokerScanExecutionError(
            "persisted Scan authority changed before broker execution"
        )
    existing = await repository.load_by_action(
        conn,
        owner_kind="scan",
        owner_id=scan_id,
        action_id=BROKER_SCAN_ACTION_ID,
        for_update=True,
    )
    if existing is not None:
        if existing.record.terminal:
            receipt = dict(existing.receipt or {})
            redacted = _json_object(
                receipt.get("redacted_execution"),
                name="terminal receipt execution",
            ) if receipt else {}
            receipt_input = _json_object(
                redacted.get("input"), name="terminal receipt input",
            ) if redacted else {}
            trustworthy_receipt = bool(
                receipt
                and receipt.get("capability_name") == "scan.execute"
                and str(receipt.get("scan_id") or "") == scan_id
                and str(receipt.get("target_id") or "")
                == execution.target_binding.target_id
                and receipt_input.get("execution_plan_digest") == plan.digest
                and receipt_input.get("target_binding_digest")
                == execution.target_binding.digest
                and dict(receipt.get("budget_reserved") or {})
                == dict(existing.record.requested)
                and str(receipt.get("receipt_hash") or "")
                == str(existing.record.execution_receipt_hash or "")
                and str(receipt.get("input_digest") or "")
                == existing.action_digest
            )
            if (
                not trustworthy_receipt
                and not existing.record.execution_uncertain
                and existing.record.status != "released"
            ):
                raise BrokerScanExecutionError(
                    "broker Scan terminal reservation lacks a trustworthy receipt"
                )
            return BrokerScanExecutionAdmission(
                lease=None, stored=existing, idempotent_redelivery=True,
            )
        raise BrokerScanExecutionError(
            "broker Scan already has an active deterministic reservation"
        )

    effective_budget = execution.payload()["execution_budget"]
    limits = scan_budget_ledger_limits(
        effective_budget,
        allow_zero=execution.shard_authority is not None,
    )
    used = _json_object(locked["budget_used_json"], name="Scan budget ledger")
    current_ledger = {name: int(used.get(name) or 0) for name in limits}
    prepared, runtime_budget = prepare_scan_process_capability(
        execution_plan_digest=plan.digest,
        target=execution.target_binding,
        stage_rows=execution.stage_rows(),
        ledger_limits=limits,
        consumed=current_ledger,
        allow_state_changing_http=bool(
            plan.policy.active_testing
            and plan.policy.allow_state_changing_http
        ),
        allocation_limits=allocation_limits,
    )
    action_digest = scan_capability_action_digest(
        scan_id=scan_id,
        execution_plan_digest=plan.digest,
        target=execution.target_binding,
        prepared=prepared,
    )
    requested = DurableBudgetReservation.request(
        owner_kind="scan",
        owner_id=scan_id,
        capability_name="scan.execute",
        amounts=prepared.estimated_budget,
        reservation_id=str(uuid.uuid4()),
    )
    stored = await repository.create_requested(
        conn,
        action_id=BROKER_SCAN_ACTION_ID,
        action_digest=action_digest,
        record=requested,
    )
    try:
        reserved, held_ledger = stored.record.reserve_against(
            limits=limits,
            consumed=current_ledger,
            lease_seconds=max(30, int(lease_seconds)),
        )
    except BudgetExceeded as exc:
        finished_at = datetime.now(timezone.utc)
        zero_actual = {name: 0 for name in stored.record.requested}
        receipt = CapabilityReceipt(
            receipt_id=str(uuid.uuid4()),
            capability_name="scan.execute",
            adapter_name=prepared.adapter_name,
            adapter_version=prepared.adapter_version,
            target_id=execution.target_binding.target_id,
            scan_id=scan_id,
            worker_id=worker_id,
            scope_receipt_id=execution.target_binding.scope_receipt_id,
            approval_receipt_id=plan.policy.approval_receipt_id,
            status="blocked",
            input_digest=action_digest,
            parser_version=prepared.parser_version,
            started_at=finished_at.isoformat(),
            finished_at=finished_at.isoformat(),
            redacted_execution=dict(prepared.redacted_execution),
            budget_reservation_id=stored.record.reservation_id,
            budget_reservation_state="failed",
            budget_reserved=stored.record.requested,
            budget_consumed=zero_actual,
            observations=(),
            errors=(
                "budget_exhausted:"
                + next(iter(exc.shortages), "unknown"),
            ),
        )
        failed = stored.record.fail(
            reason="budget_exhausted_before_execution",
            actual=zero_actual,
            execution_receipt_hash=receipt.receipt_hash,
            execution_may_have_started=False,
            now=finished_at,
        )
        terminal = await repository.persist_terminal(
            conn,
            previous=stored,
            terminal=failed,
            ledger_after_settlement=current_ledger,
            receipt=receipt,
        )
        return BrokerScanExecutionAdmission(lease=None, stored=terminal)

    stored = await repository.persist_transition(
        conn,
        previous=stored,
        current=reserved,
        ledger_after_hold=held_ledger,
    )
    used.update(held_ledger)
    await conn.execute(
        "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
        scan_uuid,
        json.dumps(used, sort_keys=True, separators=(",", ":")),
    )
    running = stored.record.start(
        worker_id=worker_id,
        lease_seconds=max(30, int(lease_seconds)),
    )
    stored = await repository.persist_transition(
        conn, previous=stored, current=running,
    )
    lease = BrokerScanExecutionLease(
        reservation_id=running.reservation_id,
        action_digest=action_digest,
        execution_plan_digest=plan.digest,
        target_binding_digest=execution.target_binding.digest,
        worker_id=worker_id,
        runtime_budget=runtime_budget,
        requested_budget=running.requested,
        lease_seconds=max(30, int(lease_seconds)),
        target_id=execution.target_binding.target_id,
        target_kind=execution.target_binding.target_kind,
        scope_receipt_id=execution.target_binding.scope_receipt_id,
        approval_receipt_id=plan.policy.approval_receipt_id,
        capability_input=prepared.redacted_execution,
        parser_version=prepared.parser_version,
    )
    return BrokerScanExecutionAdmission(lease=lease, stored=stored)


async def heartbeat_broker_scan_execution(
    conn: Any,
    *,
    metadata: Mapping[str, Any],
    lease_seconds: int,
    store: PostgresBudgetReservationStore | None = None,
) -> StoredBudgetReservation:
    repository = store or PostgresBudgetReservationStore()
    stored = await repository.load(
        conn, str(metadata.get("reservation_id") or ""), for_update=True,
    )
    if stored is None:
        raise BrokerScanExecutionError("broker Scan reservation is missing")
    _validate_stored(stored, metadata, require_running=True)
    try:
        owner_id = uuid.UUID(stored.record.owner_id)
    except ValueError as exc:
        raise BrokerScanExecutionError("broker Scan owner ID is invalid") from exc
    owner_status = await conn.fetchval(
        "SELECT status FROM scans WHERE id=$1 FOR UPDATE", owner_id,
    )
    if str(owner_status or "") not in {"running", "cancelled"}:
        raise BrokerScanExecutionError(
            "broker Scan owner is no longer executable"
        )
    heartbeat = stored.record.heartbeat(
        worker_id=str(metadata.get("worker_id") or ""),
        lease_seconds=max(30, int(lease_seconds)),
    )
    return await repository.persist_transition(
        conn, previous=stored, current=heartbeat,
    )


async def settle_broker_scan_execution(
    conn: Any,
    *,
    metadata: Mapping[str, Any],
    result: Mapping[str, Any],
    store: PostgresBudgetReservationStore | None = None,
) -> tuple[StoredBudgetReservation, dict[str, Any]]:
    """Persist the terminal receipt and reconcile the Scan ledger atomically."""
    repository = store or PostgresBudgetReservationStore()
    stored = await repository.load(
        conn, str(metadata.get("reservation_id") or ""), for_update=True,
    )
    if stored is None:
        raise BrokerScanExecutionError("broker Scan reservation is missing")
    _validate_stored(stored, metadata, require_running=not stored.record.terminal)
    if stored.record.terminal:
        receipt = dict(stored.receipt or {})
        if (
            not receipt
            or str(receipt.get("receipt_hash") or "")
            != str(stored.record.execution_receipt_hash or "")
            or str(receipt.get("input_digest") or "")
            != stored.action_digest
        ):
            raise BrokerScanExecutionError(
                "broker Scan terminal receipt is not trustworthy"
            )
        return stored, broker_scan_execution_summary(
            stored, idempotent_redelivery=True,
        )

    try:
        owner_id = uuid.UUID(stored.record.owner_id)
    except ValueError as exc:
        raise BrokerScanExecutionError("broker Scan owner ID is invalid") from exc
    owner = await conn.fetchrow(
        "SELECT status, budget_used_json FROM scans WHERE id=$1 FOR UPDATE",
        owner_id,
    )
    if not owner:
        raise BrokerScanExecutionError("broker Scan owner disappeared")
    if str(owner["status"] or "") not in {"running", "cancelled"}:
        raise BrokerScanExecutionError(
            "broker Scan owner no longer accepts execution results"
        )
    requested = dict(stored.record.requested)
    try:
        measured = measure_deterministic_scan_result(
            result,
            requested_budget=requested,
            # The control plane cannot independently prove remote wall time. Full
            # hold is the conservative settlement required by the V2 contract.
            elapsed_seconds=float(requested.get("tool_wall_seconds") or 0),
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise BrokerScanExecutionError(
            "broker Scan result contains invalid budget evidence"
        ) from exc
    action_status = (
        "cancelled" if str(owner["status"] or "") == "cancelled"
        else "completed" if measured.status == "success"
        else "partial" if measured.status == "partial"
        else "cancelled" if measured.status == "cancelled"
        else "blocked" if measured.status == "blocked"
        else "failed"
    )
    now = datetime.now(timezone.utc)
    started_at = stored.record.started_at or now
    terminal, receipt = terminalize_capability_reservation(
        stored.record,
        action_digest=stored.action_digest,
        capability_name="scan.execute",
        adapter_name="scanner.dast",
        adapter_version="1",
        parser_version=(
            measured.parser_version
            or str(metadata.get("parser_version") or "scan-report/v2")
        ),
        target_id=str(metadata.get("target_id") or ""),
        target_kind=str(metadata.get("target_kind") or "web"),
        capability_input=_json_object(
            metadata.get("capability_input"), name="capability_input"
        ),
        action_status=action_status,
        actual_budget=measured.actual_budget,
        worker_id=str(metadata.get("worker_id") or ""),
        started_at=started_at.isoformat(),
        finished_at=now.isoformat(),
        receipt_id=str(uuid.uuid4()),
        scope_receipt_id=metadata.get("scope_receipt_id"),
        approval_receipt_id=metadata.get("approval_receipt_id"),
        result={
            "ok": measured.status == "success",
            "error": measured.errors[0] if measured.errors else None,
            "receipt_errors": list(measured.errors),
            "timed_out": measured.timed_out,
            "execution_started": measured.execution_started,
            "receipt_observations": list(measured.observations),
        },
    )
    used = _json_object(owner["budget_used_json"], name="Scan budget ledger")
    ledger = {
        name: int(used.get(name) or 0)
        for name in stored.record.requested
    }
    reconciled = terminal.reconcile_consumed(ledger)
    used.update(reconciled)
    settled = await repository.persist_terminal(
        conn,
        previous=stored,
        terminal=terminal,
        ledger_after_settlement=used,
        receipt=receipt,
    )
    await conn.execute(
        "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
        owner_id,
        json.dumps(used, sort_keys=True, separators=(",", ":")),
    )
    return settled, broker_scan_execution_summary(
        settled, idempotent_redelivery=False,
    )


__all__ = (
    "BROKER_SCAN_ACTION_ID",
    "BROKER_SCAN_EXECUTION_SCHEMA",
    "BrokerScanExecutionAdmission",
    "BrokerScanExecutionError",
    "BrokerScanExecutionLease",
    "broker_scan_execution_summary",
    "heartbeat_broker_scan_execution",
    "reserve_broker_scan_execution",
    "settle_broker_scan_execution",
)
