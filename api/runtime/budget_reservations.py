"""Durable reservation-state transitions for Scan and Hunt capability budgets.

This module is datastore-agnostic by design. A caller locks the owning Scan/Hunt row,
persists each returned immutable record, and applies ``reconcile_consumed`` to the
shared ledger in the same transaction. Recovery is conservative: a stale operation
that may have reached the target is never blindly refunded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Literal, Mapping
from uuid import uuid4

from .budgets import (
    BUDGET_DIMENSIONS,
    BudgetError,
    reconcile_budget_snapshot,
    reserve_budget_snapshot,
)


ReservationStatus = Literal[
    "requested", "reserved", "running", "committed", "released", "failed"
]
OwnerKind = Literal["scan", "hunt"]
TERMINAL_RESERVATION_STATUSES = frozenset({"committed", "released", "failed"})
_RECEIPT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,119}$")


class ReservationTransitionError(BudgetError):
    """The requested durable reservation transition is invalid."""


def _utc(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ReservationTransitionError("reservation timestamps must be timezone-aware")
    return result.astimezone(timezone.utc)


def _amounts(
    values: Mapping[str, int], *, allow_zero: bool = False,
    allowed: frozenset[str] = BUDGET_DIMENSIONS,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw_kind, raw_value in values.items():
        kind = str(raw_kind or "").strip()
        if kind not in allowed:
            raise ReservationTransitionError(f"unknown budget dimension: {kind}")
        if isinstance(raw_value, bool):
            raise ReservationTransitionError(f"budget amount for {kind} must be an integer")
        try:
            amount = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise ReservationTransitionError(
                f"budget amount for {kind} must be an integer"
            ) from exc
        if amount < 0:
            raise ReservationTransitionError(
                f"budget amount for {kind} must be non-negative"
            )
        if amount or allow_zero:
            result[kind] = amount
    return result


def _receipt_hash(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower() or None
    if normalized is not None and not _RECEIPT_HASH_RE.fullmatch(normalized):
        raise ReservationTransitionError(
            "execution receipt hash must be 64 lowercase hex characters"
        )
    return normalized


def _reason(value: str | None, *, default: str) -> str:
    normalized = str(value or default).strip().lower()
    if not _REASON_RE.fullmatch(normalized):
        raise ReservationTransitionError(
            "reservation reason must be a bounded machine-readable code"
        )
    return normalized


@dataclass(frozen=True)
class DurableBudgetReservation:
    """Immutable record persisted around one executable Scan/Hunt action."""

    reservation_id: str
    owner_kind: OwnerKind
    owner_id: str
    capability_name: str
    requested: Mapping[str, int]
    status: ReservationStatus = "requested"
    actual: Mapping[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = None
    hold_applied: bool = False
    lease_expires_at: datetime | None = None
    worker_id: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    execution_receipt_hash: str | None = None
    failure_reason: str | None = None
    execution_uncertain: bool = False
    version: int = 1

    def __post_init__(self) -> None:
        reservation_id = str(self.reservation_id or "").strip()
        owner_id = str(self.owner_id or "").strip()
        capability = str(self.capability_name or "").strip().lower()
        if not reservation_id or not owner_id or not capability:
            raise ReservationTransitionError(
                "reservation_id, owner_id, and capability_name are required"
            )
        if self.owner_kind not in {"scan", "hunt"}:
            raise ReservationTransitionError("owner_kind must be scan or hunt")
        if self.status not in {
            "requested", "reserved", "running", "committed", "released", "failed"
        }:
            raise ReservationTransitionError("invalid reservation status")
        requested = _amounts(self.requested)
        if not requested:
            raise ReservationTransitionError("reservation must hold at least one positive amount")
        actual = _amounts(self.actual or {}, allow_zero=True)
        outside = set(actual) - set(requested)
        if outside:
            raise ReservationTransitionError(
                f"actual usage contains unreserved dimensions: {sorted(outside)}"
            )
        for kind, amount in actual.items():
            if amount > requested[kind]:
                raise ReservationTransitionError(
                    f"actual usage exceeds reservation for {kind}"
                )
        created = _utc(self.created_at)
        updated = _utc(self.updated_at or created)
        lease = _utc(self.lease_expires_at) if self.lease_expires_at else None
        started = _utc(self.started_at) if self.started_at else None
        finished = _utc(self.finished_at) if self.finished_at else None
        receipt_hash = _receipt_hash(self.execution_receipt_hash)
        if self.version < 1:
            raise ReservationTransitionError("reservation version must be positive")
        if self.status == "requested" and self.hold_applied:
            raise ReservationTransitionError("requested reservation cannot already hold budget")
        if self.status in {"reserved", "running", "committed"} and not self.hold_applied:
            raise ReservationTransitionError(f"{self.status} reservation must hold budget")
        if self.status in {"requested", "reserved", "running"} and actual:
            raise ReservationTransitionError("non-terminal reservation cannot contain actual usage")
        if self.status == "requested" and any(
            value is not None for value in (lease, self.worker_id, started, finished, receipt_hash)
        ):
            raise ReservationTransitionError("requested reservation contains execution state")
        if self.status == "reserved" and (lease is None or self.worker_id or started or finished):
            raise ReservationTransitionError(
                "reserved reservation requires only an active lease"
            )
        if self.status == "running" and (not self.worker_id or not started or not lease):
            raise ReservationTransitionError(
                "running reservation requires worker_id, started_at, and lease_expires_at"
            )
        if self.status in TERMINAL_RESERVATION_STATUSES and not finished:
            raise ReservationTransitionError("terminal reservation requires finished_at")
        if self.status in TERMINAL_RESERVATION_STATUSES and lease is not None:
            raise ReservationTransitionError("terminal reservation cannot retain an active lease")
        if self.execution_uncertain and self.status != "failed":
            raise ReservationTransitionError("execution_uncertain is valid only for failed reservations")
        if self.execution_uncertain and not self.hold_applied:
            raise ReservationTransitionError("uncertain execution requires a previously applied hold")
        if self.status == "committed" and not receipt_hash:
            raise ReservationTransitionError("committed reservation requires an execution receipt hash")
        if self.status == "released" and any(actual.values()):
            raise ReservationTransitionError("released reservation must settle all dimensions to zero")
        object.__setattr__(self, "reservation_id", reservation_id)
        object.__setattr__(self, "owner_id", owner_id)
        object.__setattr__(self, "capability_name", capability)
        object.__setattr__(self, "requested", requested)
        object.__setattr__(self, "actual", actual)
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        object.__setattr__(self, "lease_expires_at", lease)
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "finished_at", finished)
        object.__setattr__(self, "execution_receipt_hash", receipt_hash)

    @classmethod
    def request(
        cls,
        *,
        owner_kind: OwnerKind,
        owner_id: str,
        capability_name: str,
        amounts: Mapping[str, int],
        now: datetime | None = None,
        reservation_id: str | None = None,
    ) -> "DurableBudgetReservation":
        timestamp = _utc(now)
        return cls(
            reservation_id=reservation_id or str(uuid4()),
            owner_kind=owner_kind,
            owner_id=owner_id,
            capability_name=capability_name,
            requested=amounts,
            actual={},
            created_at=timestamp,
            updated_at=timestamp,
        )

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_RESERVATION_STATUSES

    def _require_status(self, *allowed: ReservationStatus) -> None:
        if self.status not in allowed:
            raise ReservationTransitionError(
                f"reservation is {self.status}; expected one of {', '.join(allowed)}"
            )

    def _next(self, now: datetime, **changes: Any) -> "DurableBudgetReservation":
        return replace(self, updated_at=_utc(now), version=self.version + 1, **changes)

    def reserve(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> "DurableBudgetReservation":
        self._require_status("requested")
        if isinstance(lease_seconds, bool) or int(lease_seconds) <= 0:
            raise ReservationTransitionError("lease_seconds must be a positive integer")
        timestamp = _utc(now)
        return self._next(
            timestamp,
            status="reserved",
            hold_applied=True,
            lease_expires_at=timestamp + timedelta(seconds=int(lease_seconds)),
        )

    def reserve_against(
        self,
        *,
        limits: Mapping[str, int],
        consumed: Mapping[str, int],
        now: datetime | None = None,
        lease_seconds: int = 120,
    ) -> tuple["DurableBudgetReservation", dict[str, int]]:
        """Atomically-computable hold transition for a datastore row lock."""
        self._require_status("requested")
        held_ledger = reserve_budget_snapshot(limits, consumed, self.requested)
        return self.reserve(now=now, lease_seconds=lease_seconds), held_ledger

    def start(
        self, *, worker_id: str, now: datetime | None = None, lease_seconds: int = 120
    ) -> "DurableBudgetReservation":
        self._require_status("reserved")
        worker = str(worker_id or "").strip()
        if not worker:
            raise ReservationTransitionError("worker_id is required")
        if isinstance(lease_seconds, bool) or int(lease_seconds) <= 0:
            raise ReservationTransitionError("lease_seconds must be a positive integer")
        timestamp = _utc(now)
        if self.lease_expires_at and timestamp > self.lease_expires_at:
            raise ReservationTransitionError("reservation lease expired before execution started")
        return self._next(
            timestamp,
            status="running",
            worker_id=worker,
            started_at=timestamp,
            lease_expires_at=timestamp + timedelta(seconds=int(lease_seconds)),
        )

    def heartbeat(
        self, *, worker_id: str, now: datetime | None = None, lease_seconds: int = 120
    ) -> "DurableBudgetReservation":
        self._require_status("running")
        if str(worker_id or "").strip() != self.worker_id:
            raise ReservationTransitionError("only the owning worker may renew the lease")
        if isinstance(lease_seconds, bool) or int(lease_seconds) <= 0:
            raise ReservationTransitionError("lease_seconds must be a positive integer")
        timestamp = _utc(now)
        if self.lease_expires_at and timestamp > self.lease_expires_at:
            raise ReservationTransitionError("running reservation lease already expired")
        return self._next(
            timestamp,
            lease_expires_at=timestamp + timedelta(seconds=int(lease_seconds)),
        )

    def commit(
        self,
        *,
        actual: Mapping[str, int],
        execution_receipt_hash: str,
        now: datetime | None = None,
        worker_id: str | None = None,
    ) -> "DurableBudgetReservation":
        self._require_status("running")
        timestamp = _utc(now)
        if self.lease_expires_at and timestamp > self.lease_expires_at:
            raise ReservationTransitionError(
                "running reservation lease expired before commit"
            )
        if worker_id is not None and str(worker_id or "").strip() != self.worker_id:
            raise ReservationTransitionError(
                "only the owning worker may commit the reservation"
            )
        measured = _amounts(actual, allow_zero=True)
        return self._next(
            timestamp,
            status="committed",
            actual=measured,
            execution_receipt_hash=_receipt_hash(execution_receipt_hash),
            finished_at=timestamp,
            lease_expires_at=None,
            execution_uncertain=False,
        )

    def release(
        self,
        *,
        proof_not_started: bool,
        reason: str,
        now: datetime | None = None,
    ) -> "DurableBudgetReservation":
        self._require_status("requested", "reserved")
        if not proof_not_started:
            raise ReservationTransitionError(
                "release requires durable proof that execution never started"
            )
        timestamp = _utc(now)
        return self._next(
            timestamp,
            status="released",
            actual={kind: 0 for kind in self.requested},
            failure_reason=_reason(reason, default="released_before_execution"),
            finished_at=timestamp,
            lease_expires_at=None,
            execution_uncertain=False,
        )

    def fail(
        self,
        *,
        reason: str,
        now: datetime | None = None,
        actual: Mapping[str, int] | None = None,
        execution_receipt_hash: str | None = None,
        execution_may_have_started: bool | None = None,
    ) -> "DurableBudgetReservation":
        self._require_status("requested", "reserved", "running")
        timestamp = _utc(now)
        may_have_started = (
            self.status == "running"
            if execution_may_have_started is None
            else bool(execution_may_have_started)
        )
        if self.status == "requested" and may_have_started:
            raise ReservationTransitionError(
                "requested reservation cannot represent started execution"
            )
        if actual is not None:
            measured = _amounts(actual, allow_zero=True)
            receipt_hash = _receipt_hash(execution_receipt_hash)
            if self.status in {"requested", "reserved"} and any(measured.values()):
                raise ReservationTransitionError(
                    "pre-execution reservation cannot report consumed budget"
                )
            if may_have_started and not receipt_hash:
                raise ReservationTransitionError(
                    "measured failed execution requires an execution receipt hash"
                )
            uncertain = False
        elif may_have_started:
            # No trustworthy receipt after execution may have begun: charge the full hold.
            measured = dict(self.requested)
            receipt_hash = None
            uncertain = True
        else:
            measured = {kind: 0 for kind in self.requested}
            receipt_hash = None
            uncertain = False
        return self._next(
            timestamp,
            status="failed",
            actual=measured,
            execution_receipt_hash=receipt_hash,
            failure_reason=_reason(reason, default="execution_failed"),
            finished_at=timestamp,
            lease_expires_at=None,
            execution_uncertain=uncertain,
        )

    def recover_stale(
        self,
        *,
        now: datetime | None = None,
        actual_from_receipt: Mapping[str, int] | None = None,
        execution_receipt_hash: str | None = None,
    ) -> "DurableBudgetReservation":
        self._require_status("reserved", "running")
        timestamp = _utc(now)
        if self.lease_expires_at is None or timestamp <= self.lease_expires_at:
            raise ReservationTransitionError("reservation lease is not stale")
        if self.status == "reserved":
            return self.release(
                proof_not_started=True,
                reason="stale_reserved_before_execution",
                now=timestamp,
            )
        return self.fail(
            reason="stale_running_worker",
            now=timestamp,
            actual=actual_from_receipt,
            execution_receipt_hash=execution_receipt_hash,
            execution_may_have_started=True,
        )

    def reconcile_consumed(self, consumed_after_reservation: Mapping[str, int]) -> dict[str, int]:
        if not self.terminal:
            raise ReservationTransitionError("only a terminal reservation can reconcile the ledger")
        if not self.hold_applied:
            # A requested action can be cancelled before the transactional hold is written.
            # In that case the ledger must remain byte-for-byte unchanged.
            return dict(consumed_after_reservation)
        return reconcile_budget_snapshot(
            consumed_after_reservation,
            self.requested,
            self.actual,
        )

    def canonical_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in (
            "created_at", "updated_at", "lease_expires_at", "started_at", "finished_at"
        ):
            value = payload.get(key)
            payload[key] = value.isoformat() if isinstance(value, datetime) else None
        payload["requested"] = dict(self.requested)
        payload["actual"] = dict(self.actual)
        return payload

    @property
    def state_digest(self) -> str:
        encoded = json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
