"""Transactional recovery for stale durable budget reservations.

The caller owns the database transaction.  Stale rows are claimed with
``FOR UPDATE SKIP LOCKED``; the owner ledger, terminal reservation, and Hunt action
are then reconciled in that same transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Mapping
import uuid

from .budgets import BUDGET_DIMENSIONS
from .reservation_store import (
    PostgresBudgetReservationStore,
    ReservationStoreError,
    StoredBudgetReservation,
)


class ReservationRecoveryError(RuntimeError):
    """A stale reservation could not be reconciled with its durable owner."""


@dataclass(frozen=True)
class ReservationRecoveryEvent:
    reservation_id: str
    owner_kind: str
    owner_id: str
    action_id: str
    previous_status: str
    terminal_status: str
    execution_uncertain: bool
    budget_consumed: Mapping[str, int]

    def public_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "owner_kind": self.owner_kind,
            "owner_id": self.owner_id,
            "action_id": self.action_id,
            "previous_status": self.previous_status,
            "terminal_status": self.terminal_status,
            "execution_uncertain": self.execution_uncertain,
            "budget_consumed": dict(self.budget_consumed),
        }


def _json_object(value: Any, *, name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ReservationRecoveryError(f"{name} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReservationRecoveryError(f"{name} is not an object")
    return dict(value)


async def _lock_owner(conn: Any, stored: StoredBudgetReservation) -> Any:
    try:
        owner_id = uuid.UUID(stored.record.owner_id)
    except (ValueError, AttributeError) as exc:
        raise ReservationRecoveryError("stale reservation owner ID is invalid") from exc
    if stored.record.owner_kind == "hunt":
        return await conn.fetchrow(
            "SELECT id, budget_used_json FROM hunt_runs WHERE id=$1 FOR UPDATE",
            owner_id,
        )
    if stored.record.owner_kind == "scan":
        return await conn.fetchrow(
            "SELECT id, budget_used_json FROM scans WHERE id=$1 FOR UPDATE",
            owner_id,
        )
    raise ReservationRecoveryError("stale reservation owner kind is invalid")


async def _persist_owner_ledger(
    conn: Any,
    stored: StoredBudgetReservation,
    ledger: Mapping[str, int],
) -> None:
    encoded = json.dumps(dict(ledger), sort_keys=True, separators=(",", ":"))
    owner_id = uuid.UUID(stored.record.owner_id)
    if stored.record.owner_kind == "hunt":
        try:
            action_id = uuid.UUID(stored.action_id)
        except (ValueError, AttributeError) as exc:
            raise ReservationRecoveryError("stale Hunt action ID is invalid") from exc
        await conn.execute(
            "UPDATE hunt_runs SET budget_used_json=$2::jsonb, updated_at=NOW() WHERE id=$1",
            owner_id,
            encoded,
        )
        await conn.execute(
            """UPDATE hunt_actions
               SET status='failed', completed_at=COALESCE(completed_at, NOW()),
                   result_summary=$2::jsonb
               WHERE id=$1 AND status IN ('reserved','running')""",
            action_id,
            json.dumps({
                "error": "stale_reservation_recovered",
                "reservation_id": stored.record.reservation_id,
                "execution_uncertain": stored.record.status == "running",
            }, sort_keys=True, separators=(",", ":")),
        )
    else:
        await conn.execute(
            "UPDATE scans SET budget_used_json=$2::jsonb WHERE id=$1",
            owner_id,
            encoded,
        )
        action_status = "failed" if stored.record.status == "running" else "blocked"
        reason_code = (
            "stale_running_worker"
            if stored.record.status == "running"
            else "stale_reserved_before_execution"
        )
        await conn.execute(
            """UPDATE scan_capability_actions
               SET status=$4, reason_code=$5,
                   result_json=COALESCE(result_json, '{}'::jsonb) || $6::jsonb,
                   finished_at=COALESCE(finished_at, NOW()), updated_at=NOW()
               WHERE scan_id=$1 AND action_id=$2
                 -- scan_capability_actions.reservation_id is text; casting the
                 -- parameter to uuid made every sweep raise "operator does not
                 -- exist: text = uuid", so no expired hold was ever reclaimed.
                 AND reservation_id=$3
                 AND status NOT IN (
                    'success','partial','skipped','blocked','failed','cancelled','timed_out'
                 )""",
            owner_id,
            stored.action_id,
            stored.record.reservation_id,
            action_status,
            reason_code,
            json.dumps({
                "error": "stale_reservation_recovered",
                "reservation_id": stored.record.reservation_id,
                "reservation_status": "failed" if stored.record.status == "running" else "released",
                "execution_uncertain": stored.record.status == "running",
            }, sort_keys=True, separators=(",", ":")),
        )


async def recover_stale_reservations(
    conn: Any,
    *,
    now: datetime | None = None,
    limit: int = 100,
    store: PostgresBudgetReservationStore | None = None,
) -> tuple[ReservationRecoveryEvent, ...]:
    """Recover a batch inside the caller's active PostgreSQL transaction."""
    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ReservationRecoveryError("reservation recovery time must be timezone-aware")
    repository = store or PostgresBudgetReservationStore()
    try:
        stale = await repository.stale(
            conn,
            now=timestamp,
            limit=limit,
            for_update_skip_locked=True,
        )
    except ReservationStoreError as exc:
        raise ReservationRecoveryError(str(exc)) from exc
    events: list[ReservationRecoveryEvent] = []
    for stored in stale:
        owner = await _lock_owner(conn, stored)
        if owner:
            owner_ledger = _json_object(owner["budget_used_json"], name="owner budget ledger")
        elif stored.ledger_after_hold is not None:
            # The owner was deleted after the hold.  Terminalize the orphan so it
            # cannot be reclaimed forever, using the persisted hold snapshot.
            owner_ledger = dict(stored.ledger_after_hold)
        else:
            raise ReservationRecoveryError(
                "stale reservation has neither an owner nor a held ledger snapshot"
            )
        terminal = stored.record.recover_stale(now=timestamp)
        budget_ledger = {
            key: int(value)
            for key, value in owner_ledger.items()
            if key in BUDGET_DIMENSIONS
        }
        settled_budget = terminal.reconcile_consumed(budget_ledger)
        settled = dict(owner_ledger)
        settled.update(settled_budget)
        try:
            await repository.persist_terminal(
                conn,
                previous=stored,
                terminal=terminal,
                ledger_after_settlement=settled,
                receipt=None,
            )
        except ReservationStoreError as exc:
            raise ReservationRecoveryError(str(exc)) from exc
        if owner:
            await _persist_owner_ledger(conn, stored, settled)
        events.append(ReservationRecoveryEvent(
            reservation_id=terminal.reservation_id,
            owner_kind=terminal.owner_kind,
            owner_id=terminal.owner_id,
            action_id=stored.action_id,
            previous_status=stored.record.status,
            terminal_status=terminal.status,
            execution_uncertain=terminal.execution_uncertain,
            budget_consumed=dict(terminal.actual),
        ))
    return tuple(events)
