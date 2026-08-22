from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.budget_reservations import DurableBudgetReservation
from runtime.receipts import CapabilityReceipt
from runtime.reservation_store import (
    BUDGET_RESERVATION_SCHEMA_SQL,
    PostgresBudgetReservationStore,
    ReservationConflict,
    ReservationStoreError,
    StoredBudgetReservation,
    _UPDATE_SQL,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def test_update_statement_uses_every_positional_parameter_contiguously():
    """asyncpg cannot infer types for skipped PostgreSQL bind positions."""
    positions = sorted({int(value) for value in re.findall(r"\$(\d+)", _UPDATE_SQL)})
    assert positions == list(range(1, max(positions) + 1))


def _row(
    record, *, action_id="action-1", action_digest="a" * 64,
    held=None, settled=None, receipt=None,
):
    return {
        "id": record.reservation_id,
        "action_id": action_id,
        "action_digest": action_digest,
        "state_digest": record.state_digest,
        "state_json": record.canonical_dict(),
        "ledger_after_hold_json": held,
        "ledger_after_settlement_json": settled,
        "receipt_json": receipt,
    }


class FakeConn:
    def __init__(self):
        self.rows = {}
        self.actions = {}
        self.executed = []
        self.force_update_conflict = False

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def fetchrow(self, query, *args):
        if query.lstrip().startswith("INSERT INTO budget_reservations"):
            record = _record_from_args(args)
            action_id = args[3]
            action_digest = args[24]
            key = (record.owner_kind, record.owner_id, action_id)
            if key in self.actions:
                return None
            row = _row(record, action_id=action_id, action_digest=action_digest)
            self.rows[record.reservation_id] = row
            self.actions[key] = record.reservation_id
            return row
        if query.lstrip().startswith("UPDATE budget_reservations"):
            if self.force_update_conflict:
                return None
            record = _record_from_args(args)
            expected_version, expected_digest = args[-2], args[-1]
            current = self.rows.get(record.reservation_id)
            if not current:
                return None
            stored = StoredBudgetReservation.from_row(current)
            if (
                stored.record.version != expected_version
                or stored.record.state_digest != expected_digest
            ):
                return None
            row = _row(
                record,
                action_id=current["action_id"],
                action_digest=current["action_digest"],
                held=json.loads(args[19]) if args[19] is not None else None,
                settled=json.loads(args[20]) if args[20] is not None else None,
                receipt=json.loads(args[21]) if args[21] is not None else None,
            )
            self.rows[record.reservation_id] = row
            return row
        if "WHERE id=$1" in query:
            return self.rows.get(args[0])
        if "owner_kind=$1 AND owner_id=$2 AND action_id=$3" in query:
            reservation_id = self.actions.get((args[0], args[1], args[2]))
            return self.rows.get(reservation_id) if reservation_id else None
        raise AssertionError(query)

    async def fetch(self, query, *args):
        now, limit = args
        matches = []
        for row in self.rows.values():
            record = StoredBudgetReservation.from_row(row).record
            if record.status in {"reserved", "running"} and record.lease_expires_at < now:
                matches.append(row)
        matches.sort(key=lambda item: StoredBudgetReservation.from_row(item).record.lease_expires_at)
        return matches[:limit]


def _record_from_args(args):
    state = json.loads(args[18])
    for name in (
        "created_at", "updated_at", "lease_expires_at", "started_at", "finished_at"
    ):
        if state.get(name):
            state[name] = datetime.fromisoformat(state[name])
    return DurableBudgetReservation(**state)


def _requested(amounts=None, reservation_id="reservation-1"):
    return DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="web.crawl",
        amounts=amounts or {"http_requests": 10},
        reservation_id=reservation_id,
        now=NOW,
    )


def _receipt(record):
    return CapabilityReceipt(
        capability_name=record.capability_name,
        adapter_name="katana",
        adapter_version="1",
        target_id="target-1",
        hunt_id=record.owner_id,
        worker_id=record.worker_id,
        status="succeeded",
        input_digest="a" * 64,
        parser_version="katana/v1",
        budget_reservation_id=record.reservation_id,
        budget_reservation_state=record.status,
        budget_reserved=record.requested,
        budget_consumed=record.actual,
        started_at=record.started_at.isoformat(),
        finished_at=record.finished_at.isoformat(),
    )


@pytest.mark.asyncio
async def test_schema_is_idempotent_and_records_migration_marker():
    conn = FakeConn()
    await PostgresBudgetReservationStore().ensure_schema(conn)
    assert len(conn.executed) == 1
    sql = conn.executed[0][0]
    assert "CREATE TABLE IF NOT EXISTS budget_reservations" in sql
    assert "UNIQUE (owner_kind, owner_id, action_id)" in sql
    assert "v2_budget_reservations_v2" in sql
    assert BUDGET_RESERVATION_SCHEMA_SQL == sql


@pytest.mark.asyncio
async def test_action_redelivery_returns_same_record_but_conflicting_budget_fails():
    conn = FakeConn()
    store = PostgresBudgetReservationStore()
    first = await store.create_requested(
        conn, action_id="action-1", action_digest="a" * 64, record=_requested()
    )
    redelivered = await store.create_requested(
        conn, action_id="action-1", action_digest="a" * 64,
        record=_requested(reservation_id="reservation-2")
    )
    assert redelivered.record.reservation_id == first.record.reservation_id

    with pytest.raises(ReservationConflict, match="different capability, input, or budget"):
        await store.create_requested(
            conn,
            action_id="action-1",
            action_digest="a" * 64,
            record=_requested({"http_requests": 11}, "reservation-3"),
        )

    with pytest.raises(ReservationConflict, match="different capability, input, or budget"):
        await store.create_requested(
            conn,
            action_id="action-1",
            action_digest="b" * 64,
            record=_requested(reservation_id="reservation-4"),
        )


@pytest.mark.asyncio
async def test_versioned_hold_heartbeat_and_terminal_receipt_are_persisted():
    conn = FakeConn()
    store = PostgresBudgetReservationStore()
    requested = await store.create_requested(
        conn, action_id="action-1", action_digest="a" * 64, record=_requested()
    )
    reserved_record, held = requested.record.reserve_against(
        limits={"http_requests": 20},
        consumed={"http_requests": 2},
        now=NOW,
        lease_seconds=30,
    )
    reserved = await store.persist_transition(
        conn,
        previous=requested,
        current=reserved_record,
        ledger_after_hold=held,
    )
    running_record = reserved.record.start(
        worker_id="worker-1", now=NOW + timedelta(seconds=1), lease_seconds=30
    )
    running = await store.persist_transition(conn, previous=reserved, current=running_record)
    heartbeat = running.record.heartbeat(
        worker_id="worker-1", now=NOW + timedelta(seconds=2), lease_seconds=30
    )
    running2 = await store.persist_transition(conn, previous=running, current=heartbeat)

    provisional = running2.record.commit(
        actual={"http_requests": 4},
        execution_receipt_hash="a" * 64,
        worker_id="worker-1",
        now=NOW + timedelta(seconds=3),
    )
    receipt = _receipt(provisional)
    committed = running2.record.commit(
        actual={"http_requests": 4},
        execution_receipt_hash=receipt.receipt_hash,
        worker_id="worker-1",
        now=NOW + timedelta(seconds=3),
    )
    stored = await store.persist_terminal(
        conn,
        previous=running2,
        terminal=committed,
        ledger_after_settlement={"http_requests": 6},
        receipt=receipt,
    )
    assert stored.record.status == "committed"
    assert stored.record.version == 5
    assert stored.ledger_after_hold == {"http_requests": 12}
    assert stored.ledger_after_settlement == {"http_requests": 6}
    assert stored.receipt["receipt_hash"] == receipt.receipt_hash


@pytest.mark.asyncio
async def test_optimistic_lock_and_stale_recovery_fail_closed():
    conn = FakeConn()
    store = PostgresBudgetReservationStore()
    requested = await store.create_requested(
        conn, action_id="action-1", action_digest="a" * 64, record=_requested()
    )
    reserved_record, held = requested.record.reserve_against(
        limits={"http_requests": 20}, consumed={"http_requests": 0},
        now=NOW, lease_seconds=10,
    )
    reserved = await store.persist_transition(
        conn, previous=requested, current=reserved_record, ledger_after_hold=held
    )
    conn.force_update_conflict = True
    with pytest.raises(ReservationConflict, match="concurrently"):
        await store.persist_transition(
            conn,
            previous=reserved,
            current=reserved.record.start(worker_id="worker-1", now=NOW + timedelta(seconds=1)),
        )
    conn.force_update_conflict = False

    stale = await store.stale(conn, now=NOW + timedelta(seconds=11))
    assert len(stale) == 1 and stale[0].record.status == "reserved"
    released = stale[0].record.recover_stale(now=NOW + timedelta(seconds=11))
    terminal = await store.persist_terminal(
        conn,
        previous=stale[0],
        terminal=released,
        ledger_after_settlement={"http_requests": 0},
        receipt=None,
    )
    assert terminal.record.status == "released"


def test_row_roundtrip_rejects_tampered_state_digest():
    record = _requested()
    row = _row(record)
    row["state_digest"] = "0" * 64
    with pytest.raises(ReservationStoreError, match="digest mismatch"):
        StoredBudgetReservation.from_row(row)


def test_store_rejects_invalid_state_jump_and_receipt_for_another_input():
    conn = FakeConn()
    store = PostgresBudgetReservationStore()
    requested = asyncio.run(store.create_requested(
        conn, action_id="action-1", action_digest="a" * 64, record=_requested()
    ))
    invalid = DurableBudgetReservation(
        reservation_id=requested.record.reservation_id,
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="web.crawl",
        requested={"http_requests": 10},
        status="committed",
        actual={"http_requests": 1},
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
        hold_applied=True,
        worker_id="worker-1",
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        execution_receipt_hash="b" * 64,
        version=2,
    )
    with pytest.raises(ReservationStoreError, match="requested -> committed"):
        asyncio.run(store.persist_transition(
            conn, previous=requested, current=invalid,
        ))

    reserved_record, held = requested.record.reserve_against(
        limits={"http_requests": 20}, consumed={"http_requests": 0}, now=NOW,
    )
    reserved = asyncio.run(store.persist_transition(
        conn, previous=requested, current=reserved_record, ledger_after_hold=held,
    ))
    running_record = reserved.record.start(worker_id="worker-1", now=NOW)
    running = asyncio.run(store.persist_transition(
        conn, previous=reserved, current=running_record,
    ))
    provisional = running.record.commit(
        actual={"http_requests": 1}, execution_receipt_hash="b" * 64,
        worker_id="worker-1", now=NOW + timedelta(seconds=1),
    )
    wrong_receipt = CapabilityReceipt(
        capability_name="web.crawl", adapter_name="katana", adapter_version="1",
        target_id="target-1", hunt_id="hunt-1", worker_id="worker-1",
        status="succeeded", input_digest="c" * 64, parser_version="katana/v1",
        budget_reservation_id=provisional.reservation_id,
        budget_reservation_state="committed", budget_reserved=provisional.requested,
        budget_consumed=provisional.actual, started_at=provisional.started_at.isoformat(),
        finished_at=provisional.finished_at.isoformat(),
    )
    terminal = running.record.commit(
        actual={"http_requests": 1}, execution_receipt_hash=wrong_receipt.receipt_hash,
        worker_id="worker-1", now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ReservationStoreError, match="input digest"):
        asyncio.run(store.persist_terminal(
            conn, previous=running, terminal=terminal,
            ledger_after_settlement={"http_requests": 1}, receipt=wrong_receipt,
        ))
