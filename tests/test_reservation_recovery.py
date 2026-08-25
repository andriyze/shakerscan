from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json

import pytest

from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.reservation_recovery import (
    ReservationRecoveryError,
    recover_stale_reservations,
)
from api.runtime.reservation_store import StoredBudgetReservation


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def _stored(*, status: str, reservation_id: str, action_id: str, owner_kind: str = "hunt"):
    requested = DurableBudgetReservation.request(
        owner_kind=owner_kind,
        owner_id="11111111-1111-4111-8111-111111111111",
        capability_name="collections.replay",
        amounts={"http_requests": 3, "agent_actions": 1},
        reservation_id=reservation_id,
        now=NOW,
    )
    reserved, held = requested.reserve_against(
        limits={"http_requests": 20, "agent_actions": 20},
        consumed={"http_requests": 4, "agent_actions": 2},
        now=NOW,
        lease_seconds=10,
    )
    record = reserved
    if status == "running":
        record = reserved.start(worker_id="worker-1", now=NOW, lease_seconds=10)
    return StoredBudgetReservation(
        action_id=action_id,
        action_digest="a" * 64,
        record=record,
        ledger_after_hold=held,
    )


class Store:
    def __init__(self, rows):
        self.rows = tuple(rows)
        self.persisted = []
        self.stale_calls = []

    async def stale(self, conn, **kwargs):
        self.stale_calls.append(kwargs)
        return self.rows

    async def persist_terminal(self, conn, **kwargs):
        self.persisted.append(kwargs)
        return kwargs["previous"]


class Connection:
    def __init__(self, ledgers):
        self.ledgers = list(ledgers)
        self.execute_calls = []

    async def fetchrow(self, query, *args):
        assert "FOR UPDATE" in query
        if not self.ledgers:
            return None
        return {"id": args[0], "budget_used_json": self.ledgers.pop(0)}

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


def test_sweeper_refunds_reserved_and_fully_charges_uncertain_running_work():
    reserved = _stored(
        status="reserved",
        reservation_id="reservation-reserved",
        action_id="22222222-2222-4222-8222-222222222222",
    )
    running = _stored(
        status="running",
        reservation_id="reservation-running",
        action_id="33333333-3333-4333-8333-333333333333",
    )
    store = Store([reserved, running])
    conn = Connection([
        {"http_requests": 7, "agent_actions": 3, "candidates": 2, "verifications": 1},
        {"http_requests": 7, "agent_actions": 3, "candidates": 2, "verifications": 1},
    ])

    events = asyncio.run(recover_stale_reservations(
        conn,
        now=NOW + timedelta(seconds=11),
        limit=10,
        store=store,
    ))

    assert [event.terminal_status for event in events] == ["released", "failed"]
    assert events[0].budget_consumed == {"http_requests": 0, "agent_actions": 0}
    assert events[0].execution_uncertain is False
    assert events[1].budget_consumed == {"http_requests": 3, "agent_actions": 1}
    assert events[1].execution_uncertain is True
    settled = [call["ledger_after_settlement"] for call in store.persisted]
    assert settled == [
        {"http_requests": 4, "agent_actions": 2, "candidates": 2, "verifications": 1},
        {"http_requests": 7, "agent_actions": 3, "candidates": 2, "verifications": 1},
    ]
    owner_updates = [args for query, args in conn.execute_calls if "UPDATE hunt_runs" in query]
    assert json.loads(owner_updates[0][1]) == {
        "http_requests": 4,
        "agent_actions": 2,
        "candidates": 2,
        "verifications": 1,
    }
    assert json.loads(owner_updates[1][1]) == {
        "http_requests": 7,
        "agent_actions": 3,
        "candidates": 2,
        "verifications": 1,
    }
    action_updates = [args for query, args in conn.execute_calls if "UPDATE hunt_actions" in query]
    assert json.loads(action_updates[0][1])["execution_uncertain"] is False
    assert json.loads(action_updates[1][1])["execution_uncertain"] is True
    assert store.stale_calls[0]["for_update_skip_locked"] is True


def test_orphaned_stale_reservation_terminalizes_from_held_snapshot():
    stored = _stored(
        status="reserved",
        reservation_id="reservation-orphan",
        action_id="22222222-2222-4222-8222-222222222222",
    )
    store = Store([stored])
    conn = Connection([])
    events = asyncio.run(recover_stale_reservations(
        conn,
        now=NOW + timedelta(seconds=11),
        store=store,
    ))
    assert events[0].terminal_status == "released"
    assert store.persisted[0]["ledger_after_settlement"] == {
        "http_requests": 4,
        "agent_actions": 2,
    }
    assert conn.execute_calls == []


def test_scan_recovery_terminalizes_the_linked_capability_action():
    stored = _stored(
        status="running",
        reservation_id="44444444-4444-4444-8444-444444444444",
        action_id="finalize.report",
        owner_kind="scan",
    )
    store = Store([stored])
    conn = Connection([
        {"http_requests": 7, "agent_actions": 3, "candidates": 2, "verifications": 1},
    ])

    asyncio.run(recover_stale_reservations(
        conn,
        now=NOW + timedelta(seconds=11),
        store=store,
    ))

    action_updates = [
        args for query, args in conn.execute_calls
        if "UPDATE scan_capability_actions" in query
    ]
    assert len(action_updates) == 1
    assert action_updates[0][1] == "finalize.report"
    assert action_updates[0][3] == "failed"
    assert action_updates[0][4] == "stale_running_worker"
    assert json.loads(action_updates[0][5])["execution_uncertain"] is True


def test_recovery_requires_timezone_and_durable_owner_or_hold():
    stored = _stored(
        status="reserved",
        reservation_id="reservation-invalid",
        action_id="22222222-2222-4222-8222-222222222222",
    )
    with pytest.raises(ReservationRecoveryError, match="timezone-aware"):
        asyncio.run(recover_stale_reservations(
            Connection([]), now=NOW.replace(tzinfo=None), store=Store([stored]),
        ))

    orphan = StoredBudgetReservation(
        action_id=stored.action_id,
        action_digest=stored.action_digest,
        record=stored.record,
        ledger_after_hold=None,
    )
    with pytest.raises(ReservationRecoveryError, match="neither an owner"):
        asyncio.run(recover_stale_reservations(
            Connection([]), now=NOW + timedelta(seconds=11), store=Store([orphan]),
        ))


def test_worker_watchdog_wires_transactional_reservation_recovery():
    source = open("api/worker.py", encoding="utf-8").read()
    start = source.index("async def sweep_stale_budget_reservations")
    end = source.index("\n\nasync def async_main", start)
    helper = source[start:end]
    assert "async with conn.transaction()" in helper
    assert "await recover_stale_reservations" in helper
    assert "await repair_terminal_reservation_actions" in helper
    assert "BUDGET_RESERVATION_SWEEP_BATCH_SIZE" in helper
    main = source[source.index("async def async_main"):]
    assert "await sweep_stale_budget_reservations()" in main
