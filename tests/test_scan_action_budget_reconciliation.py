from __future__ import annotations

import asyncio

import pytest

from api.scan.action_budget_reconciliation import (
    repair_terminal_reservation_actions_incremental,
    scan_action_budget_reconciliation,
)


class _Conn:
    def __init__(self, row):
        self.row = row
        self.query = ""

    async def fetchrow(self, query):
        self.query = query
        return self.row

    async def fetch(self, query, limit):
        self.query = query
        self.limit = limit
        return list(self.row or [])


def test_reconciliation_reports_only_content_free_aggregate_health():
    conn = _Conn({
        "receipt_link_missing": 1,
        "linked_authority_mismatch": 2,
        "stale_execution_without_hold": 3,
        "stale_terminal_reservation_without_action": 4,
        "legacy_historical_mismatch": 7,
        "linked_action_count": 50,
    })

    result = asyncio.run(scan_action_budget_reconciliation(conn))

    assert result == {
        "status": "degraded",
        "inconsistent_count": 10,
        "receipt_link_missing": 1,
        "linked_authority_mismatch": 2,
        "stale_execution_without_hold": 3,
        "stale_terminal_reservation_without_action": 4,
        "legacy_historical_mismatch": 7,
        "linked_action_count": 50,
    }
    assert "receipt_json->>'budget_reservation_id'" in conn.query
    assert "v2_scan_action_budget_link_v1" in conn.query
    assert "INTERVAL '5 minutes'" in conn.query


def test_reconciliation_is_ok_when_all_invariants_hold():
    result = asyncio.run(scan_action_budget_reconciliation(_Conn({})))

    assert result["status"] == "ok"
    assert result["inconsistent_count"] == 0


class _RepairConn:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        if "WITH batch AS" in query:
            return self.rows
        if "FOR UPDATE SKIP LOCKED" in query:
            return [{"id": action} for action in args[0]]
        return [{"id": action} for action in args[0]]


def test_repair_terminalizes_actions_after_terminal_reservations():
    rows = [{"id": f"r{i}", "updated_at": i, "passable": True, "reservation_status": "released",
             "failure_reason": None, "execution_uncertain": False, "open_action": f"a{i}"} for i in range(2)]
    conn = _RepairConn(rows)

    repaired, _cursor, examined = asyncio.run(
        repair_terminal_reservation_actions_incremental(conn, cursor=None, limit=25))

    assert (repaired, examined) == (2, 2)
    batch_query, batch_args = conn.queries[0]
    assert batch_args[2] == 25 and "LIMIT $3" in batch_query
    assert "FOR UPDATE SKIP LOCKED" in conn.queries[1][0]
    update = conn.queries[2][0]
    assert "WHEN c.reservation_status='released' THEN 'blocked'" in update
    assert "terminal_reservation_reconciled" in update


def test_repair_rejects_unbounded_limits():
    with pytest.raises(ValueError, match="between 1 and 1000"):
        asyncio.run(repair_terminal_reservation_actions_incremental(_RepairConn([]), cursor=None, limit=1001))
