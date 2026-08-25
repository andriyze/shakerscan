from __future__ import annotations

import asyncio

import pytest

from api.scan.action_budget_reconciliation import (
    repair_terminal_reservation_actions,
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


def test_repair_terminalizes_actions_after_terminal_reservations():
    conn = _Conn([{"id": "a"}, {"id": "b"}])

    repaired = asyncio.run(repair_terminal_reservation_actions(conn, limit=25))

    assert repaired == 2
    assert conn.limit == 25
    assert "FOR UPDATE OF a SKIP LOCKED" in conn.query
    assert "WHEN c.reservation_status='released' THEN 'blocked'" in conn.query
    assert "terminal_reservation_reconciled" in conn.query


def test_repair_rejects_unbounded_limits():
    with pytest.raises(ValueError, match="between 1 and 1000"):
        asyncio.run(repair_terminal_reservation_actions(_Conn([]), limit=1001))
