from __future__ import annotations

import asyncio

from api.scan.action_budget_reconciliation import (
    scan_action_budget_reconciliation,
)


class _Conn:
    def __init__(self, row):
        self.row = row
        self.query = ""

    async def fetchrow(self, query):
        self.query = query
        return self.row


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
