"""The carried-over summary is computed once, next to the deployment gate."""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.carried_over import (  # noqa: E402
    HISTORY_ROW_CAP,
    gate_findings_from_rows,
    load_target_history,
    summarize_carried_over,
)

SCAN = "scan-2"


def _row(severity, *, scan_id="scan-1", last_seen="scan-1", fingerprint=None, status="active"):
    return {"severity": severity, "scan_id": scan_id, "last_seen_scan_id": last_seen,
            "fingerprint": fingerprint, "status": status}


def test_counts_only_rows_this_run_neither_wrote_last_saw_nor_reported():
    history = {"rows": [
        _row("high", fingerprint="fp-env"),                       # carried
        _row("high", status="resolved"),                          # not active
        _row("info", last_seen="scan-3", fingerprint="fp-xfo"),   # reported by this run
        _row("info", scan_id=SCAN, last_seen=SCAN),               # written by this run
        _row("medium", last_seen=SCAN),                           # last seen by this run
        _row("critical", fingerprint="fp-old"),                   # same title elsewhere, other fingerprint
    ], "total": 6, "complete": True}
    reported = [{"fingerprint": "fp-xfo"}, {"fingerprint": "fp-new", "title": "same title"}]
    summary = summarize_carried_over(SCAN, reported, history)
    assert summary == {
        "count": 2, "material": 2, "highest": "critical", "complete": True,
        "total_active": 6, "unloaded_active": 0,
    }


def test_missing_linkage_is_uncertainty_not_proof_of_reobservation():
    history = {"rows": [{"severity": "medium", "status": "active"}], "total": 1, "complete": True}
    assert summarize_carried_over(SCAN, [{"title": "x"}], history)["count"] == 1


def test_an_incomplete_history_is_reported_as_a_lower_bound():
    history = {"rows": [_row("low")], "total": 7, "complete": False}
    summary = summarize_carried_over(SCAN, [], history)
    assert summary["complete"] is False
    assert summary["count"] == 1
    assert summary["unloaded_active"] == 6


def test_no_history_is_an_empty_complete_summary():
    assert summarize_carried_over(SCAN, [], None)["count"] == 0
    assert summarize_carried_over(SCAN, [], None)["complete"] is True


def test_load_target_history_says_whether_every_row_was_loaded():
    class Conn:
        def __init__(self, total, rows):
            self.total, self.rows, self.calls = total, rows, []

        async def fetchval(self, sql, ids):
            self.calls.append(("count", list(ids)))
            return self.total

        async def fetch(self, sql, ids, cap):
            self.calls.append(("rows", list(ids), cap))
            return self.rows[:cap]

    rows = [{"id": i, "fingerprint": None, "severity": "low", "scan_id": "s", "last_seen_scan_id": "s"} for i in range(3)]
    complete = asyncio.run(load_target_history(Conn(3, rows), ["t1"]))
    assert complete["complete"] is True and complete["total"] == 3 and len(complete["rows"]) == 3
    truncated = asyncio.run(load_target_history(Conn(3, rows), ["t1"], cap=2))
    assert truncated["complete"] is False and len(truncated["rows"]) == 2
    empty = asyncio.run(load_target_history(Conn(9, rows), []))
    assert empty == {"rows": [], "total": 0, "complete": True}
    assert HISTORY_ROW_CAP >= 1000


def test_gate_rows_keep_their_shape():
    rows = [{"id": "f1", "fingerprint": "fp", "title": "T", "severity": "high", "tool": "t", "url": "u"}]
    assert gate_findings_from_rows(rows) == [{
        "id": "f1", "fingerprint": "fp", "title": "T", "severity": "high", "tool": "t", "url": "u",
        "source": "target_active",
    }]
    assert gate_findings_from_rows(None) == []
