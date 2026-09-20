"""An installation from before the identity change keeps its triage across it."""
from __future__ import annotations

import asyncio
import hashlib
import uuid

from api.scan.finding_reconciliation import legacy_finding_fingerprint, reconcile_legacy_finding_row

TARGET = uuid.UUID("00000000-0000-4000-8000-000000000777")


def _finding(header="X-Frame-Options"):
    return {
        "url": "http://crapi-web/", "tool": "nuclei", "cwe": None,
        "title": f"Missing HTTP response header: {header}",
        "evidence": {"template_id": "http-missing-security-headers", "matcher_name": header.lower()},
    }


class _Conn:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    async def fetchrow(self, query, target_id, fingerprint):
        self.queries.append(("fetchrow", fingerprint))
        return self.rows.get(fingerprint)

    async def execute(self, query, *args):
        self.queries.append(("execute", query.strip().splitlines()[0], args))
        return "UPDATE 1"


def _legacy_fp():
    return "t:" + hashlib.sha256(b"nuclei|GET|/|").hexdigest()[:16]


def test_a_legacy_row_with_the_same_title_moves_to_the_new_key():
    legacy = {"id": uuid.uuid4(), "status": "accepted_risk", "resurfaced_count": 0,
              "title": "Missing HTTP response header: X-Frame-Options", "tool": "nuclei", "cwe": None, "evidence": None}
    conn = _Conn({_legacy_fp(): legacy})
    row = asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint="t:new0000000000000", finding=_finding(),
    ))
    assert row is legacy
    assert conn.queries[-1][0] == "execute"
    assert conn.queries[-1][2] == ("t:new0000000000000", legacy["id"])


def test_a_legacy_row_for_a_different_check_is_left_alone():
    """The collapsed row carried the title of whichever header was written last; it is
    the same finding only when the title agrees. One disposition never spreads to every split."""
    legacy = {"id": uuid.uuid4(), "status": "false_positive", "resurfaced_count": 0,
              "title": "Missing HTTP response header: Content-Security-Policy", "tool": "nuclei", "cwe": None, "evidence": None}
    conn = _Conn({_legacy_fp(): legacy})
    row = asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint="t:new0000000000000", finding=_finding("X-Frame-Options"),
    ))
    assert row is None
    assert all(item[0] != "execute" for item in conn.queries)


def test_a_finding_with_a_cwe_never_looks_for_a_legacy_row():
    conn = _Conn({})
    row = asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint="t:x", finding={**_finding(), "cwe": "CWE-693"},
    ))
    assert row is None and conn.queries == []
    assert legacy_finding_fingerprint(None, "t:x") is None
    assert legacy_finding_fingerprint("nuclei|GET|/|", _legacy_fp()) is None
