"""An installation from before the identity change keeps its triage across it."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import uuid

import pytest

from scanner.findings import pre_service_templated_finding_identity
from api.scan.finding_identity import canonical_finding_fingerprint
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

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, query, *args):
        self.queries.append(("execute", query.strip().splitlines()[0], args))
        fingerprint, row_id = args
        old = next(key for key, row in self.rows.items() if row["id"] == row_id)
        self.rows[fingerprint] = self.rows.pop(old)
        return "UPDATE 1"


def _legacy_fp():
    return "t:" + hashlib.sha256(b"nuclei|GET|/|").hexdigest()[:16]


def test_a_legacy_row_with_the_same_title_moves_to_the_new_key():
    legacy = {"id": uuid.uuid4(), "status": "accepted_risk", "resurfaced_count": 0,
              "title": "Missing HTTP response header: X-Frame-Options", "tool": "nuclei", "cwe": None,
              "url": "http://crapi-web/", "evidence": None}
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


def test_a_finding_without_a_check_still_looks_for_its_pre_service_key():
    # Its key predates service provenance even though neither check change applied.
    conn = _Conn({})
    row = asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint="t:x", finding={**_finding(), "cwe": "CWE-693", "evidence": {}},
    ))
    assert row is None and len(conn.queries) == 1
    assert legacy_finding_fingerprint(None, "t:x") is None
    assert legacy_finding_fingerprint("nuclei|GET|/|", _legacy_fp()) is None


def _pre_service_fingerprint(finding):
    identity = pre_service_templated_finding_identity(finding)
    return "t:" + hashlib.sha256(identity.encode()).hexdigest()[:16]


@pytest.mark.parametrize("old_url", [
    "http://crapi-web:8080/", "https://crapi-web/", "http://other-host/", None,
])
def test_legacy_triage_and_proof_do_not_move_without_the_same_proven_service(old_url):
    finding = _finding()
    legacy = {
        **finding, "url": old_url, "id": uuid.uuid4(), "status": "false_positive",
        "last_verification_verdict": "exploited", "verification_count": 2,
    }
    fingerprint = _pre_service_fingerprint(finding)
    conn = _Conn({fingerprint: legacy})
    assert asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint=canonical_finding_fingerprint(finding),
        finding=finding,
    )) is None
    assert conn.rows == {fingerprint: legacy}
    assert all(item[0] != "execute" for item in conn.queries)


def test_pre_service_reconciliation_preserves_row_id_triage_and_history():
    finding = _finding()
    canonical = canonical_finding_fingerprint(finding)
    legacy = {
        **finding, "url": "http://CRAPI-WEB:80/", "id": uuid.uuid4(),
        "status": "accepted_risk", "resurfaced_count": 3, "verification_count": 5,
        "last_verification_verdict": "exploited", "first_seen_at": "2024-01-01",
    }
    old_fingerprint = _pre_service_fingerprint(finding)
    conn = _Conn({old_fingerprint: legacy})
    assert asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint=canonical, finding=finding,
    )) is legacy
    assert conn.rows == {canonical: legacy}
    assert legacy["status"] == "accepted_risk" and legacy["verification_count"] == 5
    assert legacy["resurfaced_count"] == 3 and legacy["first_seen_at"] == "2024-01-01"


def test_existing_canonical_row_prevents_legacy_unique_conflict_or_history_overwrite():
    finding = _finding()
    canonical = canonical_finding_fingerprint(finding)
    legacy = {**finding, "id": uuid.uuid4(), "status": "accepted_risk"}
    current = {**finding, "id": uuid.uuid4(), "status": "resolved"}
    rows = {_pre_service_fingerprint(finding): legacy, canonical: current}
    conn = _Conn(rows.copy())
    assert asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint=canonical, finding=finding,
    )) is None
    assert conn.rows == rows
    assert all(item[0] != "execute" for item in conn.queries)


@pytest.mark.parametrize("old_route", ["/profile?q=", "/search?name=", None])
def test_old_collapsed_dom_row_cannot_move_triage_or_proof_to_another_client_route(old_route):
    finding = {
        "url": "https://app.example.test/", "tool": "dalfox", "cwe": "CWE-79",
        "title": "Verified cross-site scripting",
        "evidence": {"method": "GET", "param": "q", "client_route": "/search?q="},
    }
    legacy = {
        **finding, "id": uuid.uuid4(), "status": "false_positive",
        "last_verification_verdict": "exploited", "verification_count": 4,
        "evidence": {**finding["evidence"], "client_route": old_route},
    }
    old_key = _pre_service_fingerprint(finding)
    conn = _Conn({old_key: legacy})
    assert asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint=canonical_finding_fingerprint(finding), finding=finding,
    )) is None
    assert conn.rows == {old_key: legacy}
    assert all(item[0] != "execute" for item in conn.queries)


def test_same_templated_dom_route_retains_legacy_triage_across_ids_and_payloads():
    finding = {
        "url": "https://app.example.test/", "tool": "dalfox", "cwe": "CWE-79",
        "title": "Verified cross-site scripting",
        "evidence": {"method": "GET", "param": "q", "client_route": "/orders/46?q=new"},
    }
    legacy = {
        **finding, "url": "https://app.example.test:443/", "id": uuid.uuid4(), "status": "accepted_risk",
        "evidence": {**finding["evidence"], "client_route": "/orders/7?q=previous"},
    }
    conn = _Conn({_pre_service_fingerprint(finding): legacy})
    canonical = canonical_finding_fingerprint(finding)
    assert asyncio.run(reconcile_legacy_finding_row(
        conn, target_uuid=TARGET, fingerprint=canonical, finding=finding,
    )) is legacy
    assert conn.rows == {canonical: legacy} and legacy["status"] == "accepted_risk"
