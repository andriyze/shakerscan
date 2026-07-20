"""Host-runnable tests for the access_control invariant proposer (Phase 0).

Pure: imports only invariant_proposals + invariant_contracts (both dep-free)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import invariant_proposals as ip


def test_proposer_emits_only_review_drafts_never_authoritative():
    rows = [
        {"method": "GET", "path": "/workshop/api/mechanic/service_requests",
         "principal_role": "mechanic", "expected_access": "requires_role"},
        {"method": "GET", "path": "/admin/reports", "principal_role": "user", "expected_access": "deny"},
    ]
    drafts = ip.propose_access_control_drafts(rows)
    assert len(drafts) == 2
    for d in drafts:
        assert d["contract_kind"] == "access_control"
        assert d["status"] == "draft"                 # never approved
        assert d["promotion_authority"] is False       # can never promote on its own
        assert d["source"] == "auto_black_box"
        assert d["approvable"] is True                 # has role + expected_access + title
        assert d["approval_errors"] == []
    kinds = {(d["method"], d["path"], d["subject_role"], d["expected_access"]) for d in drafts}
    assert ("GET", "/workshop/api/mechanic/service_requests", "mechanic", "requires_role") in kinds


def test_proposer_skips_allow_and_incomplete_rows():
    rows = [
        {"method": "GET", "path": "/public", "principal_role": "user", "expected_access": "allow"},  # allow != vuln
        {"method": "GET", "path": "/x", "principal_role": "", "expected_access": "deny"},             # no role
        {"method": "", "path": "/y", "principal_role": "admin", "expected_access": "deny"},           # no method
        {"method": "GET", "path": "", "principal_role": "admin", "expected_access": "requires_role"}, # no path
        "not-a-row",
    ]
    assert ip.propose_access_control_drafts(rows) == []


def test_proposer_dedupes_identical_expectations():
    row = {"method": "GET", "path": "/a", "principal_role": "admin", "expected_access": "requires_role"}
    drafts = ip.propose_access_control_drafts([row, dict(row), dict(row)])
    assert len(drafts) == 1
