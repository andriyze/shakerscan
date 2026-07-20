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


import invariant_contracts as ic
import pytest


def test_canonical_contract_preserves_read_path_verbatim():
    c = ic.canonical_contract({"contract_kind": "field_constraint", "method": "PUT", "path": "/api/o/1",
                               "field_name": "quantity", "operator": "lte", "expected_value": 3,
                               "title": "q<=3", "conditions": {"read_path": "data.quantity"}})
    assert c["conditions"]["read_path"] == "data.quantity"        # dots preserved (not identifier-mangled)
    assert ic.approval_errors({**c, "status": "approved"}) == []
    for bad in ["data/quantity", "../x", "a b"]:
        with pytest.raises(ValueError):
            ic.canonical_contract({"contract_kind": "field_constraint", "method": "PUT", "path": "/x",
                                   "field_name": "q", "operator": "lte", "expected_value": 3,
                                   "title": "t", "conditions": {"read_path": bad}})


def test_ownership_proposer_from_auth_boundary_edges():
    edges = [
        {"edge_type": "auth_boundary", "src_key": "POST /api/orders",
         "dst_key": "GET /api/orders/{id}",
         "attributes": {"object_id_key": "order_id", "excluded_principal": "user"}},
        {"edge_type": "auth_boundary", "src_key": "GET /api/public", "dst_key": "GET /api/pub2",
         "attributes": {}},  # no object id -> skipped
        {"edge_type": "produces", "src_key": "a", "dst_key": "b", "attributes": {"object_id_key": "x"}},
    ]
    drafts = ip.propose_ownership_drafts(edges)
    assert len(drafts) == 1
    d = drafts[0]
    assert d["contract_kind"] == "ownership"
    assert d["method"] == "GET" and d["path"] == "/api/orders/{id}"
    assert d["expected_access"] == "deny"
    assert d["conditions"]["resource_owner"] == "other"
    assert d["status"] == "draft" and d["promotion_authority"] is False
    assert d["approvable"] is True  # role + deny + resource_owner=other is complete


def test_ownership_proposer_without_principal_flags_approval_errors():
    edges = [{"edge_type": "auth_boundary", "src_key": "p", "dst_key": "GET /api/things/1",
              "attributes": {"object_id_key": "id"}}]
    drafts = ip.propose_ownership_drafts(edges)
    assert len(drafts) == 1
    assert "subject_role_required" in drafts[0]["approval_errors"]
    assert drafts[0]["approvable"] is False


def test_field_constraint_proposer_from_numeric_cap_hints():
    rows = [
        {"method": "put", "path": "/api/BasketItems/3", "field_name": "quantity",
         "operator": "lte", "expected_value": 3},
        {"method": "put", "path": "/api/BasketItems/3", "field_name": "quantity",
         "operator": "lte", "expected_value": 3},  # duplicate
        {"path": "no-leading-slash", "field_name": "x"},  # malformed -> skipped
    ]
    drafts = ip.propose_field_constraint_drafts(rows)
    assert len(drafts) == 1
    d = drafts[0]
    assert d["contract_kind"] == "field_constraint"
    assert d["method"] == "PUT"
    assert d["operator"] == "lte" and d["expected_value"] == 3
    assert d["approvable"] is True


def test_workflow_transition_proposer_partial_states_carry_approval_errors():
    rows = [{"method": "PUT", "path": "/api/orders/7", "field_name": "status",
             "from_state": "pending"}]
    drafts = ip.propose_workflow_transition_drafts(rows)
    assert len(drafts) == 1
    d = drafts[0]
    assert d["contract_kind"] == "workflow_transition"
    assert d["conditions"]["from_state"] == "pending"
    # missing to_state + probe_state are approval errors (never silently approvable)
    assert "transition_to_state_required" in d["approval_errors"]
    assert "transition_probe_state_required" in d["approval_errors"]
    assert d["approvable"] is False


def test_suspected_findings_adapter_maps_families():
    findings = [
        {"url": "http://target.test/api/BasketItems/3",
         "evidence": {"family": "field_constraint", "method": "PUT", "param": "quantity",
                      "operator": "lte", "bound": 3}},
        {"url": "http://target.test/api/orders/7",
         "evidence": {"family": "workflow", "state_field": "status", "from_state": "pending"}},
        {"url": "http://target.test/api/feed",
         "evidence": {"family": "data_exposure"}},  # not a contract family -> skipped
        {"url": "http://target.test",
         "evidence": {"family": "field_constraint", "param": "q"}},  # no route -> skipped
    ]
    drafts = ip.propose_drafts_from_suspected_findings(findings)
    kinds = sorted(d["contract_kind"] for d in drafts)
    assert kinds == ["field_constraint", "workflow_transition"]
    fc = next(d for d in drafts if d["contract_kind"] == "field_constraint")
    assert fc["path"] == "/api/BasketItems/3" and fc["field_name"] == "quantity"
    assert fc["expected_value"] == 3
    wf = next(d for d in drafts if d["contract_kind"] == "workflow_transition")
    assert wf["field_name"] == "status"
    assert all(d["status"] == "draft" and d["promotion_authority"] is False for d in drafts)
