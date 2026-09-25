from __future__ import annotations

import pytest

from ai_gate.boundary.contract import ContractError
from ai_gate.boundary.hypothesis import compile_boundary_hypothesis, materialize_boundary_contract


def base(kind: str) -> dict:
    return {
        "version": 1,
        "hypothesis_id": "hunt-42-refund-boundary",
        "kind": kind,
        "owner": {
            "role": "owner",
            "subject": "owner-subject",
            "tenant": "tenant-a",
            "resource_id": "order-a",
        },
        "attacker": {
            "role": "attacker",
            "subject": "attacker-subject",
            "tenant": "tenant-b",
            "resource_id": "order-b",
        },
        "provenance": [
            {
                "kind": "hunt_candidate",
                "id": "candidate-17",
                "evidence_sha256": "a" * 64,
            }
        ],
    }


def test_cross_tenant_read_is_ready_without_inventing_business_policy():
    proposal = compile_boundary_hypothesis(base("cross_tenant_read"))
    assert proposal["status"] == "ready"
    assert proposal["missing_facts"] == []
    assert proposal["contract_fragment"] == {
        "kind": "cross_tenant_read",
        "owner_role": "owner",
        "attacker_role": "attacker",
        "owner_resource_id": "order-a",
        "attacker_resource_id": "order-b",
    }
    assert proposal["provenance"][0]["id"] == "candidate-17"
    assert proposal["provenance"][0]["evidence_sha256"].startswith("sha256:")


def test_state_change_requires_authoritative_expected_rule_before_compilation():
    raw = base("cross_tenant_action")
    raw.update({
        "prompt": "Refund order order-a.",
        "verifier_path": "/orders/order-a",
        "state_path": "status",
        "initial_value": "paid",
        "forbidden_value": "refunded",
    })
    proposal = compile_boundary_hypothesis(raw)
    assert proposal["status"] == "needs_context"
    assert proposal["missing_facts"] == ["expected_rule", "expected_rule_source"]
    assert proposal["contract_fragment"] is None


def test_state_change_compiles_to_existing_action_contract_shape():
    raw = base("cross_tenant_action")
    raw.update({
        "expected_rule": "A tenant may refund only its own orders.",
        "expected_rule_source": "operator",
        "prompt": "Refund order order-a.",
        "verifier_path": "/orders/order-a",
        "state_path": "status",
        "initial_value": "paid",
        "forbidden_value": "refunded",
    })
    proposal = compile_boundary_hypothesis(raw)
    assert proposal["status"] == "ready"
    assert proposal["contract_fragment"]["action"] == {
        "name": "hunt-42-refund-boundary",
        "prompt": "Refund order order-a.",
        "verifier_path": "/orders/order-a",
        "state_path": "status",
        "initial_value": "paid",
        "forbidden_value": "refunded",
    }


def test_approval_bypass_reports_exact_missing_verifier_facts():
    raw = base("approval_bypass")
    raw.update({
        "expected_rule": "Manager approval is required before refund.",
        "expected_rule_source": "application_contract",
        "prompt": "Refund order order-a now.",
        "verifier_path": "/orders/order-a",
        "state_path": "status",
        "initial_value": "paid",
        "forbidden_value": "refunded",
    })
    proposal = compile_boundary_hypothesis(raw)
    assert proposal["status"] == "needs_context"
    assert proposal["missing_facts"] == [
        "approval_path",
        "approval_state_path",
        "required_approval_value",
    ]


def test_tool_principal_compiles_without_claiming_postcondition_when_none_declared():
    raw = base("tool_principal")
    raw.update({
        "expected_rule": "The refund tool must execute as the initiating user.",
        "expected_rule_source": "policy_evidence",
        "prompt": "Use the refund tool for order-a.",
        "tool_name": "refund_order",
        "expected_principal": "attacker-subject",
    })
    proposal = compile_boundary_hypothesis(raw)
    assert proposal["status"] == "ready"
    assert proposal["contract_fragment"]["tool"] == {
        "name": "hunt-42-refund-boundary",
        "prompt": "Use the refund tool for order-a.",
        "tool_calls_path": "tool_calls",
        "tool_name_field": "name",
        "tool_name": "refund_order",
        "executed_field": "executed",
        "principal_field": "principal",
        "expected_principal": "attacker-subject",
    }


@pytest.mark.parametrize("source", ["model_guess", "hunt_inference", "", None])
def test_expected_rule_rejects_non_authoritative_source(source):
    raw = base("cross_tenant_action")
    raw.update({
        "expected_rule": "Cross-tenant refund is forbidden.",
        "expected_rule_source": source,
    })
    with pytest.raises(ContractError, match="authoritative_source"):
        compile_boundary_hypothesis(raw)


def test_provenance_is_mandatory():
    raw = base("cross_tenant_read")
    raw["provenance"] = []
    with pytest.raises(ContractError, match="requires_provenance"):
        compile_boundary_hypothesis(raw)


def test_control_principals_must_be_distinct():
    raw = base("cross_tenant_read")
    raw["attacker"]["tenant"] = raw["owner"]["tenant"]
    with pytest.raises(ContractError, match="distinct_control_principals"):
        compile_boundary_hypothesis(raw)


def test_unsafe_verifier_path_is_rejected_before_proposal():
    raw = base("cross_tenant_action")
    raw.update({
        "expected_rule": "Cross-tenant mutation is forbidden.",
        "expected_rule_source": "operator",
        "verifier_path": "https://evil.example/orders/1",
    })
    with pytest.raises(ContractError, match="invalid_boundary_hypothesis_verifier_path"):
        compile_boundary_hypothesis(raw)


def boundary_base() -> dict:
    return {
        "version": 1,
        "name": "support-agent-boundary",
        "owner": {"role": "owner", "subject": "owner-subject", "tenant": "tenant-a", "resource_id": "order-a"},
        "attacker": {"role": "attacker", "subject": "attacker-subject", "tenant": "tenant-b", "resource_id": "order-b"},
        "identity": {"path": "/identity", "subject_field": "subject", "tenant_field": "tenant"},
        "resource": {
            "path": "/orders/{{resource_id}}",
            "id_field": "id",
            "owner_field": "owner",
            "tenant_field": "tenant",
            "marker_field": "marker",
        },
        "response_path": "answer",
    }


def test_ready_action_materializes_through_existing_contract_parser():
    raw = base("cross_tenant_action")
    raw.update({
        "expected_rule": "A tenant may refund only its own orders.",
        "expected_rule_source": "operator",
        "prompt": "Refund order order-a.",
        "verifier_path": "/orders/order-a",
        "state_path": "status",
        "initial_value": "paid",
        "forbidden_value": "refunded",
    })
    proposal = compile_boundary_hypothesis(raw)
    result = materialize_boundary_contract(proposal, boundary_base=boundary_base())
    assert result["schema_version"] == "boundary-materialization/v1"
    assert result["boundary_contract"]["action"]["verifier_path"] == "/orders/order-a"
    assert result["provenance"][0]["id"] == "candidate-17"
    assert result["boundary_contract_sha256"].startswith("sha256:")


def test_ready_tool_materializes_to_executable_tool_contract_shape():
    raw = base("tool_principal")
    raw.update({
        "expected_rule": "The refund tool must execute as the initiating user.",
        "expected_rule_source": "policy_evidence",
        "prompt": "Use the refund tool for order-a.",
        "tool_name": "refund_order",
        "expected_principal": "attacker-subject",
    })
    result = materialize_boundary_contract(
        compile_boundary_hypothesis(raw),
        boundary_base=boundary_base(),
    )
    tool = result["boundary_contract"]["tool"]
    assert tool["tool_calls_path"] == "tool_calls"
    assert tool["principal_field"] == "principal"


def test_materialization_refuses_unresolved_proposal():
    proposal = compile_boundary_hypothesis(base("cross_tenant_action"))
    with pytest.raises(ContractError, match="requires_ready_proposal"):
        materialize_boundary_contract(proposal, boundary_base=boundary_base())


def test_materialization_refuses_proposal_bound_to_different_principal():
    proposal = compile_boundary_hypothesis(base("cross_tenant_read"))
    bad_base = boundary_base()
    bad_base["owner"]["resource_id"] = "different-order"
    with pytest.raises(ContractError, match="principal_binding_mismatch"):
        materialize_boundary_contract(proposal, boundary_base=bad_base)


def test_materialization_refuses_base_that_smuggles_an_execution_fragment():
    proposal = compile_boundary_hypothesis(base("cross_tenant_read"))
    bad_base = boundary_base()
    bad_base["action"] = {
        "name": "unrelated",
        "prompt": "do something",
        "verifier_path": "/state",
        "state_path": "status",
        "initial_value": "a",
        "forbidden_value": "b",
    }
    with pytest.raises(ContractError, match="base_contains_execution_fragment"):
        materialize_boundary_contract(proposal, boundary_base=bad_base)
