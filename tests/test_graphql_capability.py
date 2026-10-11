"""The ``graphql`` Scan family: registration, compilation and finalizer promotion.

The checks themselves (field suggestions, alias and duplicate-field limits) are proofs over
fixed GET documents in ``capabilities.graphql_probe``; the batch is driven end to end in
``test_graphql_verify_batch.py``.
"""
from __future__ import annotations

import pytest

from capabilities.graphql_probe import (
    GRAPHQL_ENDPOINT_PATHS,
    GRAPHQL_PROOF_CONTRACTS,
    GRAPHQL_REQUESTS_PER_ENDPOINT,
    graphql_first_slice_hold,
)
from check_registry import get_check_family
from proof_contracts import CANONICAL_PROOF_CONTRACTS
from runtime.capability_registry import CAPABILITY_REGISTRY
from scan.action_plan import ScanActionPlanCompiler
from scan.contracts import SCAN_V2_FAMILY_NAMES, public_scan_contract, resolve_scan_contract
from scan.finalizer import finalize_scan_report
from tests.test_scan_action_adapter import _action as _adapter_action
from tests.toplevel_scan_fixtures import (
    SCAN_ID,
    compiler_target as _target,
    execution as _execution,
    plan as _plan,
    result_with_observations as _result_with_observation_count,
)


def _action(action_id, ordinal, *, capability_name=None, dependencies=()):
    capability = "scan.finalize" if action_id == "finalize.report" else capability_name
    return _adapter_action(action_id, capability, ordinal, dependencies=dependencies)


def test_graphql_is_an_active_canonical_family():
    assert "graphql" in SCAN_V2_FAMILY_NAMES
    spec = get_check_family("graphql")
    assert spec.is_active is True and spec.requires_credentials is False
    assert get_check_family("graphql_security").name == "graphql"
    capability = CAPABILITY_REGISTRY.require("graphql.verify_batch")
    assert capability.required_approval == "active_testing"
    assert "graphql_proof" in capability.evidence_contract
    assert set(GRAPHQL_PROOF_CONTRACTS.values()) <= CANONICAL_PROOF_CONTRACTS
    assert "graphql" in {item["name"] for item in public_scan_contract()["families"]}
    # Not in a preset: an operator selects it.
    for preset in public_scan_contract()["family_presets"].values():
        assert "graphql" not in preset
    with pytest.raises(ValueError, match="active_testing is required"):
        resolve_scan_contract(budget_profile="balanced", policy={
            "preset": "custom", "active_testing": False, "include_families": ["graphql"],
        })


def test_compiler_plans_the_graphql_batch_only_with_active_authority():
    active = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=_execution(include=("graphql",), active=True),
        target_binding=_target(), action_scope="full",
    )
    batches = [action for action in active.actions if action.capability_name == "graphql.verify_batch"]
    assert batches and batches[0].action_id == "verify.graphql"
    first = batches[0]
    assert first.capability_args["slice"]["start"] == 0
    hold = graphql_first_slice_hold(first.capability_args["slice"]["count"])
    assert hold["http_requests"] >= len(GRAPHQL_ENDPOINT_PATHS) * GRAPHQL_REQUESTS_PER_ENDPOINT
    # The first slice can pay for every check on every conventional location.
    for name, amount in hold.items():
        assert int(first.requested_budget[name]) >= amount
    assert "state_changing_requests" not in first.requested_budget  # GET only

    passive = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID, execution_plan=_execution(include=("sensitive_exposure",), active=False),
        target_binding=_target(), action_scope="full",
    )
    assert "graphql.verify_batch" not in {action.capability_name for action in passive.actions}


def _proof(check: str, **extra):
    return {
        "kind": "graphql_proof", "check": check, "proof_state": "verified",
        "finding_verdict": "verified", "proof_contract": GRAPHQL_PROOF_CONTRACTS.get(check),
        "endpoint": "https://app.example.test/graphql", "root_type": "Query",
        "response_status": 200, "response_body_sha256": "a" * 64, **extra,
    }


def test_finalizer_promotes_only_verified_known_graphql_checks():
    verify = _action("verify.graphql", 0, capability_name="graphql.verify_batch")
    final = _action("finalize.report", 1, dependencies=(verify.action_id,))
    plan = _plan(verify, final)
    observations = (
        _proof("field_suggestions", misspelling="pastezq", suggested_fields=["pastes", "paste"]),
        _proof("alias_limit_absent", alias_count=100),
        _proof("duplicate_field_limit_absent", duplicate_count=100),
        # Not promotable: unknown check, unverified, no body digest, forged contract name.
        _proof("depth_limit_absent"),
        {**_proof("alias_limit_absent"), "proof_state": "not_proven"},
        {**_proof("field_suggestions"), "response_body_sha256": ""},
    )
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={verify.action_id: _result_with_observation_count(verify, len(observations))},
        observations={verify.action_id: observations},
    )
    findings = {finding["title"]: finding for finding in report["findings"]}
    assert set(findings) == {
        "GraphQL field suggestions enabled",
        "GraphQL alias limit absent (100 aliases in one query)",
        "GraphQL duplicate field limit absent (100 duplicates in one query)",
    }
    suggestions = findings["GraphQL field suggestions enabled"]
    assert suggestions["severity"] == "low" and suggestions["cwe"] == "CWE-200"
    assert suggestions["url"] == "https://app.example.test/graphql"
    assert suggestions["evidence"]["suggested_fields"] == ["pastes", "paste"]
    assert suggestions["evidence"]["proof_contract"] == "graphql_field_suggestions/v1"
    assert findings["GraphQL alias limit absent (100 aliases in one query)"]["cwe"] == "CWE-770"


def test_a_graphql_proof_from_another_capability_is_not_promoted():
    other = _action("verify.exposure", 0, capability_name="exposure.verify_batch")
    final = _action("finalize.report", 1, dependencies=(other.action_id,))
    plan = _plan(other, final)
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={other.action_id: _result_with_observation_count(other, 1)},
        observations={other.action_id: (_proof("alias_limit_absent"),)},
    )
    assert report["findings"] == []
