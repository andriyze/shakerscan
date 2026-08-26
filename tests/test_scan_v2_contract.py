from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.contracts import (
    BUDGET_PROFILES, bind_scan_scope_receipt, public_scan_contract,
    resolve_scan_contract,
)


def test_canonical_scan_defaults_to_balanced_passive_v2():
    contract = resolve_scan_contract()
    assert contract.generation == "v2"
    assert contract.budget_profile == "balanced"
    assert contract.budget.max_duration_seconds == 1_200
    assert contract.budget.max_http_requests == 5_000
    assert contract.policy.active_testing is False
    assert contract.execution_plan.engine == "scan"
    assert contract.execution_plan.generation == "v2"
    assert contract.execution_plan.family_preset == "passive"
    assert contract.execution_plan.requested_families == ()
    assert contract.execution_plan.resolved_families == ("recon", "nuclei_passive")
    assert contract.policy.include_families == ("recon", "nuclei_passive")
    assert not hasattr(contract, "execution_scan_type")
    assert not hasattr(contract, "legacy_scan_type")
    assert not hasattr(contract, "deprecations")


def test_validated_scope_binding_rebuilds_plan_and_flattened_snapshots():
    contract = resolve_scan_contract(
        budget_profile="fast",
        policy={"active_testing": True, "allow_state_changing_http": True},
        approval_receipt_id="approval-1",
    )
    original_digest = contract.execution_plan.digest

    bound = bind_scan_scope_receipt(contract, "scope-1")
    metadata = bound.option_metadata()

    assert bound.policy.scope_receipt_id == "scope-1"
    assert metadata["scan_policy"]["scope_receipt_id"] == "scope-1"
    assert metadata["scan_execution_plan"]["policy"]["scope_receipt_id"] == "scope-1"
    assert metadata["scan_execution_plan_digest"] == bound.execution_plan.digest
    assert metadata["scan_execution_plan_digest"] != original_digest


def test_contract_resolver_has_no_legacy_translation_argument():
    with pytest.raises(TypeError, match="legacy_scan_type"):
        resolve_scan_contract(legacy_scan_type="smart")


def test_budget_profile_changes_ceilings_not_engine_or_policy_semantics():
    fast = resolve_scan_contract(budget_profile="fast", policy={"active_testing": True})
    thorough = resolve_scan_contract(budget_profile="thorough", policy={"active_testing": True})
    assert fast.policy == thorough.policy
    assert fast.budget.max_http_requests < thorough.budget.max_http_requests
    assert fast.execution_plan.engine == thorough.execution_plan.engine == "scan"
    assert not hasattr(fast, "execution_scan_type")
    assert not hasattr(thorough, "execution_scan_type")


def test_active_permission_changes_policy_not_scan_identity():
    passive = resolve_scan_contract(budget_profile="balanced")
    active = resolve_scan_contract(
        budget_profile="balanced", policy={"active_testing": True},
        approval_receipt_id="approval-1",
    )
    assert passive.execution_plan.engine == active.execution_plan.engine == "scan"
    assert passive.execution_plan.schema_version == active.execution_plan.schema_version
    assert passive.policy.active_testing is False
    assert active.policy.active_testing is True
    assert active.execution_plan.resolved_families == ("recon", "nuclei_passive")
    assert passive.execution_plan.digest != active.execution_plan.digest


def test_advanced_limits_are_resolved_and_bounded():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        advanced={"max_http_requests": 4_000, "max_workers": 3, "max_endpoints": 1_000},
    )
    assert contract.budget.max_http_requests == 4_000
    assert contract.budget.max_workers == 3
    assert contract.budget.max_endpoints == 1_000
    with pytest.raises(ValueError, match="profile ceiling"):
        resolve_scan_contract(
            budget_profile="balanced", advanced={"max_http_requests": 7_500},
        )
    with pytest.raises(ValueError):
        resolve_scan_contract(advanced={"max_workers": 129})
    with pytest.raises(ValueError):
        resolve_scan_contract(advanced={"new_scan_mode": "smart-plus"})


def test_host_and_mutation_budgets_are_independent_first_class_authority():
    passive = resolve_scan_contract(
        budget_profile="fast", advanced={"max_hosts": 7},
    )
    assert passive.budget.max_hosts == 7
    assert passive.budget.max_state_changing_requests == 0

    active = resolve_scan_contract(
        budget_profile="fast",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
        },
        approval_receipt_id="approval-1",
        advanced={"max_state_changing_requests": 9, "max_hosts": 6},
    )
    assert active.budget.max_state_changing_requests == 9
    assert active.budget.max_hosts == 6
    assert active.budget.ledger_limits()["state_changing_requests"] == 9
    assert active.budget.ledger_limits()["hosts_attempted"] == 6

    narrowed = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
        },
        approval_receipt_id="approval-1",
        advanced={"max_http_requests": 40, "max_endpoints": 12},
    )
    assert narrowed.budget.max_state_changing_requests == 40
    assert narrowed.budget.max_hosts == 12

    with pytest.raises(ValueError, match="state-changing HTTP authority"):
        resolve_scan_contract(advanced={"max_state_changing_requests": 1})


def test_active_state_change_family_and_network_policy_fail_closed():
    with pytest.raises(ValueError, match="state-changing"):
        resolve_scan_contract(policy={"allow_state_changing_http": True})
    with pytest.raises(ValueError, match="target-bound approval receipt"):
        resolve_scan_contract(policy={
            "active_testing": True,
            "allow_state_changing_http": True,
        })
    with pytest.raises(ValueError, match="must not overlap"):
        resolve_scan_contract(
            policy={"include_families": ["xss"], "exclude_families": ["xss"]}
        )
    with pytest.raises(ValueError, match="network_discovery requires active_testing"):
        resolve_scan_contract(policy={"network_discovery": True})
    with pytest.raises(ValueError, match="target-bound approval receipt"):
        resolve_scan_contract(policy={"active_testing": True, "network_discovery": True})


def test_family_policy_uses_only_canonical_registry_names():
    contract = resolve_scan_contract(policy={
        "active_testing": True,
        "include_families": ["sql-injection", "XSS"],
        "exclude_families": ["nuclei"],
    })
    assert contract.execution_plan.requested_families == ("sqli", "xss")
    assert contract.execution_plan.resolved_families == (
        "recon", "nuclei_passive", "xss", "sqli",
    )
    assert contract.policy.include_families == (
        "recon", "nuclei_passive", "xss", "sqli",
    )
    assert contract.policy.exclude_families == ("nuclei_active",)
    assert resolve_scan_contract(
        policy={"include_families": ["all"]},
    ).policy.include_families == ("recon", "nuclei_passive")
    with pytest.raises(ValueError, match="unknown family"):
        resolve_scan_contract(policy={"include_families": ["legacy_magic"]})
    with pytest.raises(ValueError, match="cannot contain all"):
        resolve_scan_contract(policy={"exclude_families": ["all"]})
    with pytest.raises(ValueError, match="not implemented by canonical Scan"):
        resolve_scan_contract(policy={"include_families": ["headers"]})
    with pytest.raises(ValueError, match="active_testing is required"):
        resolve_scan_contract(policy={"include_families": ["xss"]})


def test_standard_active_and_custom_presets_resolve_once():
    standard = resolve_scan_contract(policy={
        "preset": "standard_active",
        "active_testing": True,
    })
    assert standard.execution_plan.requested_families == ()
    assert standard.execution_plan.resolved_families == (
        "recon", "nuclei_passive", "xss", "sqli",
    )
    assert standard.policy.include_families == standard.execution_plan.resolved_families

    custom = resolve_scan_contract(policy={
        "preset": "custom",
        "active_testing": True,
        "include_families": ["sqli"],
    })
    assert custom.execution_plan.requested_families == ("sqli",)
    assert custom.execution_plan.resolved_families == ("sqli",)
    with pytest.raises(ValueError, match="at least one"):
        resolve_scan_contract(policy={"preset": "custom"})
    with pytest.raises(ValueError, match="requires active_testing"):
        resolve_scan_contract(policy={"preset": "standard_active"})


def test_public_scan_contract_generates_ui_vocabulary_from_server_sources():
    contract = public_scan_contract()

    assert contract["schema_version"] == "scan-public-contract/v1"
    assert contract["engine"] == "scan"
    assert list(contract["budget_profiles"]) == ["fast", "balanced", "thorough"]
    assert [item["name"] for item in contract["families"]] == [
        "recon", "nuclei_passive", "nuclei_active", "xss", "sqli", "bola",
    ]
    assert contract["passive_coverage"]["default_families"] == ["recon", "nuclei_passive"]
    assert contract["family_presets"]["standard_active"] == [
        "recon", "nuclei_passive", "xss", "sqli",
    ]
    assert "legacy_capability" not in contract["credentials"]
    assert "http.request" in contract["credentials"]["semantic_capabilities"]
    assert contract["request_collections"]["replay_policies"] == [
        "confirmed_active", "discovery_only", "safe_reads",
    ]
    state_limit = next(
        item for item in contract["advanced_limits"]
        if item["name"] == "max_state_changing_requests"
    )
    assert state_limit["minimum"] == 0
    assert state_limit["profile_ceilings"]["balanced"] == 100


def test_network_discovery_is_explicitly_authorized_and_unknown_profiles_reject():
    network = resolve_scan_contract(
        policy={"active_testing": True, "network_discovery": True},
        approval_receipt_id="approval-1",
    )
    assert network.policy.network_discovery is True
    assert network.execution_plan.engine == "scan"

    with pytest.raises(ValueError, match="budget_profile must be"):
        resolve_scan_contract(budget_profile="exhaustive")


def test_resolved_metadata_contains_only_canonical_plan_and_deprecation_data():
    contract = resolve_scan_contract(
        budget_profile="fast", policy={"subdomain_discovery": True},
        approval_receipt_id="approval-1",
    )
    metadata = contract.option_metadata()
    assert metadata["scan_generation"] == "v2"
    assert metadata["scan_engine"] == "scan"
    assert metadata["scan_policy"]["approval_receipt_id"] == "approval-1"
    assert metadata["resolved_scan_budget"]["max_duration_seconds"] == 300
    assert metadata["resolved_scan_budget"] == {
        **BUDGET_PROFILES["fast"].__dict__,
        "max_state_changing_requests": 0,
    }
    assert metadata["scan_execution_plan"]["engine"] == "scan"
    assert metadata["scan_execution_plan_digest"] == contract.execution_plan.digest
    assert "scan_compatibility" not in metadata
    assert "legacy_scan_type" not in metadata
