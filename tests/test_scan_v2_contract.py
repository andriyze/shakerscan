from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scan.contracts import (
    BUDGET_PROFILES, LEGACY_SCAN_MAPPING, bind_scan_scope_receipt,
    normalize_scan_authentication, resolve_scan_contract,
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
    assert contract.execution_scan_type == "deep"  # temporary old-worker adapter only
    assert contract.legacy_scan_type is None
    assert contract.deprecations == ()


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


@pytest.mark.parametrize(
    ("legacy", "profile", "active"),
    [
        ("quick", "fast", False),
        ("standard", "balanced", False),
        ("deep", "thorough", False),
        ("full", "thorough", True),
        ("aggressive", "thorough", True),
        ("smart", "thorough", True),
    ],
)
def test_every_legacy_type_translates_to_one_scan_plan_with_deprecation(
    legacy, profile, active
):
    contract = resolve_scan_contract(legacy_scan_type=legacy)
    assert contract.budget_profile == profile
    assert contract.policy.active_testing is active
    assert contract.execution_plan.engine == "scan"
    assert contract.execution_plan.canonical_dict()["engine"] == "scan"
    assert contract.execution_scan_type == ("full" if active else "deep")
    assert "scan_compatibility" not in contract.option_metadata()
    assert contract.deprecations == ({
        "field": "scan_type", "value": legacy,
        "replacement": {"active_testing": active, "budget_profile": profile},
    },)


def test_all_legacy_names_collapse_to_two_temporary_worker_backing_presets():
    aliases = {
        legacy: resolve_scan_contract(legacy_scan_type=legacy).execution_scan_type
        for legacy in LEGACY_SCAN_MAPPING
    }
    assert aliases == {
        "quick": "deep",
        "standard": "deep",
        "deep": "deep",
        "full": "full",
        "aggressive": "full",
        "smart": "full",
    }
    assert set(aliases.values()) == {"deep", "full"}


def test_smart_legacy_mapping_never_becomes_hunt_or_enters_canonical_plan():
    contract = resolve_scan_contract(legacy_scan_type="smart")
    public_plan = contract.execution_plan.canonical_dict()
    assert contract.generation == "v2"
    assert public_plan["engine"] == "scan"
    assert "hunt" not in repr(public_plan).lower()
    assert "smart" not in repr(public_plan).lower()


def test_budget_profile_changes_ceilings_not_engine_or_policy_semantics():
    fast = resolve_scan_contract(budget_profile="fast", policy={"active_testing": True})
    thorough = resolve_scan_contract(budget_profile="thorough", policy={"active_testing": True})
    assert fast.policy == thorough.policy
    assert fast.budget.max_http_requests < thorough.budget.max_http_requests
    assert fast.execution_plan.engine == thorough.execution_plan.engine == "scan"
    assert fast.execution_scan_type == thorough.execution_scan_type == "full"


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
    assert passive.execution_plan.digest != active.execution_plan.digest


def test_advanced_limits_are_resolved_and_bounded():
    contract = resolve_scan_contract(
        budget_profile="balanced",
        advanced={"max_http_requests": 7_500, "max_workers": 3, "max_endpoints": 3_000},
    )
    assert contract.budget.max_http_requests == 7_500
    assert contract.budget.max_workers == 3
    assert contract.budget.max_endpoints == 3_000
    with pytest.raises(ValueError):
        resolve_scan_contract(advanced={"max_workers": 129})
    with pytest.raises(ValueError):
        resolve_scan_contract(advanced={"new_scan_mode": "smart-plus"})


def test_active_state_change_family_and_network_policy_fail_closed():
    with pytest.raises(ValueError, match="state-changing"):
        resolve_scan_contract(policy={"allow_state_changing_http": True})
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
        "include_families": ["sql-injection", "XSS"],
        "exclude_families": ["headers"],
    })
    assert contract.policy.include_families == ("sqli", "xss")
    assert contract.policy.exclude_families == ("headers",)
    assert resolve_scan_contract(
        policy={"include_families": ["all"]},
    ).policy.include_families == ()
    with pytest.raises(ValueError, match="unknown family"):
        resolve_scan_contract(policy={"include_families": ["legacy_magic"]})
    with pytest.raises(ValueError, match="cannot contain all"):
        resolve_scan_contract(policy={"exclude_families": ["all"]})


def test_network_discovery_is_explicitly_authorized_and_exhaustive_is_compat_alias():
    network = resolve_scan_contract(
        policy={"active_testing": True, "network_discovery": True},
        approval_receipt_id="approval-1",
    )
    assert network.policy.network_discovery is True
    assert network.execution_plan.engine == "scan"

    exhaustive = resolve_scan_contract(budget_profile="exhaustive")
    assert exhaustive.budget_profile == "thorough"
    assert exhaustive.execution_plan.budget_profile == "thorough"
    assert exhaustive.deprecations == ({
        "field": "budget_profile", "value": "exhaustive", "replacement": "thorough",
    },)


def test_v2_authentication_keeps_both_bola_principals_and_rejects_unknown_fields():
    assert normalize_scan_authentication({
        "auth_header": "Bearer user-one", "user2_header": "Bearer user-two",
    }) == {"auth_header": "Bearer user-one", "user2_header": "Bearer user-two"}
    assert normalize_scan_authentication({"auto_auth": False}) == {"auto_auth": False}
    with pytest.raises(ValueError, match="unsupported authentication fields"):
        normalize_scan_authentication({"raw_command": "curl attacker"})
    with pytest.raises(ValueError, match="auto_auth must be a boolean"):
        normalize_scan_authentication({"auto_auth": "yes"})


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
    assert metadata["resolved_scan_budget"] == BUDGET_PROFILES["fast"].__dict__
    assert metadata["scan_execution_plan"]["engine"] == "scan"
    assert metadata["scan_execution_plan_digest"] == contract.execution_plan.digest
    assert "scan_compatibility" not in metadata
    assert set(LEGACY_SCAN_MAPPING) == {
        "quick", "standard", "deep", "full", "aggressive", "smart"
    }
