from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload


def _payload(**overrides):
    value = {
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Find exploitable vulnerabilities.",
        "budget_profile": "balanced",
        "budgets": {"max_duration_seconds": 900, "max_http_requests": 500},
        "credential_refs": {},
        "capabilities": [],
        "request_collection_ids": ["collection-1"],
        "policy": {
            "active_testing": False,
            "allow_state_changing_http": False,
            "network_discovery": False,
            "authorization_confirmed": False,
        },
    }
    value.update(overrides)
    return value


def test_passive_hunt_contract_is_explicit_and_resolves_lowered_budget():
    contract = normalize_hunt_start_payload(_payload())
    assert contract.schema_version == "hunt-start/v2"
    assert contract.target_kind == "web"
    assert contract.budget_profile == "balanced"
    assert contract.budgets == {"max_duration_seconds": 900, "max_http_requests": 500}
    assert contract.resolved_budget["max_duration_seconds"] == 900
    assert contract.resolved_budget["max_http_requests"] == 500
    assert contract.resolved_budget["max_capability_calls"] == 80
    assert contract.policy.active_testing is False
    assert contract.request_collection_ids == ("collection-1",)


def test_policy_and_target_kind_are_mandatory_for_v2_admission():
    missing_policy = _payload()
    missing_policy.pop("policy")
    with pytest.raises(HuntStartContractError, match="policy is required"):
        normalize_hunt_start_payload(missing_policy)

    missing_kind = _payload(target_kind=None)
    with pytest.raises(HuntStartContractError, match="target_kind"):
        normalize_hunt_start_payload(missing_kind)


def test_active_network_and_mutation_authority_requires_confirmation_and_receipt():
    with pytest.raises(HuntStartContractError, match="authorization_confirmed"):
        normalize_hunt_start_payload(_payload(policy={"active_testing": True}))

    with pytest.raises(HuntStartContractError, match="approval receipt"):
        normalize_hunt_start_payload(_payload(policy={
            "active_testing": True,
            "authorization_confirmed": True,
        }))

    contract = normalize_hunt_start_payload(_payload(policy={
        "active_testing": True,
        "network_discovery": True,
        "allow_state_changing_http": True,
        "authorization_confirmed": True,
        "approval_receipt_id": "approval-1",
    }))
    assert contract.policy.authorized is True
    assert contract.policy.network_discovery is True
    assert contract.policy.allow_state_changing_http is True


def test_network_and_state_change_cannot_be_enabled_without_active_testing():
    with pytest.raises(HuntStartContractError, match="network discovery requires active_testing"):
        normalize_hunt_start_payload(_payload(policy={
            "network_discovery": True,
            "authorization_confirmed": True,
            "approval_receipt_id": "approval-1",
        }))
    with pytest.raises(HuntStartContractError, match="state-changing HTTP requires active_testing"):
        normalize_hunt_start_payload(_payload(policy={
            "allow_state_changing_http": True,
            "authorization_confirmed": True,
            "approval_receipt_id": "approval-1",
        }))


def test_credential_references_require_explicit_authority_and_remain_opaque():
    with pytest.raises(HuntStartContractError, match="authorization_confirmed"):
        normalize_hunt_start_payload(_payload(
            credential_refs={"web_credential_profile_id": "credential-1"},
        ))

    contract = normalize_hunt_start_payload(_payload(
        credential_refs={
            "ssh_credential_profile_id": "credential-1",
            "service_credential_profile_id": "credential-2",
        },
        target_kind="device",
        policy={
            "authorization_confirmed": True,
            "approval_receipt_id": "approval-1",
        },
    ))
    assert contract.credential_refs == {
        "ssh_credential_profile_id": "credential-1",
        "service_credential_profile_id": "credential-2",
    }
    assert "password" not in repr(contract.public_dict()).lower()

    with pytest.raises(HuntStartContractError, match="distinct profile IDs"):
        normalize_hunt_start_payload(_payload(
            credential_refs={
                "primary_credential_profile_id": "credential-1",
                "secondary_credential_profile_id": "credential-1",
            },
            policy={
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-1",
            },
        ))


def test_budget_overrides_can_lower_but_not_raise_profile_limits():
    with pytest.raises(HuntStartContractError, match="exceeds the fast Hunt profile ceiling"):
        normalize_hunt_start_payload(_payload(
            budget_profile="fast",
            budgets={"max_http_requests": 501},
        ))
    contract = normalize_hunt_start_payload(_payload(
        budget_profile="fast",
        budgets={"max_http_requests": 250},
    ))
    assert contract.resolved_budget["max_http_requests"] == 250
    assert contract.resolved_budget["max_duration_seconds"] == 900


def test_unknown_top_level_policy_budget_and_credential_fields_fail_closed():
    with pytest.raises(HuntStartContractError, match="unsupported Hunt start fields"):
        normalize_hunt_start_payload(_payload(shell=True))
    with pytest.raises(HuntStartContractError, match="unsupported Hunt policy fields"):
        normalize_hunt_start_payload(_payload(policy={"shell": True}))
    with pytest.raises(HuntStartContractError, match="unsupported budget fields"):
        normalize_hunt_start_payload(_payload(budgets={"unlimited": 1}))
    with pytest.raises(HuntStartContractError, match="unsupported credential reference fields"):
        normalize_hunt_start_payload(_payload(
            credential_refs={"raw_password": "secret"},
            policy={
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-1",
            },
        ))


def test_goal_and_objective_aliases_cannot_conflict():
    with pytest.raises(HuntStartContractError, match="goal and objective conflict"):
        normalize_hunt_start_payload(_payload(objective="A different objective"))
    contract = normalize_hunt_start_payload(_payload(goal=None, objective="Inspect the API"))
    assert contract.goal == "Inspect the API"


def test_v2_contract_has_no_legacy_downgrade_path():
    contract = normalize_hunt_start_payload(_payload())

    assert not hasattr(contract, "legacy_payload")
