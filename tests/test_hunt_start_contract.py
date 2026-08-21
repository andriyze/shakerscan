from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from hunt.start_contract import HuntStartContractError, normalize_hunt_start_payload


def _payload(**overrides):
    value = {
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Find exploitable vulnerabilities.",
        "policy_profile": "balanced",
        "budgets": {"max_duration_seconds": 900, "max_http_requests": 500},
        "credential_refs": {},
        "capabilities": ["web.probe", "templates.scan"],
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


def test_passive_hunt_contract_is_normalized_without_expanding_budget_authority():
    contract = normalize_hunt_start_payload(_payload())
    assert contract.schema_version == "hunt-start/v2"
    assert contract.target_kind == "web"
    assert contract.budget_profile == "balanced"
    assert contract.budgets == {"max_duration_seconds": 900, "max_http_requests": 500}
    assert contract.policy.active_testing is False
    assert contract.capabilities == ("web.probe", "templates.scan")
    assert contract.request_collection_ids == ("collection-1",)


def test_legacy_ui_target_kind_policy_profile_maps_to_balanced():
    contract = normalize_hunt_start_payload(_payload(policy_profile="device", target_kind="device"))
    assert contract.budget_profile == "balanced"
    assert contract.target_kind == "device"


def test_active_network_and_mutation_policy_requires_explicit_authorization():
    for policy in (
        {"active_testing": True},
        {"active_testing": True, "network_discovery": True},
        {"active_testing": True, "allow_state_changing_http": True},
    ):
        with pytest.raises(HuntStartContractError, match="authorization"):
            normalize_hunt_start_payload(_payload(policy=policy))

    contract = normalize_hunt_start_payload(_payload(policy={
        "active_testing": True,
        "network_discovery": True,
        "allow_state_changing_http": True,
        "authorization_confirmed": True,
    }))
    assert contract.policy.authorized is True


def test_network_and_state_change_cannot_be_enabled_without_active_testing():
    with pytest.raises(HuntStartContractError, match="network discovery requires active_testing"):
        normalize_hunt_start_payload(_payload(policy={
            "network_discovery": True,
            "authorization_confirmed": True,
        }))
    with pytest.raises(HuntStartContractError, match="state-changing HTTP requires active_testing"):
        normalize_hunt_start_payload(_payload(policy={
            "allow_state_changing_http": True,
            "authorization_confirmed": True,
        }))


def test_credential_references_require_authorization_and_remain_opaque_ids():
    with pytest.raises(HuntStartContractError, match="credential use requires authorization"):
        normalize_hunt_start_payload(_payload(
            credential_refs={"web_credential_profile_id": "credential-1"},
        ))

    contract = normalize_hunt_start_payload(_payload(
        credential_refs={"web_credential_profile_id": "credential-1"},
        policy={"authorization_confirmed": True},
    ))
    assert contract.credential_refs == {"web_credential_profile_id": "credential-1"}
    assert "password" not in repr(contract.public_dict()).lower()


def test_budget_overrides_can_lower_but_not_raise_profile_limits():
    with pytest.raises(HuntStartContractError, match="exceeds the fast Hunt profile ceiling"):
        normalize_hunt_start_payload(_payload(
            policy_profile="fast",
            budgets={"max_http_requests": 501},
        ))
    contract = normalize_hunt_start_payload(_payload(
        policy_profile="fast",
        budgets={"max_http_requests": 250},
    ))
    assert contract.budgets == {"max_http_requests": 250}


def test_unknown_policy_budget_and_credential_fields_fail_closed():
    with pytest.raises(HuntStartContractError, match="unsupported Hunt policy fields"):
        normalize_hunt_start_payload(_payload(policy={"shell": True}))
    with pytest.raises(HuntStartContractError, match="unsupported budget fields"):
        normalize_hunt_start_payload(_payload(budgets={"unlimited": 1}))
    with pytest.raises(HuntStartContractError, match="unsupported credential reference fields"):
        normalize_hunt_start_payload(_payload(
            credential_refs={"raw_password": "secret"},
            policy={"authorization_confirmed": True},
        ))


def test_legacy_forwarding_strips_structured_policy_after_server_validation():
    source = _payload(policy={
        "active_testing": True,
        "authorization_confirmed": True,
        "approval_receipt_id": "approval-1",
    })
    contract = normalize_hunt_start_payload(source)
    forwarded = contract.legacy_payload(source)
    assert "policy" not in forwarded
    assert forwarded["target_id"] == "target-1"
    assert forwarded["policy_profile"] == "balanced"
    assert forwarded["request_collection_ids"] == ["collection-1"]
