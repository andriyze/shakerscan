"""Managed intent validation; these tests do not grant execution authority."""

from uuid import uuid4

import pytest
from schedules import managed_options, router


def test_managed_active_and_opaque_inputs_are_preserved():
    profile, selection = str(uuid4()), str(uuid4())
    options = {
        "policy": {"active_testing": True}, "budget_profile": "fast",
        "credential_profile_ids": [profile],
        "request_collections": [{"id": selection, "replay_policy": "safe_reads"}],
    }
    body = managed_options.validate(options, target="https://example.test")
    for key, value in options.items():
        assert body[key] == value
    assert body["target"] == "https://example.test"
    assert "approval_receipt_id" not in body


@pytest.mark.parametrize("options", [
    {"approval_receipt_id": str(uuid4())}, {"auth_header": "fixture-secret"},
    {"credential_profile_ids": ["bad"]},
    {"request_collections": [{"id": str(uuid4()), "headers": {"secret": "fixture"}}]},
    {"policy": {"active_testing": True, "allow_state_changing_http": True}},
])
def test_unsupported_or_stored_authority_fails_closed(options):
    with pytest.raises((ValueError, TypeError)):
        managed_options.validate(options)


def test_opt_in_preserves_standalone_and_partial_configuration_fails(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", raising=False)
    monkeypatch.delenv("SHAKERSCAN_SCHEDULE_DISPATCH_TOKEN", raising=False)
    active = {"policy": {"active_testing": True}}
    with pytest.raises(ValueError, match="passive"):
        router._validate_normal_schedule_options(active)
    monkeypatch.setenv("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", "https://gateway.test")
    with pytest.raises(ValueError):
        router._validate_normal_schedule_options(active)
    monkeypatch.setenv("SHAKERSCAN_SCHEDULE_DISPATCH_TOKEN", "fixture-only")
    assert router._validate_normal_schedule_options(active)["policy"]["active_testing"] is True
