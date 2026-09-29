"""Policy/shape regressions. No model-specific prompt or TV model exception."""
from __future__ import annotations

import json

import pytest

from runtime import hunt_http_contract as contract

PERMITTED = {"active_testing": True, "allow_state_changing_http": True}
RESERVED = {"http_requests": 1, "state_changing_requests": 1, "active_actions": 1}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("body", [{}, {"json_body": {}}, {"json_body": {"DEVICE_ID": "lab-client", "DEVICE_NAME": "ShakerScan"}}, {"form_body": {"client": "lab-client", "values": ["one", "two"]}}])
def test_authorized_write_accepts_real_bodies(method, body):
    assert contract.require_http_request_authority(
        {"method": method, "path": "/pairing/start", **body}, PERMITTED,
        requested_budget=RESERVED,
    ) is True


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_existing_passive_request_needs_no_new_permission(method):
    assert contract.require_http_request_authority({"method": method, "path": "/"}, {}) is False


@pytest.mark.parametrize("policy", [{}, {"active_testing": True}, {"allow_state_changing_http": True}, {"active_testing": False, "allow_state_changing_http": True}, {"active_testing": True, "allow_state_changing_http": "true"}])
def test_write_never_invents_missing_permission(policy):
    with pytest.raises(ValueError, match="permissions"):
        contract.require_http_request_authority({"method": "PUT"}, policy)


@pytest.mark.parametrize("dimension", list(RESERVED))
@pytest.mark.parametrize("value", [None, 0, -1, True, "1"])
def test_worker_rejects_write_without_a_real_reservation(dimension, value):
    with pytest.raises(ValueError, match=dimension):
        contract.require_http_request_authority({"method": "PUT"}, PERMITTED,
            requested_budget={**RESERVED, dimension: value})


@pytest.mark.parametrize("values", [
    {"method": "PUT", "json_body": {}, "form_body": {}},
    {"method": "PUT", "json_body": None},
    {"method": "PUT", "json_body": []},
    {"method": "PUT", "form_body": {"nested": {"x": 1}}},
    {"method": "PUT", "json_body": {"n": float("nan")}},
    {"method": "GET", "json_body": {"x": 1}},
    {"method": "PUT", "follow_redirects": True},
    {"method": "CONNECT"}, {"method": "TRACE"}, {"method": []}, {},
])
def test_unsupported_shapes_fail_before_traffic(values):
    with pytest.raises(ValueError):
        contract.validate_http_request_input(values)


def test_redacted_receipts_never_copy_pin_or_pairing_token():
    original = {"method": "PUT", "path": "/pairing/pair", "json_body": {"CHALLENGE_RESPONSE": "7319", "token": "example-secret"}}
    result = contract.redact_http_request_body(original)
    serialized = json.dumps(result)
    assert "7319" not in serialized and "example-secret" not in serialized
    assert "json_body" not in result
    assert result["body_kind"] == "json"
    assert result["body_values_visible"] is False
    assert original["json_body"]["CHALLENGE_RESPONSE"] == "7319"


def test_empty_body_is_not_confused_with_absent_body():
    assert contract.redact_http_request_body({"json_body": {}})["body_kind"] == "json"
    assert "body_kind" not in contract.redact_http_request_body({})
