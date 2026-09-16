from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from api.authenticated_assurance.models import ProfileConfiguration, ProfileWrite, exact_origin
from api.authenticated_assurance.evaluation import evaluate_health_response, current_assurance, scan_authentication_summary

NOW = datetime(2026, 9, 14, tzinfo=timezone.utc)
GENERATION = uuid4()


@pytest.fixture
def configuration():
    return ProfileConfiguration(
        target_id=uuid4(), credential_reference=uuid4(), display_name="Staging user",
        environment_label="staging", declared_role="member",
        credential_destinations=["https://app.example.test:443"],
        validation_policy={"path": "/api/me", "identity_field": "id", "expected_identity": "fixture-user",
                           "role_field": "role", "expected_role": "member", "owner_confirmed_read_only": True},
    )


def evaluate(config, **kwargs):
    return evaluate_health_response(config, revision=1, credential_version=1, credential_record_version=1, checked_at=NOW,
                                   process_generation=GENERATION,
                                   response_url=kwargs.pop("response_url", "https://app.example.test/api/me"), **kwargs)


def valid(config):
    return evaluate(config, status_code=200, content_type="application/json", body=b'{"id":"fixture-user","role":"member"}')


@pytest.mark.parametrize("status,body,content_type,expected", [
    (200, b'{"id":"fixture-user","role":"member"}', "application/json", "identity_confirmed"),
    (200, b'<html>Sign in</html>', "text/html", "invalid_response"),
    (200, b'{}', "application/json", "expected_identity_missing"),
    (200, b'{"id":"other","role":"member"}', "application/json", "unexpected_identity"),
    (200, b'{"id":"fixture-user","role":"admin"}', "application/json", "unexpected_role"),
    (403, b'{}', "application/json", "access_denied"),
    (401, b'{}', "application/json", "expected_identity_missing"),
    (503, b'{}', "application/json", "application_error"),
    (200, b'x' * 16385, "application/json", "invalid_response"),
    (200, b'{"id":"other","id":"fixture-user","role":"member"}', "application/json", "invalid_response"),
    (200, b'{"id":"fixture-user","role":"member","extra":NaN}', "application/json", "invalid_response"),
])
def test_response_semantics(configuration, status, body, content_type, expected):
    result = evaluate(configuration, status_code=status, body=body, content_type=content_type)
    assert result.reason_code == expected
    assert (result.state == "valid") == (expected == "identity_confirmed")


@pytest.mark.parametrize("url", ["http://app.example.test/api/me", "https://app.example.test:444/api/me",
                                  "https://sub.app.example.test/api/me", "https://app.example.test/other"])
def test_destination_is_exact(configuration, url):
    assert evaluate(configuration, response_url=url, status_code=200).reason_code == "destination_rejected"


def test_redirect_timeout_and_expiry(configuration):
    assert evaluate(configuration, status_code=302, location="/login").reason_code == "login_redirect"
    assert evaluate(configuration, status_code=302, location="//evil.example.test/").reason_code == "destination_rejected"
    assert evaluate(configuration, status_code=302, location="https://other.example.test/").reason_code == "destination_rejected"
    assert evaluate(configuration, timed_out=True).state == "unknown"
    assert evaluate(configuration, credential_expired=True).state == "expired"


@pytest.mark.parametrize("overrides,reason", [
    ({"credential_active": False}, "credential_revoked"),
    ({"credential_expires_at": NOW}, "credential_expired"),
    ({"revision": 2}, "profile_changed"),
    ({"credential_version": 2}, "credential_changed"),
    ({"credential_record_version": 3}, "credential_changed"),
    ({"process_generation": uuid4()}, "process_restarted"),
    ({"now": NOW + timedelta(seconds=301)}, "validation_stale"),
    ({"lifecycle_state": "disabled"}, "profile_disabled"),
    ({"destination_active": False}, "destination_rejected"),
])
def test_live_state_overrides_historical_validity(configuration, overrides, reason):
    args = dict(revision=1, credential_version=1, credential_record_version=1, configuration_digest=configuration.digest(1, 1),
                now=NOW, process_generation=GENERATION)
    args.update(overrides)
    state = current_assurance(valid(configuration), **args)
    assert state["state"] != "valid"
    assert state["reason_code"] == reason
    assert state["continuous_authentication_proven"] is False


def test_seeded_response_never_reaches_metadata(configuration):
    secret = "SEEDED-CREDENTIAL-MUST-NOT-LEAVE-WORKER"
    record = evaluate(configuration, status_code=200, content_type="application/json",
                      body=json.dumps({"id": "fixture-user", "role": "member", "token": secret}).encode())
    assert secret not in record.model_dump_json()
    assert "fixture-user" not in record.model_dump_json()


@pytest.mark.parametrize("path", ["//other.test/", "/api/me?token=x", "/../me", "/%2fme", "/api\\me"])
def test_health_policy_rejects_ambiguous_paths(configuration, path):
    document = configuration.model_dump()
    document["validation_policy"]["path"] = path
    with pytest.raises(ValidationError):
        ProfileConfiguration.model_validate(document)


def test_profiles_cannot_grant_authority_or_accept_secrets(configuration):
    for key in ["secret", "auth_header", "active_testing", "approval_receipt_id", "script"]:
        with pytest.raises(ValidationError):
            ProfileConfiguration.model_validate({**configuration.model_dump(), key: "seeded-secret"})
    with pytest.raises(ValidationError):
        ProfileWrite(configuration=configuration, expected_revision=0, reviewed=False)
    assert configuration.digest(1, 1) != configuration.digest(2, 1)
    assert configuration.digest(1, 1) != configuration.digest(1, 3)


def test_origin_normalization():
    assert exact_origin("https://APP.example.test:443") == "https://app.example.test"
    assert exact_origin("http://[::1]:8080") == "http://[::1]:8080"
    for origin in ["https://user:pass@app.test", "https://app.test\\evil", "file:///tmp/x"]:
        with pytest.raises(ValueError):
            exact_origin(origin)


def test_legacy_credentials_are_not_identity_evidence():
    profile_id = str(uuid4())
    summary = scan_authentication_summary({"credential_profile_refs": [
        {"profile_id": profile_id, "profile_version": 4, "auth_header": "seeded-secret"},
    ], "auth_cookies": "seeded-cookie"})
    assert summary["reason_code"] == "legacy_unverified"
    assert summary["coverage"] == "unverified"
    assert summary["profiles"] == [{"credential_reference": profile_id, "credential_version": 4}]
    assert "seeded" not in json.dumps(summary)


@pytest.mark.parametrize("key,value", [
    ("auth_headers_json", '{"X-API-Key":"secret"}'),
    ("login_username", "member"),
    ("oauth_client_id", "client"),
    ("user2_header", "Bearer secret"),
])
def test_historical_authentication_fields_remain_unverified(key, value):
    summary = scan_authentication_summary({key: value})
    assert summary["authentication_requested"] is True
    assert summary["reason_code"] == "legacy_unverified"
    assert summary["coverage"] == "unverified"
    assert value not in json.dumps(summary)


def test_scan_health_timeline_is_sampled_not_continuous(configuration):
    record = valid(configuration).model_dump(mode="json")
    summary = scan_authentication_summary({}, health_observations=(
        {"kind": "authentication_health", "record": record},
    ))
    assert summary["authentication_requested"] is True
    assert summary["state"] == "valid"
    assert summary["reason_code"] == "sampled_identity_confirmed"
    assert summary["coverage"] == "sampled"
    assert summary["health_sample_count"] == 1
    assert summary["valid_health_sample_count"] == 1
    assert summary["continuous_authentication_proven"] is False
    assert "fixture-user" not in json.dumps(summary)


def test_uncertain_health_sample_creates_authentication_gap(configuration):
    record = evaluate(configuration, status_code=403, content_type="application/json", body=b'{}').model_dump(mode="json")
    summary = scan_authentication_summary({}, health_observations=(
        {"kind": "authentication_health", "record": record},
    ))
    assert summary["state"] == "unknown"
    assert summary["reason_code"] == "authentication_gap"
    assert summary["coverage"] == "partial"
    assert summary["uncertain_health_sample_count"] == 1
