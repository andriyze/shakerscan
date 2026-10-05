"""Challenge issuance and response metadata cannot masquerade as a completed login."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from api.capabilities.authentication_proof import successful_token_signals


UNFINISHED = [
    {"access_token": "login-canary", "challenge": {"type": "recaptcha"}},
    {"access_token": "login-canary", "captcha": {"provider": "hcaptcha"}},
    {"access_token": "login-canary", "mfa": {"type": "totp"}},
    {"access_token": "login-canary", "two_factor": {"delivery": "sms"}},
    {"access_token": "login-canary", "verification": {"url": "/verify"}},
    {"access_token": "login-canary", "challenge": {}},
    {"access_token": "login-canary", "challenge": {"success": True}},
    {"access_token": "login-canary", "captcha": {"completed": False}},
    {"access_token": "login-canary", "mfa": {"required": None}},
    {"access_token": "login-canary", "meta": {"status": "failed"}},
    {"access_token": "login-canary", "metadata": {"state": "pending"}},
    {"data": {"access_token": "login-canary", "meta": {"success": False}}},
    {"loginResult": {"authentication": {"token": "login-canary"},
                     "captcha": {"provider": "hcaptcha"}}},
    {"access_token": "login-canary", "challenge": {"required": False, "status": "failed"}},
    {"access_token": "login-canary", "captcha": {"completed": True, "required": True}},
    {"access_token": "login-canary", "mfa": {"complete": True, "error": "invalid code"}},
    {"access_token": "login-canary", "mfa": {
        "completed": True, "required": True, "token": "old-challenge-canary"}},
    {"access_token": "login-canary", "challenge": {
        "required": False, "status": "failed", "token": "old-challenge-canary"}},
]
CLEARED = [
    {"challenge": {"required": False}},
    {"captcha": {"required": "false", "provider": "hcaptcha"}},
    {"mfa": {"required": 0}},
    {"challenge": {"complete": True}},
    {"captcha": {"completed": "true", "provider": "hcaptcha"}},
    {"mfa": {"status": "completed"}},
    {"mfa": {"completed": True, "token": "old-challenge-canary"}},
    {"challenge": {"required": False, "token": "old-challenge-canary"}},
    {"two_factor": {"status": "VERIFIED", "token": "old-challenge-canary"}},
    {"two_factor": {"state": "VERIFIED"}},
    {"verification": {"status": "not required"}},
    {"meta": {"status": "success"}},
    {"user": {"email_verification": {"status": "pending"}, "mfa": {"enabled": True}}},
    {"subscription": {"meta": {"status": "failed"}}},
]


def _response(document, token_header):
    return SimpleNamespace(
        status_code=200,
        response_headers={"Content-Type": "application/json", **(
            {"Authorization": "Bearer header-canary"} if token_header else {})},
        response_body=json.dumps(document).encode(),
    )


@pytest.mark.parametrize("document", UNFINISHED)
@pytest.mark.parametrize("token_header", [False, True])
def test_unfinished_challenge_has_no_token_signal(document, token_header):
    assert successful_token_signals(_response(document, token_header)) == ()


@pytest.mark.parametrize("extra", CLEARED)
def test_explicitly_cleared_challenge_keeps_token_signal(extra):
    result = successful_token_signals(_response({"access_token": "login-canary", **extra}, True))
    assert result == ("authorization", "json:access_token")


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("document", UNFINISHED)
def test_unfinished_challenge_never_becomes_adapter_proof(family, document):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, document, token_header=True)
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["proof_contract"] is None
    assert result.actual_budget["http_requests"] == (8 if family == "sql" else 4)
    assert "canary" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("extra", CLEARED)
@pytest.mark.parametrize("token_header", [False, True])
def test_cleared_challenges_and_unrelated_metadata_keep_adapter_proof(family, extra, token_header):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {"access_token": "login-canary", **extra}, token_header=token_header)
    assert result.observations[0]["proof_state"] == "verified"
    assert result.observations[0]["proof_contract"] is not None
    assert "canary" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("wrapper", ["loginResult", "customEnvelope", "vendorReply"])
@pytest.mark.parametrize("failure", [
    {"authenticated": False, "requiresMfa": True},
    {"status": "mfa_required"},
    {"state": "pending"},
    {"error": "invalid credentials"},
])
def test_header_tokens_honor_failed_authentication_in_unknown_wrappers(family, wrapper, failure):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {wrapper: failure}, token_header=True)
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None
    assert result.actual_budget["http_requests"] == (8 if family == "sql" else 4)


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("wrapper", ["loginResult", "customEnvelope", "vendorReply"])
def test_header_login_keeps_successful_unknown_wrapper_and_unrelated_metadata(family, wrapper):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {
        wrapper: {"authenticated": True, "status": "success"},
        "user": {"email_verification": {"status": "pending"}},
        "subscription": {"status": "failed", "error": "card declined"},
    }, token_header=True)
    assert result.observations[0]["proof_state"] == "verified"
    assert result.observations[0]["proof_contract"] is not None


@pytest.mark.parametrize("family", ["sql", "nosql"])
def test_explicit_account_authentication_failure_is_not_unrelated_metadata(family):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {"account": {"authenticated": False, "requiresMfa": True}}, token_header=True)
    assert result.observations[0]["proof_state"] == "not_proven"


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("verdict", [
    {"authenticated": False, "requiresMfa": True},
    {"status": "mfa_required"},
    {"state": "pending"},
])
def test_explicit_auth_envelope_reenters_login_scope_below_account_metadata(family, verdict):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {"user": {"authentication": {"loginResult": verdict}}}, token_header=True)
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("challenge", [
    {"mfa": {"completed": True, "token": "old-challenge-canary"}},
    {"challenge": {"required": False, "token": "old-challenge-canary"}},
    {"two_factor": {"status": "VERIFIED", "access_token": "old-challenge-canary"}},
])
def test_cleared_challenge_tokens_alone_are_not_authenticated_session_proof(family, challenge):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, challenge)
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None
    assert "canary" not in json.dumps(result.__dict__, default=str)
