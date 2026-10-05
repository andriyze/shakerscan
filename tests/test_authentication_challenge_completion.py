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
]
CLEARED = [
    {"challenge": {"required": False}},
    {"captcha": {"required": "false", "provider": "hcaptcha"}},
    {"mfa": {"required": 0}},
    {"challenge": {"complete": True}},
    {"captcha": {"completed": "true", "provider": "hcaptcha"}},
    {"mfa": {"status": "completed"}},
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
def test_cleared_challenges_and_unrelated_metadata_keep_adapter_proof(family, extra):
    from tests.test_authentication_proof_contract import _run

    result = _run(family, {"access_token": "login-canary", **extra}, token_header=True)
    assert result.observations[0]["proof_state"] == "verified"
    assert result.observations[0]["proof_contract"] is not None
    assert "canary" not in json.dumps(result.__dict__, default=str)
