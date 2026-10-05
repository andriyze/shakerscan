"""Token issuance cannot override explicit rejected or unfinished authentication."""
from __future__ import annotations

import json

import pytest

from tests.test_sqli_proof_capability import _request, _run as run_sql
from tests.test_nosqli_verify_capability import _run as run_nosql, _result


def _run(family, response, *, token_header=False):
    class AuthenticationTransport:
        async def send(self, request, **_kwargs):
            value = json.loads(request.body)["password"]
            injected = isinstance(value, dict) if family == "nosql" else "OR 1=1" in value
            headers = {"Content-Type": "application/json"}
            if injected and token_header:
                headers["Authorization"] = "Bearer operator-token"
            return _result(
                200 if injected else 401,
                json.dumps(response if injected else {"error": "invalid credentials"}).encode(),
                headers,
            )

    run = run_sql if family == "sql" else run_nosql
    return run(
        _request(
            method="POST", url="https://app.example.test/login",
            body='{"email":"nobody@example.test","password":"invalid"}',
            content_type="application/json",
        ),
        {"candidate_id": "c" * 64, "method": "POST", "field_path": "password",
         "request_class": "safe_authentication", "request_ref_id": "exact-request"},
        AuthenticationTransport(),
    )


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("envelope", [
    {"authenticated": False},
    {"isAuthenticated": "false"},
    {"requires_mfa": True},
    {"requiresMfa": True},
    {"requires_two_factor": "true"},
    {"status": "MFA_REQUIRED"},
    {"state": "pending_verification"},
    {"success": False},
    {"error": {"code": "MFA_REQUIRED"}},
    {"error_description": "login rejected"},
    {"challenge": "complete captcha"},
    {"mfa": {"required": True}},
    {"mfa": {"token": "challenge-secret"}},
    {"code": "INVALID_CREDENTIALS"},
    {"purpose": "mfa"},
    {"data": {"status": "mfa_required"}},
    {"challenge": {"required": True}},
    {"challenge": {"status": "pending"}},
])
def test_explicit_incomplete_authentication_vetoes_json_and_header_tokens(family, envelope):
    response = {"authentication": {"token": "operator-token"}, **envelope}
    result = _run(family, response, token_header=True)
    proof = result.observations[0]
    assert proof["proof_state"] == "not_proven"
    assert proof["proof_contract"] is None
    assert result.actual_budget["http_requests"] == (8 if family == "sql" else 4)
    assert "operator-token" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("response", [
    {"token": "mfa-challenge-token", "requires_mfa": True, "authenticated": False},
    {"authentication": {"token": "operator-token", "authenticated": False}},
    {"token": "operator-token"},
])
def test_unvalidated_or_nested_rejected_token_is_an_observation(family, response):
    result = _run(family, response)
    assert result.observations[0]["proof_state"] == "not_proven"
    assert result.observations[0]["proof_contract"] is None


@pytest.mark.parametrize("family", ["sql", "nosql"])
@pytest.mark.parametrize("response", [
    {"authentication": {"token": "operator-token"}},
    {"token": "operator-token", "authenticated": True, "requires_mfa": False},
    {"access_token": "operator-token", "token_type": "Bearer", "errors": []},
    {"session": {"token": "operator-token"}, "user": {"mfa": {"enabled": True}}},
    # Status fields that describe other objects do not veto a successful login.
    {"authentication": {"token": "operator-token"}, "user": {"email_verification": {"status": "pending"}}},
    {"access_token": "operator-token", "user": {"status": "unverified"}},
    {"access_token": "operator-token", "subscription": {"state": "failed", "error": "card declined"}},
    {"authentication": {"token": "operator-token"}, "challenge": {"required": False}},
    {"data": {"access_token": "operator-token", "token_type": "Bearer"}},
])
def test_successful_authentication_token_responses_still_prove_bypass(family, response):
    result = _run(family, response)
    assert result.observations[0]["proof_state"] == "verified"
    assert result.observations[0]["proof_contract"] is not None
    assert "operator-token" not in json.dumps(result.__dict__, default=str)
