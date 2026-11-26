"""The deterministic default-credential proof: verdict table, request rebuild, recorded shape.

Unit tests (no database; the proof's PostgreSQL path is in test_hunt_default_credential_proof_postgres).
No password reaches a proof, a finding record or a candidate's context.
"""
from __future__ import annotations

import json

import pytest

from hunt import default_credential_proof as proof
from hunt import default_credentials as dc
import family_proof

ATTEMPT = {"pair_id": "dc-01", "action_id": "00000000-0000-4000-8000-000000000001",
           "request_shape": {"login_url": "https://app.example.test:443/hub/login"}}


@pytest.mark.parametrize("pair, control, verdict, promotable", [
    ("accepted", "rejected", "verified", True),
    ("accepted", "accepted", "refuted", False),      # any password works: not this pair
    ("accepted", "unclear", "unverified", False),
    ("accepted", None, "unverified", False),          # the control was never sent
    ("rejected", None, "unverified", False),          # the pair no longer works
    ("accepted", "locked", "unverified", False),      # a lockout sign stops the proof
    ("rate_limited", None, "unverified", False),
])
def test_proven_only_when_the_pair_authenticates_and_the_control_is_refused(pair, control, verdict, promotable):
    outcome = {"pair": pair, **({"control": control} if control else {})}
    result = proof.evaluate(outcome, attempt=ATTEMPT, username="admin")
    assert result["promotable"] is promotable
    if verdict == "verified":
        assert result["verdict"] == "verified"
    elif verdict == "refuted":
        assert result["verdict"] == "refuted"
    else:
        assert result["verdict"] not in {"verified", "refuted"}
    assert result["stopped"] is any(v in dc.STOP_VERDICTS for v in outcome.values())
    assert result["traffic"]["http_requests"] == len(outcome)


def test_the_family_is_a_contract_with_its_aliases():
    assert "default_credentials" in family_proof.FAMILY_CONTRACTS
    for alias in ("weak_credentials", "default-credential", "Weak Password"):
        assert proof.is_default_credential_family(alias)
        assert family_proof.canonical_family(alias) == "default_credentials"
    assert not proof.is_default_credential_family("auth_bypass")
    from hunt.candidate_verification_preflight import VERIFIABLE_FAMILIES
    assert "default_credentials" in VERIFIABLE_FAMILIES


def test_a_step_is_rebuilt_from_the_shape_with_the_servers_values():
    shape = {"login_url": "https://app.example.test:443/hub/login", "body_kind": "form",
             "body": {"username": "", "password": "", "remember": "1"},
             "user_pointer": "/username", "secret_pointer": "/password", "replayable": True}
    request = proof.build_request(shape, username="admin", secret="s3cret")
    assert request == {"method": "POST", "origin": "https://app.example.test:443", "path": "/hub/login",
                       "form_body": {"username": "admin", "password": "s3cret", "remember": "1"},
                       "follow_redirects": False}
    assert shape["body"]["password"] == ""   # the recorded shape is never changed
    json_shape = {**shape, "body_kind": "json", "body": {"auth": {"user": "", "pass": ""}},
                  "user_pointer": "/auth/user", "secret_pointer": "/auth/pass"}
    assert proof.build_request(json_shape, username=None, secret="x")["json_body"] == {"auth": {"user": "", "pass": "x"}}


def test_the_recorded_shape_is_replayable_only_without_captured_values():
    values = {"method": "POST", "origin": "https://app.example.test", "path": "/hub/login",
              "form_body": {"username": "", "password": ""},
              "request_bindings": [
                  {"default_credential": "dc-01", "credential_field": "username", "body_pointer": "/username"},
                  {"default_credential": "dc-01", "credential_field": "secret", "body_pointer": "/password"}]}
    shape = dc.request_shape(values, "https://app.example.test:443/hub/login")
    assert shape["replayable"] is True and shape["user_pointer"] == "/username"
    assert shape["secret_pointer"] == "/password" and shape["body_kind"] == "form"
    with_csrf = {**values, "form_body": {**values["form_body"], "csrf": ""},
                 "request_bindings": [*values["request_bindings"],
                                      {"source_action_id": "00000000-0000-4000-8000-000000000002",
                                       "capture_name": "csrf", "body_pointer": "/csrf"}]}
    assert dc.request_shape(with_csrf, "https://app.example.test:443/hub/login")["replayable"] is False
    huge = {**values, "form_body": {"username": "", "password": "", "blob": "x" * 20_000}}
    assert dc.request_shape(huge, "https://app.example.test:443/hub/login") ["replayable"] is False


def test_the_finding_names_the_pair_and_user_never_a_password():
    result = proof.evaluate({"pair": "accepted", "control": "rejected"}, attempt=ATTEMPT, username="admin")
    record = proof.finding_record(result, hunt_id="00000000-0000-4000-8000-00000000000a",
                                  action_id="00000000-0000-4000-8000-00000000000b")
    text = json.dumps(record)
    assert record["cwe"] == "CWE-1392" and record["evidence"]["proof_contract"] == "default_credentials/v1"
    assert record["evidence"]["default_credential"] == {"pair": "dc-01", "username": "admin"}
    assert record["fingerprint"].startswith("t:") and record["url"].endswith("/hub/login")
    assert not {"password", "secret"} & {key.lower() for key in record["evidence"]}
    assert "shakerscan-control" not in text


def test_the_control_reference_is_never_a_pair_a_planner_can_bind():
    assert dc.pair(proof.CONTROL_PAIR) is None
    with pytest.raises(ValueError):
        dc.validate_request_shape({"method": "POST", "form_body": {"p": ""}, "request_bindings": [
            {"default_credential": proof.CONTROL_PAIR, "credential_field": "secret", "body_pointer": "/p"}]})


def test_an_http_basic_step_is_a_get_with_the_pair_as_a_trusted_header():
    import base64
    shape = {"login_url": "http://t.test:8080/manager/html", "body_kind": "basic", "body": {},
             "user_pointer": None, "secret_pointer": None, "replayable": True}
    request = proof.build_request(shape, username="tomcat", secret="control-x")
    assert request["method"] == "GET" and request["path"] == "/manager/html"
    assert request["origin"] == "http://t.test:8080" and "form_body" not in request and "json_body" not in request
    scheme, token = request["trusted_headers"]["Authorization"].split(" ", 1)
    assert scheme == "Basic" and base64.b64decode(token) == b"tomcat:control-x"
