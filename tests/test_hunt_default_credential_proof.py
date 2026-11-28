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


def test_an_evidence_reference_names_its_action_bare_or_with_the_action_prefix():
    # The sweep cites "action:<id>"; a candidate so cited was refused as citing no action.
    action = "473cdf19-e9d5-5b3d-b92a-ff1a15e67ad3"
    assert str(proof._uuid(action)) == action and str(proof._uuid(f"action:{action}")) == action
    assert proof._uuid("action:not-an-id") is None and proof._uuid("candidate:" + action) is None


@pytest.mark.parametrize("_id, _user, password, _source", dc.PAIRS)
def test_the_control_differs_from_the_pairs_password_in_value_only(_id, _user, password, _source):
    # A login that checks a password's length or characters before it authenticates must not be
    # able to refuse the control for its form: that read as "pair accepted, control refused".
    import re
    listed = {row[2] for row in dc.PAIRS}
    seen = set()
    for _ in range(40):
        control = proof.control_secret(password)
        seen.add(control)
        assert len(control) == len(password) and control not in listed
        assert re.sub(r"[a-z]", "a", re.sub(r"[A-Z]", "A", re.sub(r"[0-9]", "0", control))) == \
            re.sub(r"[a-z]", "a", re.sub(r"[A-Z]", "A", re.sub(r"[0-9]", "0", password)))
    assert len(seen) > 20, "random, not derived from the pair"


def test_the_control_is_never_a_value_to_avoid_and_exists_for_a_password_of_other_characters():
    assert all(proof.control_secret("root", avoid=("toor",)) != "toor" for _ in range(50))
    assert proof.control_secret("!!!") != "!!!"


def test_a_proof_that_sent_only_the_password_names_no_user():
    # The planner bound the pair's secret and wrote its own user name into the body: the pair's
    # user name was never sent, so the proof, the finding and its fingerprint do not name it.
    result = proof.evaluate({"pair": "accepted", "control": "rejected"}, attempt=ATTEMPT, username=None)
    assert result["username"] is None and result["promotable"] is True
    record = proof.finding_record(result, hunt_id="00000000-0000-4000-8000-00000000000a",
                                  action_id="00000000-0000-4000-8000-00000000000b")
    assert record["evidence"]["default_credential"] == {"pair": "dc-01"}
    assert "admin" not in json.dumps(record) and "None" not in json.dumps(record)
    named = proof.finding_record(
        proof.evaluate({"pair": "accepted", "control": "rejected"}, attempt=ATTEMPT, username="admin"),
        hunt_id="00000000-0000-4000-8000-00000000000a", action_id="00000000-0000-4000-8000-00000000000b")
    assert named["fingerprint"] != record["fingerprint"] and "admin" in named["title"]


class _ProofPool:
    """Labelled double of the attempts ledger for run_proof (its SQL is covered on PostgreSQL)."""

    def __init__(self, shape, pair_id="dc-01"):
        self.row = {"action_id": "00000000-0000-4000-8000-000000000001", "login_key": "k" * 64,
                    "login_host": "app.example.test", "pair_id": pair_id, "verdict": "accepted",
                    "request_shape": json.dumps(shape)}
        self.rows, self.pending = [], False

    def acquire(self):
        return self

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def fetchrow(self, sql, *args):
        return self.row

    async def fetch(self, sql, *args):
        return list(self.rows)

    async def fetchval(self, sql, *args):
        if "verdict='pending'" in sql:
            return 1 if self.pending else None
        return 0 if "count(*)" in sql else None

    async def execute(self, sql, *args):
        return "OK"


def _run_proof(pool, send, monkeypatch):
    import asyncio

    async def no_sleep(_seconds):
        return None

    monkeypatch.delenv("SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS", raising=False)
    return asyncio.run(proof.run_proof(
        pool, run={"id": "00000000-0000-4000-8000-00000000000a"}, context={},
        policy={"active_testing": True, "allow_state_changing_http": False},
        candidate={"evidence_refs": ["00000000-0000-4000-8000-000000000001"]},
        action_id="00000000-0000-4000-8000-00000000000b", send=send, sleep=no_sleep))


SECRET_ONLY = {"login_url": "https://app.example.test:443/hub/login", "body_kind": "form",
               "body": {"username": "alice", "password": ""}, "user_pointer": None,
               "secret_pointer": "/password", "replayable": True}


def test_run_proof_keeps_the_planners_user_name_and_reports_the_form_page_requests(monkeypatch):
    sent = []

    async def send(request):
        sent.append(request)
        return "accepted" if request["form_body"]["password"] == "admin" else "rejected"

    result = _run_proof(_ProofPool({**SECRET_ONLY, "form_prefetch": True}), send, monkeypatch)
    assert [r["form_body"]["username"] for r in sent] == ["alice", "alice"]
    control = sent[1]["form_body"]["password"]
    assert control != "admin" and len(control) == len("admin") and control.isalpha() and control.islower()
    assert result["promotable"] is True and result["username"] is None
    # Two logins, each after a read of the form's page; a login is not a state-changing charge.
    assert result["traffic"] == {"http_requests": 4, "login_posts": 2, "state_changing_requests": 0}


def test_run_proof_needs_only_the_authority_the_attempt_needed(monkeypatch):
    async def send(request):
        return "rejected"

    pool = _ProofPool(SECRET_ONLY)
    assert _run_proof(pool, send, monkeypatch)["traffic"] == {
        "http_requests": 1, "login_posts": 1, "state_changing_requests": 0}
    with pytest.raises(proof.DefaultCredentialProofRefused) as passive:
        import asyncio
        asyncio.run(proof.run_proof(pool, run={"id": "00000000-0000-4000-8000-00000000000a"}, context={},
                                    policy={"active_testing": False, "allow_state_changing_http": True},
                                    candidate={}, action_id="00000000-0000-4000-8000-00000000000b", send=send))
    assert passive.value.reason == "default_credentials_invalid"


def test_the_first_proof_step_is_paced_and_waits_for_an_unanswered_attempt(monkeypatch):
    sent = []

    async def send(request):
        sent.append(request)
        return "accepted"

    recent = _ProofPool(SECRET_ONLY)
    recent.rows = [{"pair_id": "dc-01", "verdict": "accepted", "age": 0.2}]
    with pytest.raises(proof.DefaultCredentialProofRefused) as paced:
        _run_proof(recent, send, monkeypatch)
    assert paced.value.reason == "default_credentials_paced"
    waiting = _ProofPool(SECRET_ONLY)
    waiting.rows = [{"pair_id": "dc-01", "verdict": "accepted", "age": 60.0}]
    waiting.pending = True
    with pytest.raises(proof.DefaultCredentialProofRefused) as awaited:
        _run_proof(waiting, send, monkeypatch)
    assert awaited.value.reason == "default_credentials_paced" and sent == []
    # Paced enough and nothing awaited: both steps go out (the proof paces its own second step).
    waiting.pending = False
    assert _run_proof(waiting, send, monkeypatch)["steps"] == {"pair": "accepted", "control": "accepted"}
