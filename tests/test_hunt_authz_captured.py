"""authz.verify on two logins a Hunt made itself: only when the server can tell two accounts apart."""
from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace
import uuid

import pytest

from hunt import authz_captured
from hunt.authz_captured import account_name, distinction, resolve_captured_principals, token_subjects
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.credential_refs import CredentialReferenceError

HUNT = "22222222-2222-4222-8222-222222222222"
A, B = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def jwt(claims):
    part = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")  # noqa: E731
    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


def test_token_subjects_and_sign_in_account_names():
    assert token_subjects([jwt({"data": {"id": 22, "email": "A@x.test"}})]) == {"id": "22", "email": "a@x.test"}
    assert token_subjects(["opaque-session-cookie-value", "not.a.jwt"]) == {}
    assert account_name({"method": "POST", "json_body": {"email": "Bob@x.test", "password": "[withheld:1]"}}) == ("email", "bob@x.test")
    assert account_name(json.dumps({"method": "POST", "form_body": {"username": "alice", "password": "***"}})) == ("username", "alice")
    # Two account fields: the server cannot tell which the application signs in by.
    assert account_name({"method": "POST", "json_body": {"username": "alice", "email": "a@x.test"}}) is None
    assert account_name({"method": "GET", "json_body": {"email": "bob@x.test"}}) is None
    assert account_name({"method": "POST", "json_body": {"email": "[withheld:2]"}}) is None


@pytest.mark.parametrize("primary, secondary, accounts, expected", [
    ({"sub": "1"}, {"sub": "2"}, (None, None), "token_subject"),
    # Tokens that name the same subject are one account, whatever the sign-in requests said.
    ({"sub": "1"}, {"sub": "1"}, (("email", "a"), ("email", "b")), None),
    ({}, {}, (("username", "alice"), ("username", "bob")), "sign_in_account"),
    ({}, {}, (("username", "alice"), ("username", "alice")), None),
    ({}, {}, (("username", "alice"), None), None),
    # Different fields (alice by user name, b@x by email) may be one account.
    ({}, {}, (("username", "alice"), ("email", "b@x.test")), None),
    ({"sub": "1"}, {}, (None, None), None),
    # A per-session id never outranks the subject.
    ({"sub": "7", "id": "s1"}, {"sub": "7", "id": "s2"}, (None, None), None),
])
def test_two_logins_are_distinct_only_on_server_side_evidence(primary, secondary, accounts, expected):
    assert distinction(primary, secondary, *accounts) == expected


class _Pool:
    def __init__(self, inputs):
        self.inputs = inputs

    def acquire(self):
        inputs = self.inputs

        class Acquired:
            async def __aenter__(self):
                async def fetch(_sql, _hunt, ids):
                    return [{"input": inputs[str(item)]} for item in ids if str(item) in inputs]
                return SimpleNamespace(fetch=fetch)

            async def __aexit__(self, *_):
                return None
        return Acquired()


def _resolve(monkeypatch, tokens, inputs, *, values=None):
    async def identity(*, values, **_kwargs):
        source = values["request_bindings"][0]["source_action_id"]
        token = tokens[source]
        return {"Authorization": f"Bearer {token}"}, [token], "workflow_binding"

    monkeypatch.setattr(authz_captured, "resolve_artifact_identity", identity)
    values = values or {
        "primary_bindings": [{"source_action_id": A, "capture_name": "token", "header": "Authorization", "prefix": "Bearer "}],
        "secondary_bindings": [{"source_action_id": B, "capture_name": "token", "header": "Authorization", "prefix": "Bearer "}],
        "routes": ["/rest/basket/1"]}
    return asyncio.run(resolve_captured_principals(
        pool=_Pool(inputs), run={"id": HUNT}, hunt_id=HUNT, context={}, target=None, policy=None,
        hunt_policy={"active_testing": True}, target_url="http://app.test", values=values, stack=None,
        session_store=None))


def test_two_accounts_resolve_to_two_header_sets(monkeypatch):
    tokens = {A: jwt({"data": {"id": 1, "email": "a@x.test"}}), B: jwt({"data": {"id": 2, "email": "b@x.test"}})}
    primary, secondary, reason = _resolve(monkeypatch, tokens, {})
    assert primary != secondary and reason == "token_subject"
    # Opaque sessions: the two sign-in requests this Hunt sent named different accounts.
    opaque = {A: "s" * 32, B: "t" * 32}
    inputs = {A: {"method": "POST", "form_body": {"username": "alice", "password": "x"}},
              B: {"method": "POST", "form_body": {"username": "bob", "password": "y"}}}
    assert _resolve(monkeypatch, opaque, inputs)[2] == "sign_in_account"


def test_one_account_signed_in_twice_is_refused(monkeypatch):
    same_subject = {A: jwt({"sub": "7", "iat": 1}), B: jwt({"sub": "7", "iat": 2})}
    with pytest.raises(CredentialReferenceError, match="could not be told apart"):
        _resolve(monkeypatch, same_subject, {})
    # Opaque sessions with nothing that tells them apart, or the same sign-in name.
    opaque = {A: "s" * 32, B: "t" * 32}
    with pytest.raises(CredentialReferenceError, match="could not be told apart"):
        _resolve(monkeypatch, opaque, {})
    same_name = {A: {"method": "POST", "json_body": {"email": "a@x.test"}},
                 B: {"method": "POST", "json_body": {"email": "A@x.test"}}}
    with pytest.raises(CredentialReferenceError, match="could not be told apart"):
        _resolve(monkeypatch, opaque, same_name)
    # The same capture named twice.
    twice = {"primary_bindings": [{"source_action_id": A, "capture_name": "token", "header": "Authorization"}],
             "secondary_bindings": [{"source_action_id": A, "capture_name": "token", "header": "Authorization"}],
             "routes": ["/x"]}
    with pytest.raises(CredentialReferenceError, match="could not be told apart"):
        _resolve(monkeypatch, {A: jwt({"sub": "1"})}, {}, values=twice)


def test_the_contract_takes_one_identity_mode():
    binding = [{"source_action_id": str(uuid.UUID(A)), "capture_name": "token", "header": "Authorization",
                "prefix": "Bearer "}]
    other = [dict(binding[0], source_action_id=B)]
    CAPABILITY_REGISTRY.validate_hunt_input("authz.verify", {
        "routes": ["/rest/basket/1"], "primary_bindings": binding, "secondary_bindings": other})
    for bad in ({"routes": ["/x"], "primary_bindings": binding},
                {"routes": ["/x"], "primary_bindings": binding, "secondary_bindings": other,
                 "primary_principal": "primary", "secondary_principal": "secondary"}):
        with pytest.raises(CapabilityInputContractError):
            CAPABILITY_REGISTRY.validate_hunt_input("authz.verify", bad)


def test_one_account_named_differently_in_ignored_fields_is_refused(monkeypatch):
    # The app signs in by username; the planner varies an email it ignores.
    opaque = {A: "s" * 32, B: "t" * 32}
    inputs = {A: {"method": "POST", "json_body": {"username": "alice", "email": "a@x.test", "password": "p"}},
              B: {"method": "POST", "json_body": {"username": "alice", "email": "b@x.test", "password": "p"}}}
    with pytest.raises(CredentialReferenceError, match="could not be told apart"):
        _resolve(monkeypatch, opaque, inputs)


@pytest.mark.parametrize("first,second,same", [
    ("alice", "alice@x.test", True),      # one sign-in field that takes a user name or its e-mail
    ("alice@x.test", "alice", True),
    ("Alice ", "alice", True),
    ("ａlice", "alice", True),            # full-width letter: one name after Unicode folding
    ("alice", "bob", False),
    ("alice@x.test", "bob@x.test", False),
    ("alice@x.test", "alice@y.test", False),
    ("alice", "bob@alice.test", False),
])
def test_one_account_spelt_two_ways_is_not_two_sign_in_accounts(first, second, same):
    from hunt.authz_captured import same_account_spelling
    assert same_account_spelling(first, second) is same
    expected = None if same else "sign_in_account"
    assert distinction({}, {}, ("username", first.strip().lower()), ("username", second.strip().lower())) == expected
