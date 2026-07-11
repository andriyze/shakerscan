"""Tests for paired-owner identity signals used by BOLA triage.

A smart_bola cross-user lead is a *suspected* finding until it can prove the
requester received an object it does not own. These tests pin the ownership
Identity in a body can strengthen a lead but cannot prove authorization failure.
Deterministic promotion requires the separate listing/expectation differential.
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import scanner_tools.access_control_checks as acc  # noqa: E402


def _jwt(claims: dict) -> str:
    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS256'})}.{b64(claims)}.sig"


class _Session:
    def __init__(self, token: str | None):
        headers = {"Authorization": f"Bearer {token}"} if token else {"Cookie": "session=abc"}
        self.config = type("Cfg", (), {"headers": headers})()


def test_principal_identity_decoded_from_jwt():
    s = _Session(_jwt({"sub": "42", "email": "user1@example.com"}))
    idents = acc._principal_identity_values(s)
    assert "user1@example.com" in idents and "42" in idents


def test_non_jwt_auth_yields_no_identity():
    assert acc._principal_identity_values(_Session(None)) == set()


def test_owner_identity_values_pulls_explicit_owner_fields():
    body = json.dumps({"order": {"id": 11, "user": {"email": "user1@example.com", "username": "alice"}}})
    vals = acc._owner_identity_values(body)
    assert "user1@example.com" in vals and "alice" in vals


def test_ownership_confirmed_when_owner_present_requester_absent():
    u1 = _Session(_jwt({"email": "user1@example.com"}))
    u2 = _Session(_jwt({"email": "user2@example.com"}))
    body = json.dumps({"order": {"id": 11, "user": {"email": "user1@example.com"}}})
    assert acc._confirm_cross_principal_ownership(body, u1, u2) is True


def test_third_party_identity_is_not_paired_owner_signal():
    u1 = _Session(_jwt({"email": "user1@example.com"}))
    u2 = _Session(_jwt({"email": "user2@example.com"}))
    body = json.dumps({"order": {"id": 11, "user": {"email": "victim@example.test"}}})
    assert acc._confirm_cross_principal_ownership(body, u1, u2) is False


def test_public_support_email_is_not_treated_as_owner():
    u1 = _Session(_jwt({"email": "user1@example.com"}))
    u2 = _Session(_jwt({"email": "user2@example.com"}))
    body = json.dumps({"profile": {"name": "Store", "support_email": "help@example.com"}})
    assert acc._owner_identity_values(body) == set()
    assert acc._confirm_cross_principal_ownership(body, u1, u2) is False


def test_ownership_not_confirmed_when_requester_also_present():
    # Shared/multi-tenant resource that legitimately lists both users -> not a clean BOLA.
    u1 = _Session(_jwt({"email": "user1@example.com"}))
    u2 = _Session(_jwt({"email": "user2@example.com"}))
    body = json.dumps({"members": ["user1@example.com", "user2@example.com"]})
    assert acc._confirm_cross_principal_ownership(body, u1, u2) is False


def test_ownership_fails_closed_without_resolvable_identity():
    # Opaque/cookie auth -> identity unknown -> stay suspected, never auto-confirm.
    body = json.dumps({"order": {"user": {"email": "user1@example.com"}}})
    assert acc._confirm_cross_principal_ownership(body, _Session(None), _Session(None)) is False


def test_ownership_fails_closed_when_owner_identity_absent_from_body():
    u1 = _Session(_jwt({"email": "user1@example.com"}))
    u2 = _Session(_jwt({"email": "user2@example.com"}))
    body = json.dumps({"order": {"id": 11, "status": "shipped"}})  # no identity leaked
    assert acc._confirm_cross_principal_ownership(body, u1, u2) is False
