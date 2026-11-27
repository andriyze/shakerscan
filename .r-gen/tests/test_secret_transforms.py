"""Discovered secrets, 2.11: what the worker reads from a value without disclosing it.

Every case checks the derived metadata carries no part of the value: no signature, salt, digest,
password or key material. Values are synthetic.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json

import pytest

from api.hunt.secret_transforms import DERIVED_SCHEMA, derive, still_valid

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def _b64(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def _jwt(header: dict, claims: dict, signature: str = "c2lnbmF0dXJlLXN5bnRoZXRpYy0xMjM0NTY") -> str:
    return f"{_b64(header)}.{_b64(claims)}.{signature}"


def _no_piece_of(value: str, derived: dict, *, public_prefix: str = "") -> None:
    """No 12-character piece of the value (after its public scheme prefix) is in the metadata."""
    text = json.dumps(derived)
    secret = value[len(public_prefix):] if value.startswith(public_prefix) else value
    for start in range(0, max(1, len(secret) - 12)):
        piece = secret[start:start + 12]
        assert piece not in text, f"derived metadata holds a piece of the value: {piece!r}"


def test_a_jwt_gives_its_header_claim_names_times_and_roles_never_its_signature():
    token = _jwt({"alg": "HS256", "typ": "JWT", "kid": "key-2026"},
                 {"sub": "user-17", "iss": "https://auth.example.test", "aud": ["api", "admin"],
                  "exp": 1_700_000_000, "iat": 1_699_990_000, "roles": ["admin", "user"],
                  "scope": "read write", "is_admin": True,
                  "api_key": "Zq81kXp0Lm29Qa7Wn4Rt", "nested": {"a": 1}})
    derived = derive(token, "jwt", now=NOW)
    assert derived["schema_version"] == DERIVED_SCHEMA and derived["transform"] == "jwt"
    assert (derived["alg"], derived["typ"], derived["kid"]) == ("HS256", "JWT", "key-2026")
    assert derived["claim_names"] == sorted(["sub", "iss", "aud", "exp", "iat", "roles", "scope",
                                             "is_admin", "api_key", "nested"])
    assert derived["subject"] == "user-17" and derived["issuer"] == "https://auth.example.test"
    assert derived["audience"] == ["api", "admin"] and derived["roles"] == ["admin", "user"]
    assert derived["scopes"] == ["read", "write"] and derived["flags"] == {"is_admin": True}
    assert derived["expired"] is True and derived["expires_at"].startswith("2023-11-14")
    assert derived["unsigned"] is False
    text = json.dumps(derived)
    assert "Zq81kXp0Lm29Qa7Wn4Rt" not in text, "a claim value shaped like a credential is dropped"
    assert "c2lnbmF0dXJl" not in text
    _no_piece_of(token, derived)


def test_an_unsigned_jwt_and_a_bearer_prefix_are_recognised():
    token = "Bearer " + _jwt({"alg": "none"}, {"sub": "x"}, signature="")
    derived = derive(token, "bearer_token", now=NOW)
    assert derived["transform"] == "jwt" and derived["unsigned"] is True


def test_expiry_is_recomputed_when_shown():
    derived = derive(_jwt({"alg": "HS256"}, {"exp": int(NOW.timestamp()) + 60}), "jwt", now=NOW)
    assert derived["expired"] is False
    later = datetime(2026, 10, 16, tzinfo=timezone.utc)
    assert still_valid(derived, now=later)["expired"] is True


@pytest.mark.parametrize(("value", "expected"), [
    ("$2b$12$" + "a" * 22 + "B" * 31, {"hash_type": "bcrypt", "cost": 12}),
    ("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
     {"hash_type": "argon2id", "memory_kib": 65536, "iterations": 3, "parallelism": 4}),
    ("$6$rounds=5000$saltsalt$" + "x" * 86, {"hash_type": "sha512_crypt", "rounds": 5000}),
    ("$1$saltsalt$" + "y" * 22, {"hash_type": "md5_crypt"}),
    ("pbkdf2_sha256$600000$saltsalt$" + "Q" * 44, {"hash_type": "django_pbkdf2_sha256", "iterations": 600000}),
    ("{SSHA}" + "W" * 32, {"hash_type": "ldap_ssha"}),
    ("5f4dcc3b5aa765d61d8327deb882cf99", {"hash_type": "md5_or_ntlm", "encoding": "hex"}),
    ("a" * 64, {"hash_type": "sha256"}),
])
def test_password_hashes_are_identified_by_scheme_and_work_factor_only(value, expected):
    derived = derive(value, "password")
    assert derived["transform"] == "hash"
    assert expected.items() <= derived.items()
    # The scheme name (``pbkdf2_sha256$``) is what is shown; the salt and digest never are.
    _no_piece_of(value, derived, public_prefix=value.split("$")[0] if "$" in value else "")


def test_a_private_key_gives_its_type_and_whether_it_is_encrypted():
    rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEsynthetic\n-----END RSA PRIVATE KEY-----"
    assert derive(rsa, "private_key") == {"schema_version": DERIVED_SCHEMA, "transform": "private_key",
                                          "key_type": "rsa", "encrypted": False}
    encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n-----END ENCRYPTED PRIVATE KEY-----"
    assert derive(encrypted, "private_key")["encrypted"] is True


def test_a_connection_url_gives_scheme_host_port_never_credentials():
    value = "postgresql://admin:Sup3rS3cretPw@db.internal:5432/prod"
    derived = derive(value, "connection_url")
    assert derived == {"schema_version": DERIVED_SCHEMA, "transform": "connection_url",
                       "scheme": "postgresql", "host": "db.internal", "port": 5432,
                       "has_username": True, "has_password": True, "database": "prod"}
    assert "admin" not in json.dumps(derived) and "Sup3rS3cretPw" not in json.dumps(derived)


def test_a_provider_key_gives_its_provider_by_prefix():
    assert derive("sk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd", "api_key")["provider"] == "stripe"
    assert derive("AKIA" + "IOSFODNN7EXAMPLE", "api_key")["provider"] == "aws_access_key_id"


@pytest.mark.parametrize("value", [
    "", "plain-password-123", "x" * 8_192, "eyJ.not.a.jwt", "eyJhbGciOi" + "!" * 40,
    "$2b$99$short", "‮\u0000odd", "postgresql://host-only", 12345, None,
    "eyJ" + "A" * 9_000 + ".eyJ" + "B" * 20 + ".x",
])
def test_hostile_or_unrecognised_values_derive_nothing_and_never_raise(value):
    derived = derive(value, "other")
    assert derived["schema_version"] == DERIVED_SCHEMA
    assert derived["transform"] in {"none", "hash", "jwt", "connection_url"}
    if isinstance(value, str) and len(value) > 20:
        _no_piece_of(value, derived)


def test_credential_shaped_claim_names_never_reach_the_planner():
    from api.hunt.discovered_secrets import planner_view

    marker = "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2"
    derived = derive(_jwt({"alg": "HS256"}, {marker: True, "sub": "fixture-user"}), "jwt")
    target = "11111111-1111-4111-8111-111111111111"
    shown = planner_view({"derived": derived, "found_on": target, "source": {}}, target)
    assert marker not in json.dumps(shown)
    assert shown["derived"]["claim_names"] == ["sub"]
    assert shown["derived"]["signature_verified"] is False


def test_old_stored_metadata_is_screened_again_on_operator_and_planner_reads():
    from api.hunt.discovered_secrets import _public, planner_view

    marker = "ghp_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2"
    stored = {"schema_version": DERIVED_SCHEMA, "transform": "jwt", "claim_names": [marker, "sub"],
              "subject": marker, "roles": ["reader", marker], "signature_verified": True,
              "raw": {"password": marker}}
    row = {"id": "11111111-1111-4111-8111-111111111111", "target_id": "11111111-1111-4111-8111-111111111111",
           "kind": "jwt", "label": "fixture", "length": 100, "source": {}, "first_seen_at": NOW,
           "last_seen_at": NOW, "seen_count": 1, "state": "active", "expires_at": NOW,
           "uses": 0, "last_used_at": None, "granted_to": [], "derived": json.dumps(stored)}
    public = _public(row)
    for shown in (public["derived"], planner_view({**public, "derived": stored}, row["target_id"])["derived"]):
        assert marker not in json.dumps(shown)
        assert "raw" not in shown and "subject" not in shown
        assert shown["roles"] == ["reader"]
        assert shown["claim_names"] == ["sub"]
        assert shown["signature_verified"] is False


def test_stored_metadata_is_bounded_and_invalid_times_are_not_proof_of_freshness():
    shown = still_valid({"schema_version": DERIVED_SCHEMA, "transform": "jwt", "claim_names": ["sub"] * 1000,
                         "roles": ["reader"] * 1000, "expires_at": "2026-10-15T00:00:00", "expired": False})
    assert len(shown["claim_names"]) <= 40 and len(shown["roles"]) <= 16
    assert "expires_at" not in shown and "expired" not in shown
    assert still_valid({"schema_version": "unknown", "transform": "jwt", "raw": "anything"}) is None
