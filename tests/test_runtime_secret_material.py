from __future__ import annotations

from api.runtime.secret_material import contains_secret_material, sensitive_key


def test_sensitive_key_detects_credential_conventions_without_substring_noise():
    for key in (
        "authorization", "apiKey", "access_token", "session-id", "client_secret",
    ):
        assert sensitive_key(key)
    for key in (
        "path", "page", "monkey", "keyboard", "public_id", "api_version",
        "access_level", "refresh_interval",
    ):
        assert not sensitive_key(key)


def test_secret_material_detects_nested_fields_and_inline_credentials():
    assert contains_secret_material({"query": {"token": "secret"}})
    assert contains_secret_material("/?access_token=secret")
    assert contains_secret_material("Authorization: Bearer secret")
    assert contains_secret_material(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
    )
    assert not contains_secret_material({
        "path": "/reports?page=2", "wait_until": "load", "max_requests": 5,
    })
