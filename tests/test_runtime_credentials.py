import json

import pytest

from api.runtime.credentials import (
    CREDENTIAL_SECRET_SCHEMA,
    CredentialContractError,
    build_credential_secret,
    immediate_http_headers,
    parse_credential_secret,
    public_credential_configuration,
)


@pytest.mark.parametrize(
    ("kind", "kwargs"),
    [
        ("authorization_header", {"secret": "Bearer opaque"}),
        ("bearer_token", {"secret": "opaque"}),
        ("api_key_header", {"secret": "opaque", "header_name": "X-API-Key"}),
        ("cookie", {"secret": "session=opaque"}),
        ("basic_auth", {"username": "analyst", "secret": "opaque"}),
        (
            "form_login",
            {"username": "analyst", "secret": "opaque", "endpoint_url": "/login"},
        ),
        (
            "oauth_client_credentials",
            {
                "client_id": "scanner",
                "secret": "opaque",
                "endpoint_url": "https://example.test/oauth/token",
                "scopes": ["read", "write"],
            },
        ),
        (
            "oauth_password",
            {
                "username": "analyst",
                "secret": "opaque",
                "endpoint_url": "/oauth/token",
                "scopes": ["read"],
            },
        ),
        (
            "custom_headers",
            {"custom_headers": {"X-Tenant": "opaque-a", "X-Token": "opaque-b"}},
        ),
        ("ssh_password", {"username": "operator", "secret": "opaque"}),
        (
            "ssh_private_key",
            {"username": "operator", "secret": "-----BEGIN PRIVATE KEY-----\nkey\n"},
        ),
        (
            "ssh_private_key_with_passphrase",
            {
                "username": "operator",
                "secret": "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n",
                "secondary_secret": "opaque-passphrase",
            },
        ),
    ],
)
def test_credential_envelopes_round_trip_all_supported_kinds(kind, kwargs):
    encoded = build_credential_secret(kind, **kwargs)
    material = parse_credential_secret(kind, encoded)

    assert material["schema_version"] == CREDENTIAL_SECRET_SCHEMA
    assert material["auth_kind"] == kind


def test_immediate_http_projection_is_worker_private_and_exact():
    bearer = parse_credential_secret(
        "bearer_token",
        build_credential_secret("bearer_token", secret="opaque-token"),
    )
    basic = parse_credential_secret(
        "basic_auth",
        build_credential_secret("basic_auth", username="agent", secret="opaque-password"),
    )
    custom = parse_credential_secret(
        "custom_headers",
        build_credential_secret(
            "custom_headers", custom_headers={"X-Tenant": "one", "X-Token": "two"}
        ),
    )

    assert immediate_http_headers(bearer) == {"Authorization": "Bearer opaque-token"}
    assert immediate_http_headers(basic) == {
        "Authorization": "Basic YWdlbnQ6b3BhcXVlLXBhc3N3b3Jk"
    }
    assert immediate_http_headers(custom) == {"X-Tenant": "one", "X-Token": "two"}


def test_public_configuration_never_contains_secret_values():
    encoded = build_credential_secret(
        "ssh_private_key_with_passphrase",
        username="operator",
        secret="-----BEGIN OPENSSH PRIVATE KEY-----\nopaque-key\n",
        secondary_secret="opaque-passphrase",
    )
    public = public_credential_configuration(parse_credential_secret(
        "ssh_private_key_with_passphrase", encoded
    ))

    serialized = json.dumps(public)
    assert public["secret_values_visible"] is False
    assert public["username_configured"] is True
    assert public["secondary_secret_configured"] is True
    assert "opaque-key" not in serialized
    assert "opaque-passphrase" not in serialized
    assert "operator" not in serialized


@pytest.mark.parametrize("header_name", ["Host", "Content-Length", "Proxy-Authorization"])
def test_server_owned_headers_cannot_be_overridden(header_name):
    with pytest.raises(CredentialContractError, match="header_name is not allowed"):
        build_credential_secret(
            "api_key_header", secret="opaque", header_name=header_name
        )


def test_header_values_reject_request_splitting():
    with pytest.raises(CredentialContractError, match="line breaks"):
        build_credential_secret(
            "custom_headers", custom_headers={"X-Token": "opaque\r\nX-Escape: yes"}
        )


def test_passphrase_kind_requires_separate_passphrase():
    with pytest.raises(CredentialContractError, match="secondary_secret is required"):
        build_credential_secret(
            "ssh_private_key_with_passphrase",
            username="operator",
            secret="-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n",
        )


def test_interactive_credentials_cannot_project_direct_headers():
    material = parse_credential_secret(
        "form_login",
        build_credential_secret(
            "form_login", username="agent", secret="opaque", endpoint_url="/login"
        ),
    )
    with pytest.raises(CredentialContractError, match="target-bound login"):
        immediate_http_headers(material)


def test_worker_parser_accepts_only_two_legacy_raw_kinds():
    assert parse_credential_secret("cookie", "sid=legacy")["secret"] == "sid=legacy"
    with pytest.raises(CredentialContractError, match="envelope is invalid"):
        parse_credential_secret("bearer_token", "legacy-token")


def test_envelope_kind_cannot_be_reinterpreted():
    encoded = build_credential_secret("cookie", secret="sid=opaque")
    with pytest.raises(CredentialContractError, match="does not match"):
        parse_credential_secret("authorization_header", encoded)
