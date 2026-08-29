import base64
import json

import pytest

from api.runtime.credentials import (
    CREDENTIAL_SECRET_SCHEMA,
    IDENTITY_PAIR_KINDS,
    SSH_CREDENTIAL_KINDS,
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
        (
            "query_parameter",
            {"secret": "opaque-query-token", "parameter_name": "api_key"},
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


def test_query_parameter_configuration_exposes_only_the_parameter_name():
    encoded = build_credential_secret(
        "query_parameter", secret="opaque-query-token", parameter_name="api_key"
    )
    public = public_credential_configuration(
        parse_credential_secret("query_parameter", encoded)
    )

    assert public["parameter_name"] == "api_key"
    assert "opaque-query-token" not in json.dumps(public)


def test_query_parameter_requires_a_bounded_name():
    with pytest.raises(CredentialContractError, match="parameter_name is required"):
        build_credential_secret("query_parameter", secret="opaque-query-token")


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


# --- Identity pair kinds: either half alone is a complete identity ---------------------
#
# basic_auth, form_login and oauth_password accept a username, a secret, or both. A target
# may publish a shared secret with no account name, or an account whose secret arrives
# through a separate flow. SSH is excluded on purpose: a login with neither a password nor a
# key cannot authenticate, so accepting one would only defer the failure to execution time.

_PAIR_KIND_EXTRAS = {
    "basic_auth": {},
    "form_login": {"endpoint_url": "/login"},
    "oauth_password": {"endpoint_url": "/oauth/token"},
}


@pytest.mark.parametrize("kind", sorted(IDENTITY_PAIR_KINDS))
@pytest.mark.parametrize(
    ("label", "half"),
    [
        ("secret only", {"secret": "opaque"}),
        ("username only", {"username": "analyst"}),
        ("both", {"username": "analyst", "secret": "opaque"}),
    ],
)
def test_identity_pair_kinds_accept_either_half(kind, label, half):
    encoded = build_credential_secret(kind, **half, **_PAIR_KIND_EXTRAS[kind])
    material = parse_credential_secret(kind, encoded)

    assert material["auth_kind"] == kind
    assert bool(material["username"]) is ("username" in half)
    assert bool(material["secret"]) is ("secret" in half)


@pytest.mark.parametrize("kind", sorted(IDENTITY_PAIR_KINDS))
def test_identity_pair_kinds_reject_neither_half(kind):
    with pytest.raises(CredentialContractError, match="username, a secret, or both"):
        build_credential_secret(kind, **_PAIR_KIND_EXTRAS[kind])


@pytest.mark.parametrize("kind", sorted(SSH_CREDENTIAL_KINDS))
def test_ssh_kinds_still_require_both_halves(kind):
    extras = (
        {"secondary_secret": "opaque-passphrase"}
        if kind == "ssh_private_key_with_passphrase"
        else {}
    )
    # Only the private-key kinds accept line breaks in their secret.
    secret = (
        "opaque-password"
        if kind == "ssh_password"
        else "-----BEGIN OPENSSH PRIVATE KEY-----\nopaque\n"
    )
    with pytest.raises(CredentialContractError, match="secret is required"):
        build_credential_secret(kind, username="operator", **extras)
    with pytest.raises(CredentialContractError, match="username is required"):
        build_credential_secret(kind, secret=secret, **extras)


@pytest.mark.parametrize(
    ("kind", "extras"),
    [
        ("authorization_header", {}),
        ("bearer_token", {}),
        ("cookie", {}),
        ("api_key_header", {"header_name": "X-API-Key"}),
        ("query_parameter", {"parameter_name": "api_key"}),
        (
            "oauth_client_credentials",
            {"client_id": "scanner", "endpoint_url": "https://example.test/token"},
        ),
    ],
)
def test_non_pair_kinds_still_require_a_secret(kind, extras):
    """The relaxation is scoped to the pair kinds and widens nothing else."""
    with pytest.raises(CredentialContractError, match="secret is required"):
        build_credential_secret(kind, **extras)


def test_one_sided_basic_auth_projects_a_well_formed_header():
    """RFC 7617 allows either part of user-id ":" password to be empty.

    The username half was previously interpolated with str(), so a profile without one
    posted the literal string "None" as an account name.
    """
    secret_only = parse_credential_secret(
        "basic_auth", build_credential_secret("basic_auth", secret="opaque-password")
    )
    username_only = parse_credential_secret(
        "basic_auth", build_credential_secret("basic_auth", username="analyst")
    )

    assert immediate_http_headers(secret_only) == {
        "Authorization": "Basic " + base64.b64encode(b":opaque-password").decode()
    }
    assert immediate_http_headers(username_only) == {
        "Authorization": "Basic " + base64.b64encode(b"analyst:").decode()
    }
    assert "None" not in immediate_http_headers(secret_only)["Authorization"]


def test_public_configuration_reports_which_half_is_present():
    """A secret-only profile must be distinguishable from an empty one."""
    secret_only = public_credential_configuration(parse_credential_secret(
        "basic_auth", build_credential_secret("basic_auth", secret="opaque-password")
    ))
    username_only = public_credential_configuration(parse_credential_secret(
        "basic_auth", build_credential_secret("basic_auth", username="analyst")
    ))

    assert (secret_only["username_configured"], secret_only["secret_configured"]) == (False, True)
    assert (username_only["username_configured"], username_only["secret_configured"]) == (True, False)
    assert "opaque-password" not in json.dumps(secret_only)
    assert "analyst" not in json.dumps(username_only)
