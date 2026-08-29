from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.runtime.credential_resolver import SecretHTTPHeaders
from api.runtime.credential_store import CredentialProfileMetadata
from api.runtime.scan_credentials import (
    SCAN_CREDENTIAL_CAPABILITY,
    ScanCredentialError,
    admit_scan_credential_profiles,
    bind_scan_session_headers,
    bind_resolved_scan_credential,
    resolve_scan_http_principal,
    resolve_scan_interactive_credential,
    scan_credential_resolution_capability,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
TARGET_ID = "22222222-2222-4222-8222-222222222222"


def test_canonical_scan_paths_never_auto_attach_target_credentials():
    source = (Path(__file__).resolve().parents[1] / "api" / "api.py").read_text(
        encoding="utf-8"
    )
    # The sole occurrence is the isolated legacy compatibility definition.
    # Scan, schedules, and ASM must instead carry explicit opaque profile IDs.
    assert source.count("_resolve_target_credential_profiles(") == 1


def _profile(
    profile_id: str,
    *,
    slot: str,
    kind: str = "bearer_token",
    target_kind: str = "web",
    active: bool = True,
    expires_at=None,
    capabilities=(SCAN_CREDENTIAL_CAPABILITY,),
    client_id_configured: bool = False,
) -> CredentialProfileMetadata:
    return CredentialProfileMetadata(
        profile_id=profile_id,
        target_kind=target_kind,
        target_id=TARGET_ID,
        name=profile_id,
        auth_kind=kind,
        principal_label=None,
        principal_slot=slot,
        configuration={
            "schema_version": "credential-secret/v1",
            "auth_kind": kind,
            "client_id_configured": client_id_configured,
        },
        current_version=3,
        record_version=4,
        is_active=active,
        expires_at=expires_at,
        rotated_at=NOW,
        created_at=NOW,
        updated_at=NOW,
        allowed_capabilities=capabilities,
    )


def test_scan_admission_freezes_distinct_target_bound_principals_without_secrets():
    primary = _profile("primary", slot="primary")
    secondary = _profile("secondary", slot="secondary", kind="cookie")
    rows = admit_scan_credential_profiles(
        [primary.profile_id, secondary.profile_id],
        [primary, secondary],
        target_id=TARGET_ID,
        target_kind="web",
        now=NOW,
    )
    assert [row["scan_lane"] for row in rows] == ["primary", "secondary"]
    assert [row["profile_version"] for row in rows] == [3, 3]
    assert all(row["secret_values_visible"] is False for row in rows)
    assert "primary-secret" not in repr(rows)


def test_scan_admission_accepts_semantic_static_capability_and_freezes_it():
    profile = _profile(
        "primary", slot="primary", capabilities=("http.request",),
    )

    rows = admit_scan_credential_profiles(
        [profile.profile_id], [profile],
        target_id=TARGET_ID, target_kind="web", now=NOW,
    )

    assert rows[0]["allowed_capabilities"] == ["http.request"]
    assert rows[0]["credential_resolution_capability"] == "http.request"


def test_scan_admission_requires_session_capability_for_interactive_profile():
    profile = _profile(
        "primary", slot="primary", kind="form_login",
        capabilities=("http.request",),
    )

    with pytest.raises(ScanCredentialError, match="semantic capability"):
        admit_scan_credential_profiles(
            [profile.profile_id], [profile],
            target_id=TARGET_ID, target_kind="web", now=NOW,
        )

    assert scan_credential_resolution_capability(
        ("auth.session.establish", "http.request"), auth_kind="form_login",
    ) == "auth.session.establish"


@pytest.mark.parametrize(
    ("profiles", "ids", "message"),
    [
        ([_profile("a", slot="primary")], ["a", "a"], "distinct"),
        ([_profile("a", slot="primary")], ["missing"], "unavailable"),
        ([_profile("a", slot="primary", active=False)], ["a"], "inactive"),
        ([_profile("a", slot="primary", expires_at=NOW - timedelta(seconds=1))], ["a"], "expired"),
        ([_profile("a", slot="ssh", kind="ssh_password")], ["a"], "HTTP"),
        ([_profile("a", slot="secondary", kind="api_key_header")], ["a"], "secondary"),
        ([_profile("a", slot="primary", capabilities=("request.replay",))], ["a"], "does not allow"),
        ([_profile("a", slot="primary", kind="oauth_password")], ["a"], "client ID"),
        (
            [_profile("a", slot="primary", kind="query_parameter")],
            ["a"],
            "request replay executor",
        ),
        (
            [_profile("a", slot="primary"), _profile("b", slot="service")],
            ["a", "b"],
            "more than one primary",
        ),
    ],
)
def test_scan_admission_rejects_ambiguous_or_unexecutable_profiles(profiles, ids, message):
    with pytest.raises(ScanCredentialError, match=message):
        admit_scan_credential_profiles(
            ids, profiles, target_id=TARGET_ID, target_kind="web", now=NOW,
        )


def test_scan_worker_binding_projects_primary_and_secondary_headers():
    primary = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="bearer_token"),
        http_headers=lambda: SecretHTTPHeaders({"Authorization": "Bearer primary-secret"}),
    )
    secondary = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="cookie"),
        http_headers=lambda: SecretHTTPHeaders({"Cookie": "session=secondary-secret"}),
    )
    options = bind_resolved_scan_credential({}, primary, scan_lane="primary")
    options = bind_resolved_scan_credential(options, secondary, scan_lane="secondary")
    assert options == {
        "auth_header": "Bearer primary-secret",
        "user2_cookies": "session=secondary-secret",
    }


def test_scan_worker_binding_preserves_custom_headers_and_form_login():
    header = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="custom_headers"),
        http_headers=lambda: SecretHTTPHeaders({"X-API-Key": "secret", "X-Tenant": "blue"}),
    )
    form = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="form_login"),
        interactive_http=lambda: SimpleNamespace(
            username="operator",
            secret="password",
            endpoint_url="/login",
            client_id=None,
            scopes=(),
        ),
    )
    options = bind_resolved_scan_credential({}, header, scan_lane="primary")
    assert options["auth_headers_json"] == '{"X-API-Key":"secret","X-Tenant":"blue"}'
    options = bind_resolved_scan_credential({}, form, scan_lane="secondary")
    assert options == {
        "user2_login_username": "operator",
        "user2_login_password": "password",
        "user2_login_url": "/login",
    }


def test_scan_worker_binding_keeps_primary_and_secondary_login_endpoints_distinct():
    primary = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="form_login"),
        interactive_http=lambda: SimpleNamespace(
            username="owner",
            secret="owner-password",
            endpoint_url="/owner/login",
            client_id=None,
            scopes=(),
        ),
    )
    secondary = SimpleNamespace(
        profile=SimpleNamespace(auth_kind="form_login"),
        interactive_http=lambda: SimpleNamespace(
            username="attacker",
            secret="attacker-password",
            endpoint_url="/attacker/login",
            client_id=None,
            scopes=(),
        ),
    )

    options = bind_resolved_scan_credential({}, primary, scan_lane="primary")
    options = bind_resolved_scan_credential(
        options, secondary, scan_lane="secondary",
    )
    secondary_credential = resolve_scan_interactive_credential(
        options, lane="secondary", capability_name="auth.session.establish",
    )

    assert options["login_url"] == "/owner/login"
    assert options["user2_login_url"] == "/attacker/login"
    assert secondary_credential is not None
    assert secondary_credential.public_endpoint_path == "/attacker/login"
    assert secondary_credential.capability_args()["lane"] == "secondary"


def test_scan_immediate_primary_principal_is_secret_free_and_digest_bound():
    principal = resolve_scan_http_principal({
        "auth_header": "Bearer primary-secret",
        "auth_headers_json": '{"X-Tenant":"blue"}',
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
            "allowed_capabilities": ["http.request"],
        }],
    }, capability_name="http.request")

    assert principal.authenticated is True
    assert principal.headers() == {
        "Authorization": "Bearer primary-secret",
        "X-Tenant": "blue",
    }
    assert principal.capability_args()["as_principal"] == "primary"
    assert len(principal.capability_args()["principal_binding_digest"]) == 64
    assert principal.public_dict() == {
        "lane": "primary",
        "authenticated": True,
        "source": "credential_profiles",
        "reason": None,
        "header_names": ["Authorization", "X-Tenant"],
        "profile_reference_count": 1,
        "secret_values_visible": False,
    }
    assert "primary-secret" not in repr(principal)
    assert "primary-secret" not in repr(principal.public_dict())


def test_scan_principal_applies_profile_only_to_allowed_semantic_action():
    options = {
        "auth_header": "Bearer primary-secret",
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "bearer_token",
            "principal_slot": "primary",
            "scan_lane": "primary",
            "allowed_capabilities": ["http.request"],
        }],
    }

    allowed = resolve_scan_http_principal(
        options, capability_name="http.request",
    )
    denied = resolve_scan_http_principal(
        options, capability_name="templates.scan",
    )

    assert allowed.authenticated is True
    assert denied.authenticated is False
    assert denied.headers() == {}
    assert denied.public_dict()["reason"] == "credential_capability_not_allowed"


def test_scan_interactive_primary_is_explicitly_not_applied_without_session_capability():
    principal = resolve_scan_http_principal({
        "login_username": "operator",
        "login_password": "secret-password",
    })

    assert principal.authenticated is False
    assert principal.headers() == {}
    assert principal.public_dict()["reason"] == (
        "interactive_session_not_established"
    )
    assert "secret-password" not in repr(principal)


def test_scan_interactive_profile_builds_content_free_session_binding():
    credential = resolve_scan_interactive_credential({
        "oauth_client_id": "scanner-client",
        "oauth_client_secret": "oauth-worker-private-secret",
        "oauth_token_url": "/oauth/token?tenant=blue",
        "oauth_scope": "read profile",
        "resolved_credential_profiles": [{
            "profile_id": "profile-1",
            "profile_version": 3,
            "auth_kind": "oauth_client_credentials",
            "principal_slot": "primary",
            "scan_lane": "primary",
            "allowed_capabilities": ["auth.session.establish"],
        }],
    }, capability_name="auth.session.establish")

    assert credential is not None
    assert credential.capability_args() == {
        "lane": "primary",
        "auth_kind": "oauth_client_credentials",
        "credential_binding_digest": credential.binding_digest,
        "endpoint_binding_digest": credential.endpoint_binding_digest,
        "endpoint_path": "/oauth/token?<redacted-query>",
    }
    assert len(credential.binding_digest) == 64
    assert len(credential.endpoint_binding_digest) == 64
    assert credential.public_dict()["secret_values_visible"] is False
    assert "oauth-worker-private-secret" not in repr(credential)
    assert "oauth-worker-private-secret" not in repr(credential.session_credential())


def test_username_only_scan_session_never_turns_missing_secret_into_text():
    credential = resolve_scan_interactive_credential({
        "login_username": "operator",
        "login_password": None,
        "login_url": "/login",
    })

    assert credential is not None
    session = credential.session_credential()
    assert session.username == "operator"
    assert session.secret == ""
    assert session.secret != "None"


def test_established_session_headers_become_an_immediate_primary_principal():
    options = bind_scan_session_headers(
        {
            "login_username": "operator",
            "login_password": "form-worker-private-secret",
            "resolved_credential_profiles": [{
                "profile_id": "profile-1",
                "profile_version": 3,
                "auth_kind": "form_login",
                "principal_slot": "primary",
                "scan_lane": "primary",
                "allowed_capabilities": [
                    "auth.session.establish", "http.request",
                ],
            }],
        },
        {"Cookie": "session=worker-private-cookie"},
        lane="primary",
    )
    principal = resolve_scan_http_principal(options, capability_name="http.request")

    assert principal.authenticated is True
    assert principal.headers() == {"Cookie": "session=worker-private-cookie"}
    assert principal.public_dict()["source"] == "credential_profiles"
    assert principal.public_dict()["reason"] is None


def test_scan_http_principal_rejects_case_insensitive_duplicate_headers():
    with pytest.raises(ScanCredentialError, match="headers are invalid"):
        resolve_scan_http_principal({
            "auth_header": "Bearer first",
            "auth_headers_json": json.dumps({
                "authorization": "Bearer second",
            }),
        })
