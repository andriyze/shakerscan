from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from api.runtime.credential_resolver import SecretHTTPHeaders
from api.runtime.credential_store import CredentialProfileMetadata
from api.runtime.scan_credentials import (
    SCAN_CREDENTIAL_CAPABILITY,
    ScanCredentialError,
    admit_scan_credential_profiles,
    bind_resolved_scan_credential,
    resolve_scan_http_principal,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)
TARGET_ID = "22222222-2222-4222-8222-222222222222"


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
        "login_url": "/login",
    }


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
        }],
    })

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


def test_scan_interactive_primary_is_explicitly_not_applied_without_session_capability():
    principal = resolve_scan_http_principal({
        "login_username": "operator",
        "login_password": "secret-password",
    })

    assert principal.authenticated is False
    assert principal.headers() == {}
    assert principal.public_dict()["reason"] == (
        "interactive_session_capability_not_available"
    )
    assert "secret-password" not in repr(principal)
