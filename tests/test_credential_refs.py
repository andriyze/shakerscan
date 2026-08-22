from datetime import datetime, timedelta, timezone

import pytest

from api.runtime.credential_refs import (
    CredentialReferenceError,
    select_hunt_principal_reference,
    validate_generic_credential_references,
)
from api.runtime.credential_store import CredentialProfileMetadata
from api.runtime.credentials import (
    build_credential_secret,
    parse_credential_secret,
    public_credential_configuration,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def _profile(
    profile_id,
    *,
    kind="bearer_token",
    slot="primary",
    target_kind="api",
    active=True,
    expires_at=None,
):
    kwargs = {"secret": "placeholder"}
    if kind in {"basic_auth", "form_login", "oauth_password"} or kind.startswith("ssh_"):
        kwargs["username"] = "operator"
    if kind == "form_login":
        kwargs["endpoint_url"] = "/login"
    if kind == "oauth_password":
        kwargs["endpoint_url"] = "/oauth/token"
    if kind == "oauth_client_credentials":
        kwargs.update({"client_id": "client", "endpoint_url": "/oauth/token"})
    if kind == "ssh_private_key_with_passphrase":
        kwargs["secondary_secret"] = "passphrase"
    configuration = public_credential_configuration(
        parse_credential_secret(kind, build_credential_secret(kind, **kwargs))
    )
    return CredentialProfileMetadata(
        profile_id=profile_id,
        target_kind=target_kind,
        target_id="22222222-2222-4222-8222-222222222222",
        name=profile_id,
        auth_kind=kind,
        principal_label=None,
        principal_slot=slot,
        configuration=configuration,
        current_version=2,
        record_version=3,
        is_active=active,
        expires_at=expires_at,
        rotated_at=NOW,
        created_at=NOW,
        updated_at=NOW,
        allowed_capabilities=("request.replay",),
    )


def test_primary_and_secondary_profiles_resolve_to_content_free_rows():
    profiles = [
        _profile("profile-a", slot="primary"),
        _profile("profile-b", kind="cookie", slot="secondary"),
    ]
    rows, missing = validate_generic_credential_references(
        {
            "primary_credential_profile_id": "profile-a",
            "secondary_credential_profile_id": "profile-b",
        },
        profiles,
        target_kind="api",
        now=NOW,
    )
    assert missing == {}
    assert [row["principal_slot"] for row in rows] == ["primary", "secondary"]
    assert all(row["secret_values_visible"] is False for row in rows)
    assert "placeholder" not in repr(rows)


@pytest.mark.parametrize(
    ("role", "profile", "message"),
    [
        ("primary_credential_profile_id", _profile("p", slot="secondary"), "incompatible"),
        ("cookie_credential_id", _profile("p", kind="bearer_token"), "incompatible"),
        (
            "ssh_credential_profile_id",
            _profile("p", kind="ssh_password", slot="ssh", target_kind="device"),
            "target kind",
        ),
        (
            "oauth_credential_profile_id",
            _profile("p", active=False),
            "inactive or expired",
        ),
        (
            "web_credential_profile_id",
            _profile("p", expires_at=NOW - timedelta(seconds=1)),
            "inactive or expired",
        ),
    ],
)
def test_role_target_status_and_expiry_are_fail_closed(role, profile, message):
    with pytest.raises(CredentialReferenceError, match=message):
        validate_generic_credential_references(
            {role: profile.profile_id}, [profile], target_kind="api", now=NOW,
        )


def test_missing_device_legacy_refs_are_returned_only_for_two_migration_keys():
    rows, missing = validate_generic_credential_references(
        {"ssh_credential_profile_id": "legacy-ssh"},
        [],
        target_kind="device",
        now=NOW,
        allow_missing_legacy_device_refs=True,
    )
    assert rows == []
    assert missing == {"ssh_credential_profile_id": "legacy-ssh"}

    with pytest.raises(CredentialReferenceError, match="unavailable"):
        validate_generic_credential_references(
            {"primary_credential_profile_id": "missing"},
            [],
            target_kind="device",
            now=NOW,
            allow_missing_legacy_device_refs=True,
        )


def test_hunt_principal_selection_is_exact_content_free_and_capability_bound():
    context = {
        "credential_refs": [{
            "profile_id": "profile-a",
            "profile_version": 4,
            "principal_slot": "primary",
            "allowed_capabilities": ["request.replay"],
            "source": "credential_profiles",
            "secret_values_visible": False,
        }],
    }
    assert select_hunt_principal_reference(context, "anonymous") is None
    assert select_hunt_principal_reference(context, "primary") == {
        "profile_id": "profile-a",
        "profile_version": 4,
        "principal_slot": "primary",
    }

    context["credential_refs"][0]["allowed_capabilities"] = ["web.probe"]
    with pytest.raises(CredentialReferenceError, match="exactly one usable"):
        select_hunt_principal_reference(context, "primary")


def test_hunt_principal_selection_rejects_ambiguity_and_unknown_slots():
    row = {
        "profile_id": "profile-a",
        "profile_version": 1,
        "principal_slot": "primary",
        "allowed_capabilities": [],
        "source": "credential_profiles",
    }
    with pytest.raises(CredentialReferenceError, match="exactly one usable"):
        select_hunt_principal_reference({"credential_refs": [row, dict(row)]}, "primary")
    with pytest.raises(CredentialReferenceError, match="must be anonymous"):
        select_hunt_principal_reference({"credential_refs": []}, "administrator")
