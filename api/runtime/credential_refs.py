"""Content-free validation for Scan/Hunt credential profile references."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .credential_store import CredentialProfileMetadata
from .credentials import HTTP_CREDENTIAL_KINDS, SSH_CREDENTIAL_KINDS


GENERIC_CREDENTIAL_REF_KEYS = frozenset({
    "web_credential_profile_id",
    "ssh_credential_profile_id",
    "primary_credential_profile_id",
    "secondary_credential_profile_id",
    "service_credential_profile_id",
    "authorization_header_credential_id",
    "cookie_credential_id",
    "oauth_credential_profile_id",
})
class CredentialReferenceError(ValueError):
    """A submitted opaque reference is missing, expired, misbound, or ambiguous."""


def normalize_hunt_principal_slot(value: Any) -> str:
    slot = str(value or "").strip().lower()
    if slot in {"", "anonymous", "anon", "none"}:
        return "anonymous"
    if slot not in {"primary", "secondary", "service"}:
        raise CredentialReferenceError(
            "as_principal must be anonymous, primary, secondary, or service"
        )
    return slot


def select_hunt_principal_reference(
    context: Mapping[str, Any],
    value: Any,
    *,
    capability: str = "request.replay",
) -> dict[str, Any] | None:
    """Select exactly one content-free generic profile from an admitted Hunt context."""
    slot = normalize_hunt_principal_slot(value)
    if slot == "anonymous":
        return None
    matches: list[dict[str, Any]] = []
    for item in context.get("credential_refs") or []:
        if not isinstance(item, Mapping):
            continue
        if item.get("source") != "credential_profiles" or item.get("principal_slot") != slot:
            continue
        allowed = item.get("allowed_capabilities") or []
        if allowed and capability not in allowed:
            continue
        matches.append(dict(item))
    if len(matches) != 1:
        raise CredentialReferenceError(
            f"Hunt requires exactly one usable managed profile for principal '{slot}'"
        )
    profile_id = str(matches[0].get("profile_id") or "").strip()
    try:
        profile_version = int(matches[0].get("profile_version") or 0)
    except (TypeError, ValueError) as exc:
        raise CredentialReferenceError("managed principal version is invalid") from exc
    if not profile_id or len(profile_id) > 200 or profile_version < 1:
        raise CredentialReferenceError("managed principal reference is invalid")
    return {
        "profile_id": profile_id,
        "principal_slot": slot,
        "profile_version": profile_version,
    }


def _role_compatible(role: str, profile: CredentialProfileMetadata) -> bool:
    if role == "ssh_credential_profile_id":
        return profile.auth_kind in SSH_CREDENTIAL_KINDS and profile.principal_slot == "ssh"
    if role == "web_credential_profile_id":
        return profile.auth_kind in HTTP_CREDENTIAL_KINDS and profile.principal_slot != "ssh"
    if role == "primary_credential_profile_id":
        return profile.principal_slot == "primary" and profile.auth_kind in HTTP_CREDENTIAL_KINDS
    if role == "secondary_credential_profile_id":
        return profile.principal_slot == "secondary" and profile.auth_kind in HTTP_CREDENTIAL_KINDS
    if role == "service_credential_profile_id":
        return profile.principal_slot == "service" and profile.auth_kind in HTTP_CREDENTIAL_KINDS
    if role == "authorization_header_credential_id":
        return profile.auth_kind == "authorization_header"
    if role == "cookie_credential_id":
        return profile.auth_kind == "cookie"
    if role == "oauth_credential_profile_id":
        return profile.auth_kind in {"oauth_client_credentials", "oauth_password"}
    return False


def validate_generic_credential_references(
    refs: Mapping[str, str],
    profiles: Sequence[CredentialProfileMetadata],
    *,
    target_kind: str,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    unknown = sorted(set(refs) - GENERIC_CREDENTIAL_REF_KEYS)
    if unknown:
        raise CredentialReferenceError(
            f"unsupported credential reference fields: {', '.join(unknown)}"
        )
    normalized_now = now or datetime.now(timezone.utc)
    if normalized_now.tzinfo is None:
        raise CredentialReferenceError("credential validation time must be timezone-aware")
    by_id = {profile.profile_id: profile for profile in profiles}
    rows: list[dict[str, Any]] = []
    missing: dict[str, str] = {}
    for role, raw_profile_id in refs.items():
        profile_id = str(raw_profile_id or "").strip()
        profile = by_id.get(profile_id)
        if profile is None:
            raise CredentialReferenceError(
                f"{role} is unavailable or bound to another target"
            )
        expires_at = profile.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not profile.is_active or (expires_at is not None and expires_at <= normalized_now):
            raise CredentialReferenceError(f"{role} is inactive or expired")
        if profile.target_kind != target_kind:
            raise CredentialReferenceError(f"{role} target kind does not match the Hunt")
        if not _role_compatible(role, profile):
            raise CredentialReferenceError(
                f"{role} is incompatible with {profile.auth_kind}/{profile.principal_slot}"
            )
        rows.append({
            "role": role,
            "profile_id": profile.profile_id,
            "auth_kind": profile.auth_kind,
            "principal_slot": profile.principal_slot,
            "profile_version": profile.current_version,
            "allowed_capabilities": list(profile.allowed_capabilities),
            "configuration": dict(profile.configuration),
            "source": "credential_profiles",
            "secret_values_visible": False,
        })
    return rows, missing
