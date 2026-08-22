"""Canonical generic credential admission and worker-private Scan binding."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Mapping, Sequence

from .credential_resolver import CredentialResolutionError, ResolvedCredential
from .credential_store import CredentialProfileMetadata
from .credentials import HTTP_CREDENTIAL_KINDS, IMMEDIATE_HTTP_HEADER_KINDS


SCAN_CREDENTIAL_CAPABILITY = "scan.execute"
MAX_SCAN_CREDENTIAL_PROFILES = 2
_PRIMARY_SLOTS = frozenset({"primary", "service"})
_SECONDARY_KINDS = frozenset({
    "authorization_header",
    "bearer_token",
    "cookie",
    "basic_auth",
    "form_login",
})


class ScanCredentialError(ValueError):
    """A Scan credential selection is ambiguous, unsupported, or no longer valid."""


def admit_scan_credential_profiles(
    profile_ids: Sequence[Any],
    profiles: Sequence[CredentialProfileMetadata],
    *,
    target_id: Any,
    target_kind: str,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Freeze content-free profile/version references for one Scan."""
    requested = [str(value or "").strip() for value in profile_ids]
    if not requested or any(not value for value in requested):
        return []
    if len(requested) > MAX_SCAN_CREDENTIAL_PROFILES:
        raise ScanCredentialError(
            f"Scan accepts at most {MAX_SCAN_CREDENTIAL_PROFILES} credential profiles"
        )
    if len(requested) != len(set(requested)):
        raise ScanCredentialError("Scan credential profile IDs must be distinct")
    normalized_kind = str(target_kind or "").strip().lower()
    if normalized_kind not in {"web", "api"}:
        raise ScanCredentialError("Scan credential target kind must be web or api")
    normalized_target_id = str(target_id or "").strip()
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ScanCredentialError("Scan credential validation time must be timezone-aware")

    by_id = {profile.profile_id: profile for profile in profiles}
    rows: list[dict[str, Any]] = []
    lanes: set[str] = set()
    for profile_id in requested:
        profile = by_id.get(profile_id)
        if profile is None:
            raise ScanCredentialError(
                "Scan credential profile is unavailable or bound to another target"
            )
        expires_at = profile.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if not profile.is_active or (expires_at is not None and expires_at <= current):
            raise ScanCredentialError("Scan credential profile is inactive or expired")
        if profile.target_id != normalized_target_id or profile.target_kind != normalized_kind:
            raise ScanCredentialError("Scan credential profile target binding does not match")
        if profile.auth_kind not in HTTP_CREDENTIAL_KINDS:
            raise ScanCredentialError("Scan credentials must use an HTTP authentication kind")
        if profile.auth_kind == "query_parameter":
            raise ScanCredentialError(
                "query-parameter credentials require the target-bound request replay executor"
            )
        slot = profile.principal_slot
        if slot in _PRIMARY_SLOTS:
            lane = "primary"
        elif slot == "secondary":
            lane = "secondary"
        else:
            raise ScanCredentialError("Scan credentials must use primary, secondary, or service slots")
        if lane in lanes:
            raise ScanCredentialError(f"Scan has more than one {lane} credential profile")
        if lane == "secondary" and profile.auth_kind not in _SECONDARY_KINDS:
            raise ScanCredentialError(
                f"secondary Scan identity does not support {profile.auth_kind}"
            )
        if (
            profile.auth_kind == "oauth_password"
            and not bool(profile.configuration.get("client_id_configured"))
        ):
            raise ScanCredentialError("OAuth password Scan credentials require a client ID")
        allowed = tuple(profile.allowed_capabilities)
        if allowed and SCAN_CREDENTIAL_CAPABILITY not in allowed:
            raise ScanCredentialError(
                f"Scan credential profile does not allow {SCAN_CREDENTIAL_CAPABILITY}"
            )
        lanes.add(lane)
        rows.append({
            "profile_id": profile.profile_id,
            "profile_version": profile.current_version,
            "target_kind": profile.target_kind,
            "principal_slot": slot,
            "scan_lane": lane,
            "auth_kind": profile.auth_kind,
            "allowed_capabilities": list(allowed),
            "source": "credential_profiles",
            "secret_values_visible": False,
        })
    return rows


def bind_resolved_scan_credential(
    options: Mapping[str, Any],
    resolved: ResolvedCredential,
    *,
    scan_lane: str,
) -> dict[str, Any]:
    """Project a worker-private resolved profile into the legacy scanner handoff."""
    lane = str(scan_lane or "").strip().lower()
    if lane not in {"primary", "secondary"}:
        raise ScanCredentialError("resolved Scan credential lane is invalid")
    kind = resolved.profile.auth_kind
    result = dict(options)

    if kind in IMMEDIATE_HTTP_HEADER_KINDS:
        headers = resolved.http_headers().as_dict()
        lowered = {name.lower(): name for name in headers}
        if lane == "secondary":
            if set(lowered) == {"authorization"}:
                result["user2_header"] = headers[lowered["authorization"]]
            elif set(lowered) == {"cookie"}:
                result["user2_cookies"] = headers[lowered["cookie"]]
            else:
                raise ScanCredentialError(
                    "secondary Scan credentials must resolve to Authorization or Cookie"
                )
        elif set(lowered) == {"authorization"}:
            result["auth_header"] = headers[lowered["authorization"]]
        elif set(lowered) == {"cookie"}:
            result["auth_cookies"] = headers[lowered["cookie"]]
        else:
            result["auth_headers_json"] = json.dumps(
                headers, sort_keys=True, separators=(",", ":")
            )
        return result

    interactive = resolved.interactive_http()
    if kind == "form_login":
        if lane == "secondary":
            result["user2_login_username"] = interactive.username
            result["user2_login_password"] = interactive.secret
        else:
            result["login_username"] = interactive.username
            result["login_password"] = interactive.secret
            result["auto_auth"] = True
        result["login_url"] = interactive.endpoint_url
        return result

    if lane == "secondary":
        raise ScanCredentialError("secondary Scan credentials cannot use OAuth exchange")
    if not interactive.client_id:
        raise CredentialResolutionError("OAuth Scan credential requires a client ID")
    result["oauth_client_id"] = interactive.client_id
    result["oauth_client_secret"] = (
        interactive.secret if kind == "oauth_client_credentials" else None
    )
    result["oauth_username"] = interactive.username if kind == "oauth_password" else None
    result["oauth_password"] = interactive.secret if kind == "oauth_password" else None
    result["oauth_token_url"] = interactive.endpoint_url
    result["oauth_scope"] = " ".join(interactive.scopes)
    return result
