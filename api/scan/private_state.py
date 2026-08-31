"""Opaque worker-private checkpoints for resumable Scan action dependencies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Mapping
import uuid

SCAN_PRIVATE_STATE_KEY_OPTION = "_scan_private_state_key"
SCAN_AUTH_SESSION_STATE_SCHEMA = "scan-auth-session-state/v2"
SCAN_AUTH_SESSION_STATE_KIND = "credential_session_state"
DEFAULT_SCAN_SESSION_TTL_SECONDS = 3_600
MAX_SCAN_SESSION_TTL_SECONDS = 86_400
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ScanPrivateStateError(ValueError):
    """A private checkpoint is absent, malformed, or detached from authority."""


def _fernet_class():
    try:
        from cryptography.fernet import Fernet
    except ModuleNotFoundError as exc:
        raise ScanPrivateStateError(
            "Scan private-state encryption is unavailable"
        ) from exc
    return Fernet


def generate_scan_private_state_key() -> str:
    return _fernet_class().generate_key().decode("ascii")


def validate_scan_private_state_key(value: Any) -> str:
    key = str(value or "").strip()
    try:
        _fernet_class()(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ScanPrivateStateError("Scan private-state key is invalid") from exc
    return key


def _binding(
    *,
    scan_id: str,
    action_id: str,
    action_digest: str,
    target_binding_digest: str,
    lane: str,
    credential_binding_digest: str,
) -> dict[str, str]:
    return {
        "scan_id": str(scan_id),
        "action_id": str(action_id),
        "action_digest": str(action_digest),
        "target_binding_digest": str(target_binding_digest),
        "lane": str(lane),
        "credential_binding_digest": str(credential_binding_digest),
    }


def seal_scan_auth_session_state(
    key: Any,
    *,
    scan_id: str,
    action_id: str,
    action_digest: str,
    target_binding_digest: str,
    lane: str,
    credential_binding_digest: str,
    headers: Mapping[str, Any],
    session_ref: str | None = None,
    profile_id: str | None = None,
    profile_version: int = 0,
    principal: str | None = None,
    established_at: datetime | None = None,
    expires_at: datetime | None = None,
    refresh_after: datetime | None = None,
    compatible_capabilities: tuple[str, ...] | list[str] = (),
    evidence_receipt_digest: str | None = None,
) -> dict[str, Any]:
    """Encrypt exact established headers while exposing only authority metadata."""
    normalized_headers = {
        str(name): str(value) for name, value in dict(headers or {}).items()
    }
    if not normalized_headers:
        raise ScanPrivateStateError("Scan auth session has no restorable headers")
    binding = _binding(
        scan_id=scan_id,
        action_id=action_id,
        action_digest=action_digest,
        target_binding_digest=target_binding_digest,
        lane=lane,
        credential_binding_digest=credential_binding_digest,
    )
    raw_current = established_at or datetime.now(timezone.utc)
    if raw_current.tzinfo is None:
        raise ScanPrivateStateError("Scan auth session establishment time is invalid")
    current = raw_current.astimezone(timezone.utc)
    if expires_at is not None and expires_at.tzinfo is None:
        raise ScanPrivateStateError("Scan auth session expiry is invalid")
    if refresh_after is not None and refresh_after.tzinfo is None:
        raise ScanPrivateStateError("Scan auth session refresh time is invalid")
    expiry = (
        expires_at.astimezone(timezone.utc)
        if expires_at is not None
        else current + timedelta(seconds=DEFAULT_SCAN_SESSION_TTL_SECONDS)
    )
    refresh = (
        refresh_after.astimezone(timezone.utc)
        if refresh_after is not None
        else expiry - timedelta(seconds=min(300, DEFAULT_SCAN_SESSION_TTL_SECONDS // 10))
    )
    if expiry <= current or expiry > current + timedelta(
        seconds=MAX_SCAN_SESSION_TTL_SECONDS
    ):
        raise ScanPrivateStateError("Scan auth session expiry is invalid")
    if refresh < current or refresh >= expiry:
        raise ScanPrivateStateError("Scan auth session refresh time is invalid")
    opaque_ref = str(session_ref or uuid.uuid4())
    try:
        uuid.UUID(opaque_ref)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ScanPrivateStateError("Scan auth session reference is invalid") from exc
    normalized_profile_id = str(profile_id or "").strip() or None
    if normalized_profile_id:
        try:
            uuid.UUID(normalized_profile_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ScanPrivateStateError("Scan auth session profile is invalid") from exc
        if int(profile_version) < 1:
            raise ScanPrivateStateError("Scan auth session profile version is invalid")
    elif int(profile_version) != 0:
        raise ScanPrivateStateError("Scan auth session profile version is invalid")
    capabilities = sorted({
        str(item).strip() for item in compatible_capabilities if str(item).strip()
    })
    if len(capabilities) > 128 or any(len(item) > 120 for item in capabilities):
        raise ScanPrivateStateError("Scan auth session capabilities are invalid")
    evidence_digest = str(evidence_receipt_digest or "").strip().lower() or None
    if evidence_digest is not None and not _DIGEST.fullmatch(evidence_digest):
        raise ScanPrivateStateError("Scan auth session evidence digest is invalid")
    metadata = {
        "session_ref": opaque_ref,
        "profile_id": normalized_profile_id,
        "profile_version": int(profile_version),
        "principal": str(principal or lane),
        "established_at": current.isoformat(),
        "expires_at": expiry.isoformat(),
        "refresh_after": refresh.isoformat(),
        "compatible_capabilities": capabilities,
        "evidence_receipt_digest": evidence_digest,
        "status": "active",
    }
    plaintext = json.dumps(
        {"binding": binding, "metadata": metadata, "headers": normalized_headers},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    token = _fernet_class()(
        validate_scan_private_state_key(key).encode("ascii")
    ).encrypt(plaintext).decode("ascii")
    return {
        "kind": SCAN_AUTH_SESSION_STATE_KIND,
        "schema_version": SCAN_AUTH_SESSION_STATE_SCHEMA,
        **binding,
        **metadata,
        "header_names": sorted(normalized_headers),
        "sealed_state": token,
        "secret_values_visible": False,
    }


def open_scan_auth_session_state(
    key: Any,
    observation: Mapping[str, Any],
    *,
    scan_id: str,
    action_id: str,
    action_digest: str,
    target_binding_digest: str,
    lane: str,
    credential_binding_digest: str,
    profile_id: str | None = None,
    profile_version: int | None = None,
    principal: str | None = None,
    capability_name: str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    expected = _binding(
        scan_id=scan_id,
        action_id=action_id,
        action_digest=action_digest,
        target_binding_digest=target_binding_digest,
        lane=lane,
        credential_binding_digest=credential_binding_digest,
    )
    row = dict(observation or {})
    if (
        row.get("kind") != SCAN_AUTH_SESSION_STATE_KIND
        or row.get("schema_version") != SCAN_AUTH_SESSION_STATE_SCHEMA
        or any(row.get(name) != value for name, value in expected.items())
    ):
        raise ScanPrivateStateError(
            "Scan auth session checkpoint differs from action authority"
        )
    try:
        plaintext = _fernet_class()(
            validate_scan_private_state_key(key).encode("ascii")
        ).decrypt(str(row.get("sealed_state") or "").encode("ascii"))
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ScanPrivateStateError(
            "Scan auth session checkpoint could not be opened"
        ) from exc
    if not isinstance(payload, Mapping) or payload.get("binding") != expected:
        raise ScanPrivateStateError(
            "Scan auth session plaintext differs from action authority"
        )
    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ScanPrivateStateError("Scan auth session metadata is unavailable")
    public_metadata = {
        name: row.get(name)
        for name in (
            "session_ref", "profile_id", "profile_version", "principal",
            "established_at", "expires_at", "refresh_after",
            "compatible_capabilities", "evidence_receipt_digest", "status",
        )
    }
    if dict(metadata) != public_metadata:
        raise ScanPrivateStateError("Scan auth session metadata changed")
    try:
        uuid.UUID(str(metadata.get("session_ref") or ""))
        expires = datetime.fromisoformat(
            str(metadata.get("expires_at") or "").replace("Z", "+00:00")
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise ScanPrivateStateError("Scan auth session metadata is invalid") from exc
    if expires.tzinfo is None:
        raise ScanPrivateStateError("Scan auth session expiry is invalid")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if str(metadata.get("status") or "") != "active" or expires <= current:
        raise ScanPrivateStateError("Scan auth session is expired or revoked")
    expected_profile_id = str(profile_id or "").strip() or None
    if expected_profile_id is not None and metadata.get("profile_id") != expected_profile_id:
        raise ScanPrivateStateError("Scan auth session profile changed")
    if profile_version is not None and int(
        metadata.get("profile_version") or 0
    ) != int(profile_version):
        raise ScanPrivateStateError("Scan auth session profile version changed")
    if principal is not None and str(metadata.get("principal") or "") != str(principal):
        raise ScanPrivateStateError("Scan auth session principal changed")
    if capability_name:
        allowed = {
            str(item) for item in metadata.get("compatible_capabilities") or ()
        }
        if str(capability_name) not in allowed:
            raise ScanPrivateStateError(
                "Scan auth session is incompatible with the capability"
            )
    headers = payload.get("headers")
    if not isinstance(headers, Mapping) or not headers:
        raise ScanPrivateStateError("Scan auth session checkpoint has no headers")
    normalized = {str(name): str(value) for name, value in headers.items()}
    if sorted(normalized) != list(row.get("header_names") or ()):
        raise ScanPrivateStateError(
            "Scan auth session checkpoint header names changed"
        )
    return normalized


__all__ = [
    "SCAN_AUTH_SESSION_STATE_KIND",
    "SCAN_PRIVATE_STATE_KEY_OPTION",
    "ScanPrivateStateError",
    "generate_scan_private_state_key",
    "open_scan_auth_session_state",
    "seal_scan_auth_session_state",
    "validate_scan_private_state_key",
]
