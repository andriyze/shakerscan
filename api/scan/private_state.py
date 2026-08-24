"""Opaque worker-private checkpoints for resumable Scan action dependencies."""

from __future__ import annotations

import json
from typing import Any, Mapping

SCAN_PRIVATE_STATE_KEY_OPTION = "_scan_private_state_key"
SCAN_AUTH_SESSION_STATE_SCHEMA = "scan-auth-session-state/v1"
SCAN_AUTH_SESSION_STATE_KIND = "credential_session_state"


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
    plaintext = json.dumps(
        {"binding": binding, "headers": normalized_headers},
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
