"""Principal contexts for server-owned workflow proofs, outside Hunt.

A workflow proof (BOLA, data exposure, create-based mass assignment) runs under the target's
own registered principals: one active principal per slot, joined to the target's own
credential profile by name. This is the resolver for every caller that is not a Hunt; a Hunt
resolves its attached credential list instead (``hunt/verification_credentials.py``) and
records every use.

Moved unchanged out of ``api.py``.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
import uuid

try:
    from workflow_experiment import WorkflowContractError
except ModuleNotFoundError:  # package import in host-side tests
    from api.workflow_experiment import WorkflowContractError

try:
    from redaction import is_sensitive_key
except ModuleNotFoundError as exc:
    if exc.name != "redaction":
        raise
    from scanner.redaction import is_sensitive_key

try:
    from secret_store import decrypt_secret
    from serialization import _decode_json_value, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from api.secret_store import decrypt_secret
    from api.serialization import _decode_json_value, row_to_dict


def workflow_identity_fingerprint(principal_metadata: Any, profile_metadata: Any, secret: str, auth_kind: str) -> str | None:
    sources = [_decode_json_value(principal_metadata) or {}, _decode_json_value(profile_metadata) or {}]
    identity: str | None = None
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("principal_identity", "account_id", "subject_id", "user_id", "email"):
            value = str(source.get(key) or "").strip().lower()
            if value:
                identity = f"{key}:{value}"
                break
        if identity:
            break
    if not identity and auth_kind == "authorization_header":
        token = secret.split(None, 1)[1] if secret.lower().startswith("bearer ") and " " in secret else secret
        parts = token.split(".")
        if len(parts) == 3:
            try:
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            except (ValueError, TypeError, json.JSONDecodeError):
                payload = {}
            if isinstance(payload, dict):
                for key in ("account_id", "user_id", "email", "sub"):
                    value = str(payload.get(key) or "").strip().lower()
                    if value and not (key == "sub" and value in {"user", "customer", "generic"}):
                        identity = f"{key}:{value}"
                        break
    return hashlib.sha256(identity.encode()).hexdigest() if identity else None


def workflow_cookie_map(secret: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in secret.split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name:
            cookies[name] = value
    return cookies


async def resolve_target_principal_contexts(
    conn: Any,
    target_uuid: uuid.UUID,
    used_slots: set[str],
) -> dict[str, dict[str, Any]]:
    rows = await conn.fetch(
        """
        SELECT p.id AS principal_id, p.label, p.role, p.tenant_id, p.auth_state,
               p.metadata_json AS principal_metadata, cp.id AS profile_id,
               cp.auth_kind, cp.secret_value, cp.metadata_json AS profile_metadata
        FROM target_principals p
        JOIN target_credential_profiles cp
          ON cp.target_id = p.target_id
         AND lower(cp.name) = lower(p.credential_profile)
        WHERE p.target_id = $1
          AND p.is_active = true
          AND cp.is_active = true
          AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
        ORDER BY p.updated_at DESC
        """,
        target_uuid,
    )
    candidates: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        payload = row_to_dict(row)
        slots = {str(payload.get("auth_state") or "").strip().lower()}
        if str(payload.get("role") or "").strip().lower() == "admin":
            slots.add("admin")
        tenant = str(payload.get("tenant_id") or "").strip().lower()
        if tenant:
            slots.add(f"tenant:{tenant}")
        for slot in slots:
            if slot in used_slots:
                candidates.setdefault(slot, []).append(payload)
    contexts: dict[str, dict[str, Any]] = {}
    for slot in sorted(used_slots - {"anonymous"}):
        matches = candidates.get(slot) or []
        if not matches:
            raise WorkflowContractError(f"principal_context_missing:{slot}")
        if len(matches) > 1:
            raise WorkflowContractError(f"principal_context_ambiguous:{slot}")
        row = matches[0]
        secret = str(decrypt_secret(row.get("secret_value")) or "").strip()
        if not secret:
            raise WorkflowContractError(f"principal_profile_secret_unavailable:{slot}")
        auth_kind = str(row.get("auth_kind") or "").strip()
        headers = {"Authorization": secret} if auth_kind == "authorization_header" else {}
        cookies = workflow_cookie_map(secret) if auth_kind == "cookie" else {}
        if not headers and not cookies:
            raise WorkflowContractError(f"principal_profile_auth_kind_invalid:{slot}")
        principal_metadata = _decode_json_value(row.get("principal_metadata")) or {}
        captured_refs = (
            principal_metadata.get("captured_refs")
            if isinstance(principal_metadata, dict)
            and isinstance(principal_metadata.get("captured_refs"), dict)
            else {}
        )
        contexts[slot] = {
            "principal_id": str(row.get("principal_id")),
            "profile_id": str(row.get("profile_id")),
            "identity_fingerprint": workflow_identity_fingerprint(
                row.get("principal_metadata"), row.get("profile_metadata"), secret, auth_kind
            ),
            "role": row.get("role"),
            "tenant_id": row.get("tenant_id"),
            "captured_refs": {
                str(key): str(value)
                for key, value in captured_refs.items()
                if not is_sensitive_key(str(key)) and value not in (None, "")
            },
            "headers": headers,
            "cookies": cookies,
        }
    return contexts
