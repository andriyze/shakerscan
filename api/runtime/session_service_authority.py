"""Credential service reuse follows persisted Hunt authority, not a login-port lock.

A login origin is provenance and the refresh destination. An active, approved Hunt
may reuse that identity on other HTTP(S) services of the same frozen asset. These
checks consume existing authority; they never create a per-port approval prompt.
"""
from __future__ import annotations

from dataclasses import replace
import json
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid

from .models import TargetBinding


def service_origin(value: str) -> str:
    """Canonicalize a service origin without accepting a URL-shaped destination."""
    text = str(value or "")
    if not text or "\\" in text or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("session service origin is invalid")
    parsed = urlsplit(text)
    port = parsed.port
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or port == 0
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or "?" in text or "#" in text):
        raise ValueError("session service origin is invalid")
    host = parsed.hostname.lower().rstrip(".")
    authority = f"[{host}]" if ":" in host else host
    default = 443 if parsed.scheme == "https" else 80
    if port is not None and port != default:
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


def normalize_session_origin(target: TargetBinding, value: str | None) -> str | None:
    """Retain login provenance; equivalent default-port spellings are identical."""
    if value is None:
        # Do not invent which service logged in when a caller supplied several.
        if len(target.allowed_origins) != 1:
            return None
        value = target.allowed_origins[0]
    normalized = service_origin(value)
    if (urlsplit(normalized).hostname != target.canonical_host
            or normalized not in {service_origin(o) for o in target.allowed_origins}):
        raise ValueError("session service origin is outside the target binding")
    return normalized


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, Mapping):
        raise ValueError("persisted Hunt service authority is unavailable")
    return dict(value)


async def validate_session_service_use(
    conn: Any, *, target: TargetBinding, metadata: Any, capability: str,
) -> None:
    """Check cross-service authority immediately before session decryption.

    Exact-bound legacy sessions and Scan retain their existing semantics. For a
    Hunt's asset-bound session, the worker cannot grant another service merely by
    changing its TargetBinding: reconstruct that binding from the stored run and
    reload the existing approval. HTTP and untrusted TLS need no extra approval.
    """
    if metadata.owner_kind != "hunt":
        return
    origins = {service_origin(o) for o in target.allowed_origins}
    if metadata.service_origin and origins == {service_origin(metadata.service_origin)}:
        return
    if not metadata.service_origin and metadata.target_binding_digest == target.digest:
        return
    row = await conn.fetchrow(
        "SELECT id, target_id, device_target_id, target_kind, status, context_pack, policy_json "
        "FROM hunt_runs WHERE id=$1", uuid.UUID(str(metadata.owner_id)),
    )
    if not row:
        raise ValueError("session Hunt service authority is unavailable")
    run = dict(row)
    policy = _mapping(run.get("policy_json"))
    if run.get("status") not in {"active", "awaiting_planner"}:
        raise ValueError("session Hunt is no longer active")
    if policy.get("active_testing") is not True:
        raise ValueError("session reuse on another service requires the Hunt's active-testing authority")
    try:
        from hunt.target_binding import web_hunt_target
        from capabilities.http import resolve_hunt_http_origin
    except ModuleNotFoundError:
        from ..hunt.target_binding import web_hunt_target
        from ..capabilities.http import resolve_hunt_http_origin
    frozen, _ = web_hunt_target(run, _mapping(run.get("context_pack")), policy)
    if replace(frozen, allowed_origins=()).digest != replace(target, allowed_origins=()).digest:
        raise ValueError("session service selection changed the frozen Hunt asset")
    if not origins:
        raise ValueError("session service selection is empty")
    for origin in origins:
        resolve_hunt_http_origin(frozen, origin, policy)
    from .credential_resolver import validate_worker_credential_authority
    await validate_worker_credential_authority(
        conn, owner_kind="hunt", owner_id=str(metadata.owner_id), target=target,
        approval_receipt_id=policy.get("approval_receipt_id"),
        scope_receipt_id=policy.get("scope_receipt_id"),
        action_name=f"hunt.capability:{capability}",
    )
