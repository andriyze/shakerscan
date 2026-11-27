"""Reuse a live login that another run made with the same credential on the same target.

A Hunt (or a Scan's interactive identity lane) that is about to log in first looks for an
active session on the same target, from the same credential version, principal slot, login
kind and service origin. When one exists and has time left, the run starts from it instead of
logging in again: the session is adopted into the run's own state (a Hunt stores its own row),
so every per-run lookup, refresh and authority check stays exactly as before.

Reuse adds no authority. It happens after the run has validated its own authorization and
resolved the credential for this target through an active grant, i.e. after it was allowed to
log in with this credential anyway. A session whose credential was rotated, deactivated or is
no longer granted to the target is never reused. Any failure to reuse falls back to logging in.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Awaitable, Callable
import uuid

from capabilities.auth import (
    TargetBoundSessionCredential,
    WorkerPrivateScanSession,
    _endpoint_args,
    _public_observation,
    _session_evidence_digest,
    establish_target_bound_http_session,
)
from runtime.models import TargetBinding
from runtime.session_service_authority import normalize_session_origin

try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:  # package import in host-side tests
    from api.secret_store import decrypt_secret

logger = logging.getLogger(__name__)

# A session this close to expiry is not worth adopting: the run would refresh it at once.
MIN_REMAINING = timedelta(minutes=5)

REUSABLE_SESSION_SQL = """
    SELECT s.id, s.principal_label, s.encrypted_headers, s.established_at, s.expires_at,
           s.refresh_after
    FROM auth_sessions s
    JOIN credential_profiles p
      ON p.id=s.profile_id AND p.is_active=true AND p.current_version=s.profile_version
     AND (p.expires_at IS NULL OR p.expires_at > $8)
    JOIN credential_profile_bindings b
      ON b.profile_id=s.profile_id AND b.binding_kind='target' AND b.binding_id=$1
     AND b.is_active=true AND b.revoked_at IS NULL
    WHERE s.status='active' AND s.target_id=$2
      AND (s.target_kind=$3 OR (s.target_kind IN ('web','api','network') AND $3 IN ('web','api','network')))
      AND s.profile_id=$4 AND s.profile_version=$5 AND s.principal_slot=$6 AND s.auth_kind=$7
      AND s.service_origin IS NOT DISTINCT FROM $9
      AND s.refresh_after > $8 AND s.expires_at > $8 + $10::interval
    ORDER BY s.expires_at DESC, s.id
    LIMIT 1
"""

Establish = Callable[..., Awaitable[WorkerPrivateScanSession]]


def adopted_session(
    row: Any,
    credential: TargetBoundSessionCredential,
    *,
    target: TargetBinding,
) -> WorkerPrivateScanSession | None:
    """The run's private session built from a stored live one; None when it cannot be read."""
    try:
        headers = json.loads(decrypt_secret(row["encrypted_headers"]))
    except Exception:  # noqa: BLE001 - an unreadable session is simply not reused
        return None
    if not isinstance(headers, dict) or not headers:
        return None
    headers = {str(name): str(value) for name, value in headers.items()}
    _origin, _endpoint_path, public_path = _endpoint_args(credential.endpoint_url, target=target)
    cookies = headers.get("Cookie") or headers.get("cookie") or ""
    cookie_names = sorted({part.split("=", 1)[0].strip() for part in cookies.split(";") if "=" in part})
    session_ref = str(uuid.uuid4())
    principal = row.get("principal_label") or credential.principal or credential.lane
    capabilities = tuple(sorted(set(credential.compatible_capabilities)))
    observation = _public_observation(
        credential, public_path=public_path, established=True, headers=headers,
        cookie_names=cookie_names, response_status=None, request_count=0, reason=None,
    )
    observation.update({
        # The login this run started from instead of logging in; no request was sent.
        "reused": True,
        "reused_session_ref": str(row["id"]),
        "session_ref": session_ref,
        "profile_id": credential.profile_id,
        "profile_version": credential.profile_version or None,
        "principal": principal,
        "established_at": row["established_at"].isoformat(),
        "expires_at": row["expires_at"].isoformat(),
        "refresh_after": row["refresh_after"].isoformat(),
        "compatible_capabilities": list(capabilities),
    })
    digest = _session_evidence_digest(observation)
    observation["evidence_receipt_digest"] = digest
    return WorkerPrivateScanSession(
        lane=credential.lane,
        auth_kind=credential.auth_kind,
        binding_digest=credential.binding_digest,
        established=True,
        observation=observation,
        error=None,
        request_count=0,
        _headers=headers,
        session_ref=session_ref,
        profile_id=credential.profile_id,
        profile_version=credential.profile_version,
        principal=principal,
        established_at=row["established_at"],
        expires_at=row["expires_at"],
        refresh_after=row["refresh_after"],
        compatible_capabilities=capabilities,
        evidence_receipt_digest=digest,
    )


async def reuse_or_establish_session(
    pool: Any,
    credential: TargetBoundSessionCredential,
    *,
    target: TargetBinding,
    now: datetime | None = None,
    establish: Establish = establish_target_bound_http_session,
) -> WorkerPrivateScanSession:
    """Start from a live session for this credential and target, or log in."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if pool is not None and credential.profile_id and credential.profile_version:
        try:
            origin, _path, _public = _endpoint_args(credential.endpoint_url, target=target)
            service_origin = normalize_session_origin(target, origin)
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    REUSABLE_SESSION_SQL,
                    str(target.target_id),
                    uuid.UUID(str(target.target_id)),
                    target.target_kind,
                    uuid.UUID(str(credential.profile_id)),
                    int(credential.profile_version),
                    credential.lane,
                    credential.auth_kind,
                    current,
                    service_origin,
                    MIN_REMAINING,
                )
        except Exception as exc:  # noqa: BLE001 - reuse is an optimisation; log in instead
            logger.warning("session reuse lookup failed; logging in: %s", type(exc).__name__)
            row = None
        if row:
            session = adopted_session(row, credential, target=target)
            if session is not None:
                return session
    return await establish(credential, target=target)
