"""Explicit saved browser-login selection at Scan admission and compilation.

QA credentials are separate from ordinary Scan authentication. A QA-only browser
profile never implicitly authenticates the crawler or any active-test family.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from fastapi import HTTPException
try:
    from runtime.browser_login_contract import (
        BROWSER_LOGIN_CAPABILITY, normalize_browser_login_reference,
    )
except ModuleNotFoundError:
    from ..runtime.browser_login_contract import (
        BROWSER_LOGIN_CAPABILITY, normalize_browser_login_reference,
    )


def browser_login_scan_limits(request: Any) -> dict[str, Any] | None:
    advanced = request.advanced.model_dump(exclude_none=True) if request.advanced is not None else None
    if not getattr(request, "browser_login_profile_ids", ()):
        return advanced
    placement = request.options.placement
    placement = placement.model_dump(exclude_none=True) if hasattr(placement, "model_dump") else placement or {}
    if request.options.parallel is True or placement.get("node_scope") == "remote":
        raise HTTPException(status_code=422, detail="browser login QA requires a single local worker")
    # Explicit QA cannot be duplicated into automatic parallel children. Narrow
    # the resolved worker ceiling rather than overriding a budget after admission.
    return {**(advanced or {}), "force_single_worker": True}


async def admit_scan_browser_login_profiles(conn, *, store, request, target_id, policy):
    requested = getattr(request, "browser_login_profile_ids", ())
    if not requested:
        return []
    # The scope ID is obtained by the existing approval validator immediately
    # after profile metadata admission; no decryption happens here.
    if not policy.active_testing or not policy.allow_state_changing_http:
        raise HTTPException(status_code=422, detail="browser login requires active_testing and allow_state_changing_http")
    try:
        ids = [str(uuid.UUID(value)) for value in requested]
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(status_code=422, detail="browser login profile IDs must be UUIDs") from None
    if not 1 <= len(ids) <= 2 or len(ids) != len(set(ids)):
        raise HTTPException(status_code=422, detail="select one or two distinct browser login profiles")
    profiles = await store.list_profiles(
        conn, target_kind=request.target_kind, target_id=target_id, include_inactive=True,
    )
    by_id = {profile.profile_id: profile for profile in profiles}
    result = []
    slots = set()
    now = datetime.now(timezone.utc)
    for profile_id in ids:
        profile = by_id.get(profile_id)
        if (profile is None or not profile.is_active
                or (profile.expires_at is not None and profile.expires_at <= now)
                or profile.target_id != str(target_id) or profile.target_kind != request.target_kind
                or profile.auth_kind not in {"form_login", "json_login"}
                or BROWSER_LOGIN_CAPABILITY not in profile.allowed_capabilities
                or not profile.configuration.get("browser_login_configured")
                or profile.principal_slot in slots):
            raise HTTPException(status_code=422, detail="browser login profile is unavailable, ambiguous, or not configured")
        slots.add(profile.principal_slot)
        result.append(normalize_browser_login_reference({
            "profile_id": profile_id, "profile_version": profile.current_version,
            "principal_slot": profile.principal_slot,
        }))
    return result
