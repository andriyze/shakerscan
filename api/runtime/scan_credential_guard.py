"""Recheck cached Scan credential authority without loading secret material."""

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

from .credential_resolver import validate_worker_credential_authority
from .credential_store import PostgresCredentialProfileStore
try:
    from authenticated_assurance.snapshots import bound_snapshot, snapshot_authority_current
    from authenticated_assurance.store import AssuranceStore
except ModuleNotFoundError:
    from ..authenticated_assurance.snapshots import bound_snapshot, snapshot_authority_current
    from ..authenticated_assurance.store import AssuranceStore


def build_scan_credential_check(pool, *, options: Mapping[str, Any], target, scan_id: str, session_check=None):
    """Return an action-bound gate for generic credentials, or no gate for anonymous work.

    This is an authority check, not evidence that the application accepts the identity.
    In-flight requests still require the adapter's interruption path.
    """
    raw_refs = options.get("credential_profile_refs")
    if not raw_refs:
        return None
    refs = tuple(deepcopy(dict(ref)) for ref in raw_refs if isinstance(ref, Mapping)) if isinstance(raw_refs, list) else ()
    valid_shape = isinstance(raw_refs, list) and len(refs) == len(raw_refs) and 1 <= len(refs) <= 2
    approval_id = options.get("approval_receipt_id")
    scope_id = options.get("scope_receipt_id")
    action_name = str(options.get("credential_action_name") or "")
    store = PostgresCredentialProfileStore()

    async def check(_action):
        if not valid_shape:
            return "authentication_uncertain"
        try:
            async with asyncio.timeout(5), pool.acquire() as conn:
                await validate_worker_credential_authority(conn, owner_kind="scan", owner_id=scan_id,
                    target=target, approval_receipt_id=approval_id, scope_receipt_id=scope_id, action_name=action_name)
                for ref in refs:
                    pinned = bound_snapshot(ref)
                    if pinned is not None:
                        current = await AssuranceStore().get(conn, pinned.profile_id)
                        if not snapshot_authority_current(pinned, current, target.target_id):
                            return "authentication_uncertain"
                    profile = await store.get_profile(conn, profile_id=ref.get("profile_id"))
                    record_version = ref.get("credential_record_version")
                    if (not profile.is_active or
                            (profile.expires_at is not None and profile.expires_at <= datetime.now(timezone.utc)) or
                            profile.target_id != target.target_id or profile.target_kind != target.target_kind or
                            type(ref.get("profile_version")) is not int or profile.current_version != ref["profile_version"] or
                            (record_version is not None and (type(record_version) is not int or profile.record_version != record_version)) or
                            profile.auth_kind != ref.get("auth_kind") or profile.principal_slot != ref.get("principal_slot") or
                            tuple(profile.allowed_capabilities) != tuple(ref.get("allowed_capabilities") or ())):
                        return "authentication_uncertain"
        except Exception:
            # No database/authority exception text enters receipts or model context.
            # Cancellation propagates (CancelledError is a BaseException).
            return "authentication_uncertain"
        if session_check is not None:
            try:
                return session_check(_action)
            except Exception:
                return "authentication_uncertain"
        return None

    return check
