"""Selected HTTP principals reuse a live, revalidated managed login."""
from __future__ import annotations

import uuid
from typing import Any

from runtime.credential_refs import select_hunt_principal_reference
from runtime.credential_resolver import WorkerCredentialResolver, CredentialResolutionError
from runtime.auth_session_store import AuthSessionStoreError


async def resolve_http_principal(conn: Any, *, context: Any, target: Any, authority: Any,
                                 hunt_id: Any, principal: str, origin: str,
                                 stack: Any, session_store: Any) -> tuple[dict[str, str], Any]:
    reference = select_hunt_principal_reference(context, principal, capability="http.request")
    resolved = await stack.enter_async_context(WorkerCredentialResolver().resolve(
        conn, profile_id=reference["profile_id"], target=target,
        capability="http.request", authority=authority,
    ))
    if (resolved.profile.current_version != reference["profile_version"]
            or resolved.profile.principal_slot != principal):
        raise CredentialResolutionError("managed Hunt principal changed after admission")
    if resolved.profile.auth_kind not in {"form_login", "json_login", "oauth_password", "oauth_client_credentials"}:
        return resolved.http_headers().as_dict(), None
    # Only this Hunt's selected profile/version can supply the principal. The normal
    # store then checks live grants, expiry, scope binding and same-asset service authority
    # before decrypting. Do not let an arbitrary session silently replace the selection.
    rows = await conn.fetch("""SELECT id FROM auth_sessions
        WHERE owner_kind='hunt' AND owner_id=$1 AND target_id=$2
          AND profile_id=$3 AND profile_version=$4 AND principal_slot=$5
          AND status='active' AND expires_at>NOW() AND refresh_after>NOW()
        ORDER BY established_at DESC, id DESC LIMIT 32""",
        uuid.UUID(str(hunt_id)), uuid.UUID(target.target_id),
        uuid.UUID(reference["profile_id"]), reference["profile_version"], principal)
    for row in rows:
        try:
            session = await session_store.load_for_worker(conn, session_ref=row["id"],
                owner_kind="hunt", owner_id=hunt_id, target=target,
                capability="http.request", selected_origins=(origin,))
        except AuthSessionStoreError:
            continue
        return session.headers(), session
    raise CredentialResolutionError(
        "No compatible current login for this principal; call auth.session.establish or auth.session.refresh")
