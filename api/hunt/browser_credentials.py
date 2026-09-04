"""Resolve existing encrypted Hunt sessions only inside the browser worker."""

from contextlib import asynccontextmanager
from typing import Any

try:
    from runtime.auth_session_store import PostgresAuthSessionStore
    from runtime.credential_resolver import validate_worker_credential_authority
except ModuleNotFoundError:
    from ..runtime.auth_session_store import PostgresAuthSessionStore
    from ..runtime.credential_resolver import validate_worker_credential_authority


@asynccontextmanager
async def browser_session_headers(pool: Any, *, prepared: Any, hunt_id: Any, policy: Any):
    if not prepared.session_ref:
        yield {}
        return
    async with pool.acquire() as conn:
        await validate_worker_credential_authority(
            conn, owner_kind="hunt", owner_id=str(hunt_id), target=prepared.target,
            approval_receipt_id=policy.approval_receipt_id,
            scope_receipt_id=prepared.target.scope_receipt_id,
            action_name=f"hunt.capability:{prepared.capability_name}",
        )
        session = await PostgresAuthSessionStore().load_for_worker(
            conn, session_ref=prepared.session_ref, owner_kind="hunt", owner_id=hunt_id,
            target=prepared.target, capability=prepared.capability_name,
        )
    headers = {}
    try:
        headers = session.headers()
        yield headers
    finally:
        headers.clear()
        session.close()
