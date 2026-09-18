"""Read-only, paginated Service Intelligence API under Exposure."""
from __future__ import annotations

import asyncio
from typing import Literal
import uuid

from fastapi import APIRouter, HTTPException, Query, Request

from .service_actions import canonical_registry
from .service_intel import load_service_intelligence
from .service_store import service_page

router = APIRouter()


@router.get("/exposure/services")
async def exposure_services(
    request: Request,
    target_kind: Literal["all", "web", "device"] = "all",
    target_id: uuid.UUID | None = None,
    root_domain: str | None = Query(None, max_length=253, pattern=r"^[A-Za-z0-9.-]+$"),
    search: str = Query("", max_length=200),
    limit: int = Query(10, ge=1, le=25),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    """Existing service evidence, candidate CVEs and advisory activities.

    Pagination is over targets. Search matches target name/locator, not a capped
    global service list. No request parameter can grant scan/credential authority.
    """
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database is not ready")
    snapshot, matcher = await asyncio.to_thread(load_service_intelligence)
    registry = canonical_registry()
    async with pool.acquire() as conn:
        async with conn.transaction(isolation="repeatable_read", readonly=True):
            return await service_page(
                conn, target_kind=target_kind, target_id=target_id, root_domain=root_domain,
                search=search, limit=limit, offset=offset,
                snapshot=snapshot, matcher=matcher, registry=registry,
            )
