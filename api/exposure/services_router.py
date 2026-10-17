"""Read-only, paginated Service Intelligence API under Exposure."""
from __future__ import annotations

import asyncio
from typing import Literal
import uuid

from fastapi import APIRouter, HTTPException, Query, Request, Response

try:
    from list_compat import mark_deprecated, v1_page, wants_list_v1
    from list_contract import CURSOR_MAX_LENGTH
except ModuleNotFoundError:  # package import layout
    from ..list_compat import mark_deprecated, v1_page, wants_list_v1
    from ..list_contract import CURSOR_MAX_LENGTH
from .service_actions import canonical_registry
from .service_intel import load_service_intelligence
from .service_store import service_page, service_page_v1

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
    cursor: str | None = Query(None, max_length=CURSOR_MAX_LENGTH),
    count: Literal["none", "estimate", "exact"] | None = None,
    response: Response = None,
):
    """Existing service evidence, candidate CVEs and advisory activities.

    Pagination is over targets. Search matches target name/locator, not a capped
    global service list. No request parameter can grant scan/credential authority.
    list/v1 (``cursor``/``count``): keyset pages of targets (kind, then id), at most 25 per page.
    """
    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Database is not ready")
    snapshot, matcher = await asyncio.to_thread(load_service_intelligence)
    registry = canonical_registry()
    v1 = wants_list_v1(cursor=cursor, count=count, fields=None, since=None)
    async with pool.acquire() as conn:
        async with conn.transaction(isolation="repeatable_read", readonly=True):
            if v1:
                page = v1_page(limit=limit, cursor=cursor, sort=None, fields=None, count=count, since=None,
                               default_limit=10)
                return await service_page_v1(
                    conn, page, target_kind=target_kind, target_id=target_id, root_domain=root_domain,
                    search=search, snapshot=snapshot, matcher=matcher, registry=registry,
                )
            mark_deprecated(response)
            return await service_page(
                conn, target_kind=target_kind, target_id=target_id, root_domain=root_domain,
                search=search, limit=limit, offset=offset,
                snapshot=snapshot, matcher=matcher, registry=registry,
            )
