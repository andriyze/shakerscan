"""Browser-capture routes: open a capture, append batches of recorded flows, close it.

The recorder (``shakerscan record``) runs on the tester's machine; these routes are all the
server side it needs. Reads use the ordinary request-collection routes: a capture is listed in
the library, and ``GET /request-collections/{id}/requests?since_seq=`` follows it live.
"""

from __future__ import annotations

from typing import Any, Callable
import uuid

from fastapi import APIRouter, Body, HTTPException, Request

from .flows import LOCAL_OPERATOR, CaptureBatch, CaptureClose, CaptureCreate
from .store import apply_batch, close_capture, close_idle_captures, create_capture

try:
    from gateway_identity import operator_identity
except ModuleNotFoundError:  # package import in host-side tests
    from ..gateway_identity import operator_identity


router = APIRouter(tags=["request-collections"])
_pool_provider: Callable[[], Any] | None = None


def configure_capture_router(pool_provider: Callable[[], Any]) -> None:
    """Bind the application database without importing the API monolith."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool() -> Any:
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="request collection database is unavailable")
    return pool


def _actor(http_request: Request | None) -> str:
    """The gateway-asserted operator, or ``local-operator`` (the open-source engine)."""
    return (operator_identity(http_request) if http_request is not None else None) or LOCAL_OPERATOR


def _collection_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid request collection id") from exc


@router.post("/request-collections/captures")
async def create_browser_capture(request: CaptureCreate, http_request: Request = None):
    """Open a browser capture bound to one web target's exact origin.

    Returns ``{id, allowed_origins, limits, ...}``: the recorder uploads only flows of those
    origins, and the server checks every flow again."""
    async with _pool().acquire() as conn:
        return await create_capture(conn, request, created_by=_actor(http_request))


@router.post("/request-collections/{collection_id}/capture-batches")
async def append_capture_batch(collection_id: str, batch: CaptureBatch, http_request: Request = None):
    """Append one batch of recorded flows. Idempotent per ``(id, seq)``: an applied ``seq`` sent
    again with the same flows is acknowledged unchanged (with other flows: 409
    ``capture_seq_conflict``), the next ``seq`` is applied, any other is a 409 naming the next.
    Out-of-scope flows are counted and never stored; a closed capture refuses new batches; only
    the operator who opened the capture may add to it (403 ``capture_owner_mismatch``)."""
    async with _pool().acquire() as conn:
        return await apply_batch(conn, _collection_uuid(collection_id), batch, actor=_actor(http_request))


@router.post("/request-collections/{collection_id}/capture-close")
async def close_browser_capture(collection_id: str, request: CaptureClose = Body(default_factory=CaptureClose),
                                http_request: Request = None):
    """Close a capture: its batches become the collection's document, which a Scan or Hunt can
    then select. Closing a closed capture answers ``already_closed``; only the operator who
    opened it may close it."""
    if not isinstance(request, CaptureClose):  # called in-process without a body
        request = CaptureClose()
    async with _pool().acquire() as conn:
        return await close_capture(
            conn, _collection_uuid(collection_id), request.client_dropped, actor=_actor(http_request),
        )


__all__ = ["close_idle_captures", "configure_capture_router", "router"]
