"""Export endpoints for the HTTP transaction archive."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

try:
    from runtime.http_archive_reader import (
        EXPORT_FORMATS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        count_transactions,
        export_document,
        read_transactions,
    )
except ModuleNotFoundError:  # package import layout
    from .http_archive_reader import (
        EXPORT_FORMATS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        count_transactions,
        export_document,
        read_transactions,
    )


router = APIRouter()
_pool_provider: Callable[[], Any] | None = None


def configure_http_archive_router(pool_provider: Callable[[], Any]) -> None:
    global _pool_provider
    _pool_provider = pool_provider


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database is not ready")
    return pool


async def _export(
    *,
    scan_id: str | None,
    hunt_run_id: str | None,
    export_format: str,
    redaction: str,
    method: str | None,
    status_code: int | None,
    limit: int,
    offset: int,
):
    if export_format not in EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"unsupported export format {export_format}")
    if redaction not in REDACTION_MODES:
        raise HTTPException(status_code=400, detail=f"unsupported redaction mode {redaction}")
    async with _pool().acquire() as conn:
        total = await count_transactions(conn, scan_id=scan_id, hunt_run_id=hunt_run_id)
        rows = await read_transactions(
            conn, scan_id=scan_id, hunt_run_id=hunt_run_id, method=method,
            status_code=status_code, limit=limit, offset=offset,
        )
    document = export_document(
        rows, export_format=export_format, redaction=redaction,
        owner={"scan_id": scan_id, "hunt_id": hunt_run_id}, total=total,
    )
    name = scan_id or hunt_run_id or "export"
    suffix = "har" if export_format == "har" else "json"
    return JSONResponse(
        document,
        headers={
            "content-disposition": f'attachment; filename="shakerscan-{name}.{suffix}"',
            "x-shakerscan-archive-total": str(total),
            "x-shakerscan-archive-redaction": redaction,
        },
    )


@router.get("/scans/{scan_id}/http-transactions", tags=["Scan"])
async def export_scan_transactions(
    scan_id: str,
    format: str = Query("transactions"),
    redaction: str = Query("redacted"),
    method: str | None = Query(None),
    status_code: int | None = Query(None),
    limit: int = Query(1_000, ge=1, le=MAX_EXPORT_ROWS),
    offset: int = Query(0, ge=0),
):
    """Every HTTP call this scan made, as ShakerScan JSON or HAR 1.2."""
    return await _export(
        scan_id=scan_id, hunt_run_id=None, export_format=format, redaction=redaction,
        method=method, status_code=status_code, limit=limit, offset=offset,
    )


@router.get("/hunts/{hunt_id}/http-transactions", tags=["Hunt"])
async def export_hunt_transactions(
    hunt_id: str,
    format: str = Query("transactions"),
    redaction: str = Query("redacted"),
    method: str | None = Query(None),
    status_code: int | None = Query(None),
    limit: int = Query(1_000, ge=1, le=MAX_EXPORT_ROWS),
    offset: int = Query(0, ge=0),
):
    """Every HTTP call this hunt made, as ShakerScan JSON or HAR 1.2."""
    return await _export(
        scan_id=None, hunt_run_id=hunt_id, export_format=format, redaction=redaction,
        method=method, status_code=status_code, limit=limit, offset=offset,
    )


__all__ = [
    "configure_http_archive_router",
    "export_hunt_transactions",
    "export_scan_transactions",
    "router",
]
