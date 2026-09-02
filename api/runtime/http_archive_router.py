"""Export endpoints for the HTTP transaction archive."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

try:
    from operator_auth import _require_model_intake_operator as _require_operator
except ModuleNotFoundError:  # package import layout
    from ..operator_auth import _require_model_intake_operator as _require_operator

try:
    from runtime.http_archive_reader import (
        EXPORT_FORMATS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        count_transactions,
        export_document,
        purge_transactions,
        read_archive_stats,
        read_transactions,
    )
except ModuleNotFoundError:  # package import layout
    from .http_archive_reader import (
        EXPORT_FORMATS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        count_transactions,
        export_document,
        purge_transactions,
        read_archive_stats,
        read_transactions,
    )


router = APIRouter()
_pool_provider: Callable[[], Any] | None = None


def raw_export_enabled() -> bool:
    """Whether this deployment permits verbatim export at all.

    Off by default. Every other public surface in ShakerScan is metadata-only or redacted,
    so a raw export is the one place a single request yields bearer tokens and request
    bodies exactly as sent. That is occasionally the point -- reproducing a proof in Burp
    needs the real request -- but it should be a deliberate deployment choice rather than a
    query parameter anyone who can reach the API may set.
    """
    value = str(os.environ.get("SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _authorize_raw(request: Request) -> None:
    """Gate verbatim export on the deployment switch and the operator credential.

    ShakerScan has no users to authorize against -- it is a single-operator tool and says
    so -- so this is not ownership. It is the product's existing privileged-operator
    control: a credential plus loopback, HTTPS, or a trusted Tailscale transport.
    """
    if not raw_export_enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "raw export is disabled; set SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW to permit "
                "verbatim request and response bodies"
            ),
        )
    _require_operator(request)


def configure_http_archive_router(pool_provider: Callable[[], Any]) -> None:
    global _pool_provider
    _pool_provider = pool_provider


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database is not ready")
    return pool


async def _scan_archive_ids(conn, scan_id: str) -> tuple[str, ...]:
    """Resolve a visible scan to every descendant that executed part of its work.

    Parallel and discovery scans retain the parent as the user's run while HTTP calls are
    captured against worker-owned child rows. Exporting only the parent silently produced
    an empty HAR. The bounded path also protects a damaged parent graph from looping.
    """
    rows = await conn.fetch(
        """WITH RECURSIVE scan_tree AS (
               SELECT id, created_at, 0 AS depth, ARRAY[id] AS path
               FROM scans WHERE id=$1
               UNION ALL
               SELECT child.id, child.created_at, parent.depth + 1,
                      parent.path || child.id
               FROM scans child
               JOIN scan_tree parent ON child.parent_scan_id=parent.id
               WHERE parent.depth < 16 AND NOT child.id=ANY(parent.path)
           )
           SELECT id FROM scan_tree ORDER BY depth, created_at, id""",
        scan_id,
    )
    values = tuple(str(row["id"]) for row in rows)
    return values or (scan_id,)


async def _export(
    *,
    request: Request,
    scan_id: str | None,
    hunt_run_id: str | None,
    export_format: str,
    redaction: str,
    method: str | None,
    status_code: int | None,
    search: str | None,
    limit: int,
    offset: int,
):
    if export_format not in EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"unsupported export format {export_format}")
    if redaction not in REDACTION_MODES:
        raise HTTPException(status_code=400, detail=f"unsupported redaction mode {redaction}")
    # HAR is always verbatim replay evidence. The raw JSON mode remains the privileged
    # diagnostic surface; HAR is the explicitly labelled workflow selected by the operator.
    effective_redaction = "raw" if export_format == "har" else redaction
    if effective_redaction == "raw" and export_format != "har":
        _authorize_raw(request)
    async with _pool().acquire() as conn:
        scan_ids = await _scan_archive_ids(conn, scan_id) if scan_id else None
        archive_total = await count_transactions(
            conn, scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=hunt_run_id,
        )
        total = await count_transactions(
            conn, scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=hunt_run_id, method=method,
            status_code=status_code, search=search,
        )
        stats = await read_archive_stats(
            conn, scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=hunt_run_id,
        )
        rows = await read_transactions(
            conn, scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=hunt_run_id, method=method,
            status_code=status_code, search=search, limit=limit, offset=offset,
        )
    owner = {"scan_id": scan_id, "hunt_id": hunt_run_id}
    if scan_ids and len(scan_ids) > 1:
        owner["included_scan_ids"] = list(scan_ids)
    document = export_document(
        rows, export_format=export_format, redaction=effective_redaction,
        owner=owner, total=total,
        archive_total=archive_total, stats=stats,
    )
    name = scan_id or hunt_run_id or "export"
    suffix = "RAW.har" if export_format == "har" else "json"
    return JSONResponse(
        document,
        headers={
            "content-disposition": f'attachment; filename="shakerscan-{name}.{suffix}"',
            "x-shakerscan-archive-total": str(total),
            "x-shakerscan-archive-redaction": effective_redaction,
            "x-shakerscan-archive-sensitive": (
                "true" if effective_redaction == "raw" else "possibly"
            ),
        },
    )


@router.get("/scans/{scan_id}/http-transactions", tags=["Scan"])
async def export_scan_transactions(
    request: Request,
    scan_id: str,
    format: str = Query("transactions"),
    redaction: str = Query("redacted"),
    method: str | None = Query(None),
    status_code: int | None = Query(None),
    search: str | None = Query(None, max_length=200),
    limit: int = Query(1_000, ge=1, le=MAX_EXPORT_ROWS),
    offset: int = Query(0, ge=0),
):
    """This scan's archived HTTP calls, as ShakerScan JSON or HAR 1.2.

    The envelope's `fidelity` says how much of the run the archive represents. Coverage is
    per capability: a call is archived only where its execution path records one, so an
    export is not a promise that the scan made no other request.
    """
    return await _export(
        request=request, scan_id=scan_id, hunt_run_id=None, export_format=format, redaction=redaction,
        method=method, status_code=status_code, search=search, limit=limit, offset=offset,
    )


@router.get("/hunts/{hunt_id}/http-transactions", tags=["Hunt"])
async def export_hunt_transactions(
    request: Request,
    hunt_id: str,
    format: str = Query("transactions"),
    redaction: str = Query("redacted"),
    method: str | None = Query(None),
    status_code: int | None = Query(None),
    search: str | None = Query(None, max_length=200),
    limit: int = Query(1_000, ge=1, le=MAX_EXPORT_ROWS),
    offset: int = Query(0, ge=0),
):
    """This hunt's archived HTTP calls, as ShakerScan JSON or HAR 1.2.

    The envelope's `fidelity` says how much of the run the archive represents. Coverage is
    per capability: a call is archived only where its execution path records one, so an
    export is not a promise that the hunt made no other request.
    """
    return await _export(
        request=request, scan_id=None, hunt_run_id=hunt_id, export_format=format, redaction=redaction,
        method=method, status_code=status_code, search=search, limit=limit, offset=offset,
    )


async def _purge(request: Request, *, scan_id: str | None, hunt_run_id: str | None):
    """Delete a run's archived calls.

    Requires the operator credential, but deliberately not the raw-export switch. Making an
    operator first enable *exporting* credentials before they may *delete* them would gate
    the safe action behind the dangerous one.
    """
    _require_operator(request)
    async with _pool().acquire() as conn:
        return await purge_transactions(
            conn, scan_id=scan_id, hunt_run_id=hunt_run_id,
            results_dir=Path(os.environ.get("RESULTS_DIR") or "/results"),
        )


@router.delete("/scans/{scan_id}/http-transactions", tags=["Scan"])
async def purge_scan_transactions(request: Request, scan_id: str):
    """Delete this scan's archived calls and the blobs only they referenced."""
    return await _purge(request, scan_id=scan_id, hunt_run_id=None)


@router.delete("/hunts/{hunt_id}/http-transactions", tags=["Hunt"])
async def purge_hunt_transactions(request: Request, hunt_id: str):
    """Delete this hunt's archived calls and the blobs only they referenced."""
    return await _purge(request, scan_id=None, hunt_run_id=hunt_id)


__all__ = [
    "configure_http_archive_router",
    "raw_export_enabled",
    "export_hunt_transactions",
    "export_scan_transactions",
    "purge_hunt_transactions",
    "purge_scan_transactions",
    "router",
]
