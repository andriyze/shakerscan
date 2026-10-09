"""Export endpoints for the HTTP transaction archive."""

from __future__ import annotations

import ipaddress
import os
import secrets
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

try:
    from operator_auth import _require_model_intake_operator as _require_operator
except ModuleNotFoundError:  # package import layout
    from ..operator_auth import _require_model_intake_operator as _require_operator

try:
    from runtime.http_archive_reader import (
        EXPORT_FORMATS,
        EXPORT_RETRY_AFTER_SECONDS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        ExportBusy,
        ExportUnavailable,
        build_export,
        count_transactions,
        export_admission,
        export_read_budget,
        is_light_export,
        purge_transactions,
        read_archive_stats,
        read_transaction_payloads,
        read_transactions,
    )
except ModuleNotFoundError:  # package import layout
    from .http_archive_reader import (
        EXPORT_FORMATS,
        EXPORT_RETRY_AFTER_SECONDS,
        MAX_EXPORT_ROWS,
        REDACTION_MODES,
        ExportBusy,
        ExportUnavailable,
        build_export,
        count_transactions,
        export_admission,
        export_read_budget,
        is_light_export,
        purge_transactions,
        read_archive_stats,
        read_transaction_payloads,
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


def _require_raw_export_enabled() -> None:
    if not raw_export_enabled():
        raise HTTPException(
            status_code=403,
            detail=(
                "raw export is disabled; set SHAKERSCAN_HTTP_ARCHIVE_ALLOW_RAW to permit "
                "verbatim request and response bodies"
            ),
        )


def _published_on_loopback_only() -> bool:
    """Whether the API port is published on loopback only (the default install)."""
    bind = str(os.environ.get("SHAKERSCAN_BIND_HOST") or "127.0.0.1").strip().strip("[]")
    if bind.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def raw_har_enabled() -> bool:
    """Whether verbatim HAR (credentials included) may be exported.

    An open-source install has one operator, and replaying a proof in Burp needs the real
    request, so verbatim HAR is on by default while the API is published on loopback only.
    Once the API is reachable from a LAN or tailnet (which adds no authentication), every
    peer could pull captured credentials with one GET, so it then needs an explicit
    SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1. Setting it to 0 always keeps the masked HAR only.
    """
    value = str(os.environ.get("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR") or "").strip().lower()
    if value in {"0", "false", "no", "off", "disabled"}:
        return False
    if value in {"1", "true", "yes", "on", "enabled"}:
        return True
    return _published_on_loopback_only()


def raw_har_availability() -> dict[str, Any]:
    """Whether verbatim HAR may be exported here, and why not, for the UI to say before asking.

    The archive envelope carries this so a client hides or disables the raw option with the
    deployment's reason instead of offering a download the server will refuse.
    """
    if raw_har_enabled():
        return {"available": True, "reason": None}
    value = str(os.environ.get("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR") or "").strip().lower()
    if value in {"0", "false", "no", "off", "disabled"}:
        reason = ("Verbatim HAR is disabled on this deployment; export the masked HAR instead.")
    else:
        reason = ("Verbatim HAR is disabled on this deployment because its API is published beyond "
                  "loopback; export the masked HAR instead. An API published beyond loopback needs "
                  "SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1")
    return {"available": False, "reason": reason}


def _authorize_raw(request: Request) -> None:
    """Gate verbatim export on the deployment switch and the operator credential.

    ShakerScan has no users to authorize against -- it is a single-operator tool and says
    so -- so this is not ownership. It is the product's existing privileged-operator
    control: a credential plus loopback, HTTPS, or a trusted Tailscale transport.
    """
    _require_raw_export_enabled()
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


def export_caller(request: Any) -> str:
    """Who is asking, for the one-export-slot-per-caller rule: the socket peer, or behind the
    trusted gateway (FLEET_GATEWAY_PROXY_SECRET) the right-most X-Forwarded-For address, as the
    fleet enrollment rate limit reads it. Earlier forwarded entries are caller-supplied."""
    peer = str(getattr(getattr(request, "client", None), "host", None) or "unknown")
    headers = getattr(request, "headers", None) or {}
    configured = os.environ.get("FLEET_GATEWAY_PROXY_SECRET", "").strip()
    presented = str(headers.get("x-shakerscan-gateway-secret", "") or "").strip()
    if configured and presented and secrets.compare_digest(configured.encode(), presented.encode()):
        forwarded = str(headers.get("x-forwarded-for", "") or "").rsplit(",", 1)[-1].strip()
        try:
            peer = str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return peer


def _raw_har_header() -> dict[str, str]:
    return {"x-shakerscan-raw-har": "available" if raw_har_enabled() else "disabled"}


async def _export(**arguments: Any):
    """Every archive response, a refusal included, says whether verbatim HAR is exported here.

    A refused export (a 403 for verbatim HAR, a 400 for an unknown format) is exactly the
    response a client reads to learn the deployment's answer, so it carries the header too.
    """
    try:
        return await _export_document(**arguments)
    except HTTPException as exc:
        exc.headers = {**(exc.headers or {}), **_raw_har_header()}
        raise


async def _export_document(
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
    # Every export, HAR included, honours the requested masking. Verbatim HAR is the replay
    # workflow (Burp needs the real request): on by default only while the API is published on
    # loopback (raw_har_enabled); raw JSON keeps its stricter operator gate as the privileged
    # diagnostic surface.
    effective_redaction = redaction
    if effective_redaction == "raw":
        if export_format != "har":
            _authorize_raw(request)
        elif not raw_har_enabled():
            raise HTTPException(
                status_code=403,
                detail=("verbatim HAR is disabled on this deployment; export the masked HAR instead. "
                        "An API published beyond loopback needs SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR=1"),
            )
    raw_har = raw_har_availability()
    try:
        # The slot is taken before any row is read: a refused request holds no rows.
        # A browse page has its own slots and smaller budgets: a user's browsing never waits
        # behind a download, theirs or anyone's.
        light = is_light_export(export_format, limit, redaction=effective_redaction)
        async with export_admission(export_caller(request), light=light):
            content, total = await _build_export_bytes(
                scan_id=scan_id, hunt_run_id=hunt_run_id, export_format=export_format,
                redaction=effective_redaction, method=method, status_code=status_code,
                search=search, limit=limit, offset=offset, raw_har=raw_har, light=light,
            )
    except ExportBusy as exc:
        raise HTTPException(
            status_code=503, detail="archive exports are busy; retry shortly",
            headers={"Retry-After": str(EXPORT_RETRY_AFTER_SECONDS)},
        ) from exc
    except ExportUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="the archive masking workers are unavailable; retry shortly",
            headers={"Retry-After": str(EXPORT_RETRY_AFTER_SECONDS)},
        ) from exc
    name = scan_id or hunt_run_id or "export"
    suffix = ("RAW.har" if effective_redaction == "raw" else "masked.har") if export_format == "har" else "json"
    return Response(
        content,
        media_type="application/json",
        headers={
            "content-disposition": f'attachment; filename="shakerscan-{name}.{suffix}"',
            "x-shakerscan-archive-total": str(total),
            "x-shakerscan-archive-redaction": effective_redaction,
            "x-shakerscan-archive-sensitive": (
                "true" if effective_redaction == "raw" else "possibly"
            ),
            **_raw_har_header(),
        },
    )


async def _build_export_bytes(
    *, scan_id: str | None, hunt_run_id: str | None, export_format: str, redaction: str,
    method: str | None, status_code: int | None, search: str | None, limit: int, offset: int,
    raw_har: Any, light: bool = False,
) -> tuple[bytes, int]:
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
        # Metadata now; headers and bodies a batch at a time while they are redacted.
        rows = await read_transactions(
            conn, scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=hunt_run_id, method=method,
            status_code=status_code, search=search, limit=limit, offset=offset,
            external_payload_budget=export_read_budget(redaction, light=light), payloads=False,
        )

    async def read_payloads(ids, budget: int):
        async with _pool().acquire() as conn:
            return await read_transaction_payloads(
                conn, ids, external_payload_budget=budget,
                scan_id=scan_id, scan_ids=scan_ids, hunt_run_id=None if scan_id else hunt_run_id,
            )

    owner = {"scan_id": scan_id, "hunt_id": hunt_run_id}
    if scan_ids and len(scan_ids) > 1:
        owner["included_scan_ids"] = list(scan_ids)
    encoded = await build_export(
        rows, export_format=export_format, redaction=redaction,
        owner=owner, total=total,
        archive_total=archive_total, stats=stats, read_payloads=read_payloads, light=light,
    )
    del rows
    if export_format == "transactions":
        # A HAR document has a fixed shape; the ShakerScan envelope says what this deployment
        # will export so the raw option is never offered only to be refused.
        encoded.document["raw_har"] = raw_har
    return encoded.render(), total


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
        # Purge exactly what export shows: the visible scan and the child scans it ran.
        scan_ids = await _scan_archive_ids(conn, scan_id) if scan_id else None
        return await purge_transactions(
            conn, scan_id=scan_id, hunt_run_id=hunt_run_id, scan_ids=scan_ids,
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
    "raw_har_availability",
    "export_hunt_transactions",
    "export_scan_transactions",
    "purge_hunt_transactions",
    "purge_scan_transactions",
    "router",
]
