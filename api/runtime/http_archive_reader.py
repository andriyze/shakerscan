"""Read and export the HTTP transaction archive.

Export answers "what did this scan or hunt actually send", so two things it states
explicitly are the redaction mode and the fidelity. An export that quietly masks a token
looks like evidence the token was never sent, and a run that predates the archive has no
transactions at all -- reporting that as an empty list would read as "it sent nothing".
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

try:
    from redaction import redact_sensitive
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_sensitive

from .http_archive import ARCHIVE_SCHEMA, har_document, har_entry


EXPORT_FORMATS = frozenset({"transactions", "har"})
REDACTION_MODES = frozenset({"redacted", "raw"})
MAX_EXPORT_ROWS = 10_000

_SELECT = """
SELECT t.id, t.plane, t.sequence, t.scan_id, t.hunt_run_id, t.hunt_action_id,
       t.capability_name, t.adapter, t.principal_slot, t.method, t.url, t.http_version,
       t.status_code, t.request_body_sha256, t.request_body_bytes,
       t.response_body_sha256, t.response_body_bytes, t.remote_ip, t.direct_origin,
       t.started_at, t.elapsed_ms, t.error, t.truncated, t.metadata_json,
       rh.content AS request_headers, rb.content AS request_body,
       sh.content AS response_headers, sb.content AS response_body
FROM http_transactions t
LEFT JOIN evidence_objects rh ON rh.id = t.request_headers_object_id
LEFT JOIN evidence_objects rb ON rb.id = t.request_body_object_id
LEFT JOIN evidence_objects sh ON sh.id = t.response_headers_object_id
LEFT JOIN evidence_objects sb ON sb.id = t.response_body_object_id
"""


def _json_safe(value: Any) -> Any:
    """Timestamps and UUIDs arrive as driver objects; an export is JSON."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _decoded(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _body_text(value: Any) -> str | None:
    decoded = _decoded(value)
    if decoded is None:
        return None
    if isinstance(decoded, str):
        return decoded
    if isinstance(decoded, (bytes, bytearray)):
        return bytes(decoded).decode("utf-8", errors="replace")
    return json.dumps(decoded)


async def read_transactions(
    conn,
    *,
    scan_id: str | None = None,
    hunt_run_id: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    limit: int = 1_000,
    offset: int = 0,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if scan_id:
        params.append(scan_id)
        clauses.append(f"t.scan_id=${len(params)}")
    if hunt_run_id:
        params.append(hunt_run_id)
        clauses.append(f"t.hunt_run_id=${len(params)}")
    if method:
        params.append(str(method).upper())
        clauses.append(f"t.method=${len(params)}")
    if status_code is not None:
        params.append(int(status_code))
        clauses.append(f"t.status_code=${len(params)}")
    if not clauses:
        raise ValueError("an export must name a scan or a hunt")
    where = " WHERE " + " AND ".join(clauses)
    params.extend([min(int(limit), MAX_EXPORT_ROWS), max(0, int(offset))])
    rows = await conn.fetch(
        f"{_SELECT}{where} ORDER BY t.sequence, t.started_at, t.id"
        f" LIMIT ${len(params) - 1} OFFSET ${len(params)}",
        *params,
    )
    return [dict(row) for row in rows]


async def count_transactions(conn, *, scan_id: str | None, hunt_run_id: str | None) -> int:
    if scan_id:
        return int(await conn.fetchval(
            "SELECT COUNT(*) FROM http_transactions WHERE scan_id=$1", scan_id,
        ) or 0)
    return int(await conn.fetchval(
        "SELECT COUNT(*) FROM http_transactions WHERE hunt_run_id=$1", hunt_run_id,
    ) or 0)


async def read_archive_stats(
    conn, *, scan_id: str | None, hunt_run_id: str | None,
) -> dict[str, int]:
    """What the archive attempted for this run, against what it holds."""
    owner_kind = "scan" if scan_id else "hunt"
    owner_id = scan_id or hunt_run_id
    row = await conn.fetchrow(
        """SELECT attempted, stored, failed, dropped FROM http_archive_stats
           WHERE owner_kind=$1 AND owner_id=$2""",
        owner_kind, owner_id,
    )
    if row is None:
        return {}
    return {key: int(row[key] or 0) for key in ("attempted", "stored", "failed", "dropped")}


def archive_fidelity(stats: Mapping[str, int], *, total: int) -> tuple[str, str]:
    """Say honestly how much of the run this archive represents.

    Labelling any non-empty archive "complete" made one surviving transaction stand for a
    run whose capture mostly failed. Complete requires the counters to agree that nothing
    was dropped and nothing failed.
    """
    if not stats and not total:
        return "unavailable", "no calls were recorded for this run"
    if not stats:
        return (
            "unknown",
            "this run predates archive accounting, so completeness cannot be established",
        )
    attempted = int(stats.get("attempted") or 0)
    stored = int(stats.get("stored") or 0)
    failed = int(stats.get("failed") or 0)
    dropped = int(stats.get("dropped") or 0)
    if attempted == 0 and total == 0:
        return "unavailable", "no calls were recorded for this run"
    if failed or dropped or stored < attempted:
        return "partial", (
            f"{stored} of {attempted} recorded calls were stored"
            + (f"; {dropped} were dropped at the capture ceiling" if dropped else "")
        )
    return "complete", f"all {stored} recorded calls were stored"


def project(row: Mapping[str, Any], *, redaction: str) -> dict[str, Any]:
    """One archived call, redacted unless the caller explicitly asked for raw."""
    item = dict(row)
    for key in ("request_headers", "request_body", "response_headers", "response_body"):
        item[key] = _decoded(item.get(key))
    if redaction != "raw":
        item = redact_sensitive(item, redact_strings=True, scrub_text=True)
    return {
        "schema_version": ARCHIVE_SCHEMA,
        "id": str(item.get("id")),
        "sequence": item.get("sequence"),
        "plane": item.get("plane"),
        "capability_name": item.get("capability_name"),
        "adapter": item.get("adapter"),
        "principal_slot": item.get("principal_slot"),
        "hunt_action_id": str(item["hunt_action_id"]) if item.get("hunt_action_id") else None,
        "method": item.get("method"),
        "url": item.get("url"),
        "http_version": item.get("http_version"),
        "status_code": item.get("status_code"),
        "request": {
            "headers": item.get("request_headers") or {},
            "body": _body_text(item.get("request_body")),
            "sha256": item.get("request_body_sha256"),
            "bytes": item.get("request_body_bytes"),
        },
        "response": {
            "headers": item.get("response_headers") or {},
            "body": _body_text(item.get("response_body")),
            "sha256": item.get("response_body_sha256"),
            "bytes": item.get("response_body_bytes"),
        },
        "remote_ip": item.get("remote_ip"),
        # Whether this call went to an operator-confirmed origin rather than the target's
        # resolved address. The two are not comparable evidence.
        "direct_origin": bool(item.get("direct_origin")),
        "started_at": _json_safe(item.get("started_at")),
        "elapsed_ms": item.get("elapsed_ms"),
        "error": item.get("error"),
        "truncated": bool(item.get("truncated")),
    }


def export_document(
    rows: Sequence[Mapping[str, Any]],
    *,
    export_format: str,
    redaction: str,
    owner: Mapping[str, Any],
    total: int,
    stats: Mapping[str, int] | None = None,
    creator_version: str = "2.0.0",
) -> dict[str, Any]:
    """Build the export envelope, stating what it is and what it is not."""
    projected = [project(row, redaction=redaction) for row in rows]
    fidelity, fidelity_detail = archive_fidelity(stats or {}, total=total)
    if export_format == "har":
        entries = [
            har_entry(
                {**dict(row), **{
                    "request_headers": item["request"]["headers"],
                    "response_headers": item["response"]["headers"],
                }},
                request_body=item["request"]["body"],
                response_body=item["response"]["body"],
            )
            for row, item in zip(rows, projected)
        ]
        document = har_document(entries, creator_version=creator_version)
        document["log"]["comment"] = json.dumps({
            "redaction": redaction,
            "exported": len(entries),
            "total": total,
            "fidelity": fidelity,
            "fidelity_detail": fidelity_detail,
        })
        return document
    return {
        "schema_version": "http-archive-export/v1",
        "owner": dict(owner),
        # Stated, never implied. A redacted export that looks complete is worse than one
        # that says what was removed.
        "redaction": redaction,
        # Backed by counters rather than inferred from the row count, because capture and
        # persistence failures are swallowed and one surviving row is not a whole run.
        "fidelity": fidelity,
        "fidelity_detail": fidelity_detail,
        "capture_stats": dict(stats or {}),
        "exported": len(projected),
        "total": total,
        "truncated_export": len(projected) < total,
        "transactions": projected,
    }


async def purge_transactions(
    conn, *, scan_id: str | None, hunt_run_id: str | None,
) -> dict[str, int]:
    """Delete a run's archived calls and the blobs only they referenced.

    The evidence retention sweep is target-scoped and reaches objects through a scan or
    finding, which a Hunt archive blob has neither of. Without a direct path the one store
    that certainly holds credentials would be the one an operator could never clear.
    Content-addressed blobs are shared, so an object is removed only once nothing else
    points at it.
    """
    owner_clause = "scan_id=$1" if scan_id else "hunt_run_id=$1"
    owner_id = scan_id or hunt_run_id
    async with conn.transaction():
        objects = await conn.fetch(
            f"""SELECT DISTINCT unnest(ARRAY[
                    request_headers_object_id, request_body_object_id,
                    response_headers_object_id, response_body_object_id
                ]) AS object_id
                FROM http_transactions WHERE {owner_clause}""",
            owner_id,
        )
        removed = await conn.fetchval(
            f"WITH gone AS (DELETE FROM http_transactions WHERE {owner_clause} RETURNING 1)"
            " SELECT COUNT(*) FROM gone",
            owner_id,
        )
        object_ids = [row["object_id"] for row in objects if row["object_id"]]
        blobs = 0
        if object_ids:
            blobs = await conn.fetchval(
                """WITH gone AS (
                       DELETE FROM evidence_objects eo
                       WHERE eo.id = ANY($1::uuid[])
                         AND eo.finding_id IS NULL
                         AND NOT EXISTS (
                             SELECT 1 FROM http_transactions t
                             WHERE eo.id IN (
                                 t.request_headers_object_id, t.request_body_object_id,
                                 t.response_headers_object_id, t.response_body_object_id
                             )
                         )
                       RETURNING 1
                   ) SELECT COUNT(*) FROM gone""",
                object_ids,
            )
        await conn.execute(
            "DELETE FROM http_archive_stats WHERE owner_kind=$1 AND owner_id=$2",
            "scan" if scan_id else "hunt", owner_id,
        )
    return {"transactions_deleted": int(removed or 0), "blobs_deleted": int(blobs or 0)}


__all__ = [
    "EXPORT_FORMATS",
    "MAX_EXPORT_ROWS",
    "REDACTION_MODES",
    "archive_fidelity",
    "count_transactions",
    "read_archive_stats",
    "export_document",
    "project",
    "purge_transactions",
    "read_transactions",
]
