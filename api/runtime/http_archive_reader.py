"""Read and export the HTTP transaction archive.

Export answers "what did this scan or hunt actually send", so two things it states
explicitly are the redaction mode and the fidelity. An export that quietly masks a token
looks like evidence the token was never sent, and a run that predates the archive has no
transactions at all -- reporting that as an empty list would read as "it sent nothing".
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from runtime.capability_registry import CAPABILITY_REGISTRY
except ModuleNotFoundError:  # package import layout
    from .capability_registry import CAPABILITY_REGISTRY

try:
    from redaction import redact_sensitive
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_sensitive

from .archive_body_masking import MAX_MASKED_BODY_CHARS
from .archive_export_worker import (
    MASKING_FAILED,
    OVER_MASKING_LIMIT,
    _decoded,
    encode_payload,
    encode_payloads,
    initialize_worker,
    legacy_body,
    stored_body_size,
    utf8,
    worker_context,
)
from .http_archive import ARCHIVE_SCHEMA, har_document, har_entry

try:
    from evidence_storage import delete_remote_evidence_object, hydrate_evidence_content, local_evidence_path
except ModuleNotFoundError:  # package import layout
    from ..evidence_storage import delete_remote_evidence_object, hydrate_evidence_content, local_evidence_path


EXPORT_FORMATS = frozenset({"transactions", "har"})
REDACTION_MODES = frozenset({"redacted", "raw"})
MAX_EXPORT_ROWS = 10_000
# Payloads above the inline ceiling live in a file or object. One read loads at most this many
# of their stored bytes: an inline payload is at most 32 KiB, but an external one can be a whole
# 10 MB body, and a 10,000-row export would otherwise read without bound. A payload past the
# budget is reported as omitted from that export, never shown as empty.
MAX_EXTERNAL_PAYLOAD_BYTES = 64 * 1024 * 1024
_BODY_FIELDS = ("request_body", "response_body")
# Every payload of a call, in the order archive_blob_secrets.PAYLOAD_FIELDS lists them.
PAYLOAD_FIELDS = ("request_headers", "request_body", "response_headers", "response_body")
# A masked export holds at most this many bytes of JSON body text (configurable with
# SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES): bytes as the response carries them, escapes
# included, so an export of multi-byte or escaped text cannot exceed it. Past it, further bodies
# are left out and listed under payload_omitted; they are never shown unmasked or as empty.
DEFAULT_MASKED_EXPORT_BYTES = 32 * 1024 * 1024
MIN_MASKED_EXPORT_BYTES = 1024 * 1024
MAX_MASKED_EXPORT_BYTES = 256 * 1024 * 1024
# Every export, raw included, holds at most this many encoded bytes of headers; past it further
# headers are withheld (payload_omitted_reasons: header_budget).
MAX_EXPORT_HEADER_BYTES = 16 * 1024 * 1024
# At most this many heavy exports (downloads, HARs, Hunt records) are read, masked and rendered at
# once, at most two per caller; a request waits this long for a slot before it is refused (503
# with Retry-After) rather than queueing with its rows loaded.
MAX_CONCURRENT_EXPORT_BUILDS = 3
MAX_EXPORTS_PER_CALLER = 2
EXPORT_ADMISSION_WAIT_SECONDS = 2.0
# A browse page (JSON, at most this many rows) has smaller budgets and its own slots, so a user's
# browsing is never refused because their own or anyone's download is running.
LIGHT_EXPORT_ROWS = 250
LIGHT_EXPORT_BODY_BYTES = 8 * 1024 * 1024
LIGHT_EXPORT_HEADER_BYTES = 4 * 1024 * 1024
MAX_CONCURRENT_BROWSE_PAGES = 8
BROWSE_ADMISSION_WAIT_SECONDS = 10.0
EXPORT_RETRY_AFTER_SECONDS = 10
# Worker processes that decode, mask and encode bodies for every export (archive_export_worker).
MASKING_WORKERS = 2
# Payloads are read from the archive a batch at a time: at most this many stored bytes (one
# payload at least) and this many payloads per batch.
EXPORT_BATCH_BYTES = 8 * 1024 * 1024
EXPORT_BATCH_BODIES = 256
# Bodies go to a worker in chunks: at most this many stored bytes (one body at least) and bodies
# per round trip, and at most this many chunks are out at once.
WORKER_CHUNK_BYTES = 1024 * 1024
WORKER_CHUNK_BODIES = 64
WORKER_CHUNKS_IN_FLIGHT = 2 * MASKING_WORKERS
_OBJECT_COLUMNS = ("storage_uri", "content_sha256", "size_bytes")

_SELECT = """
SELECT t.id, t.plane, t.sequence, t.scan_id, t.hunt_run_id, t.hunt_action_id,
       t.capability_name, t.adapter, t.principal_slot, t.method, t.url, t.http_version,
       t.status_code, t.request_body_sha256, t.request_body_bytes,
       t.response_body_sha256, t.response_body_bytes, t.remote_ip, t.direct_origin,
       t.started_at, t.elapsed_ms, t.error, t.truncated, t.metadata_json,
       rh.content AS request_headers, rb.content AS request_body,
       sh.content AS response_headers, sb.content AS response_body,
       rh.storage_uri AS request_headers_storage_uri, rh.content_sha256 AS request_headers_content_sha256,
       rh.size_bytes AS request_headers_size_bytes,
       rb.storage_uri AS request_body_storage_uri, rb.content_sha256 AS request_body_content_sha256,
       rb.size_bytes AS request_body_size_bytes,
       sh.storage_uri AS response_headers_storage_uri, sh.content_sha256 AS response_headers_content_sha256,
       sh.size_bytes AS response_headers_size_bytes,
       sb.storage_uri AS response_body_storage_uri, sb.content_sha256 AS response_body_content_sha256,
       sb.size_bytes AS response_body_size_bytes
FROM http_transactions t
LEFT JOIN evidence_objects rh ON rh.id = t.request_headers_object_id
LEFT JOIN evidence_objects rb ON rb.id = t.request_body_object_id
LEFT JOIN evidence_objects sh ON sh.id = t.response_headers_object_id
LEFT JOIN evidence_objects sb ON sb.id = t.response_body_object_id
"""
# The same rows without payload content: which payloads are stored, and how large, instead.
_SELECT_WITHOUT_PAYLOADS = (
    _SELECT.replace("rh.content AS request_headers", "NULL AS request_headers")
    .replace("rb.content AS request_body", "NULL AS request_body")
    .replace("sh.content AS response_headers", "NULL AS response_headers")
    .replace("sb.content AS response_body", "NULL AS response_body")
    .replace(
        "\nFROM http_transactions t\n",
        ",\n       (rh.id IS NOT NULL) AS request_headers_stored, (rb.id IS NOT NULL) AS request_body_stored,"
        "\n       (sh.id IS NOT NULL) AS response_headers_stored, (sb.id IS NOT NULL) AS response_body_stored"
        "\nFROM http_transactions t\n",
    )
)
# Payloads by id, only of the export's own owner: the owner clause is appended by
# ``read_transaction_payloads``, which refuses to run without one.
_SELECT_PAYLOADS = """
SELECT t.id, t.request_body_sha256, t.response_body_sha256,
       rh.content AS request_headers, rb.content AS request_body,
       sh.content AS response_headers, sb.content AS response_body,
       rh.storage_uri AS request_headers_storage_uri, rh.content_sha256 AS request_headers_content_sha256,
       rh.size_bytes AS request_headers_size_bytes,
       rb.storage_uri AS request_body_storage_uri, rb.content_sha256 AS request_body_content_sha256,
       rb.size_bytes AS request_body_size_bytes,
       sh.storage_uri AS response_headers_storage_uri, sh.content_sha256 AS response_headers_content_sha256,
       sh.size_bytes AS response_headers_size_bytes,
       sb.storage_uri AS response_body_storage_uri, sb.content_sha256 AS response_body_content_sha256,
       sb.size_bytes AS response_body_size_bytes
FROM http_transactions t
LEFT JOIN evidence_objects rh ON rh.id = t.request_headers_object_id
LEFT JOIN evidence_objects rb ON rb.id = t.request_body_object_id
LEFT JOIN evidence_objects sh ON sh.id = t.response_headers_object_id
LEFT JOIN evidence_objects sb ON sb.id = t.response_body_object_id
WHERE t.id = ANY($1::uuid[])
"""
# A row read without its payloads carries {field: stored size} here.
LAZY_PAYLOADS = "_stored_payloads"


def _scan_ids(scan_id: str | None, scan_ids: Sequence[str] | None) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(
        str(item).strip() for item in (scan_ids or ()) if str(item).strip()
    ))
    if values:
        return values
    return (str(scan_id).strip(),) if scan_id and str(scan_id).strip() else ()


def _append_scan_clause(
    clauses: list[str], params: list[Any], *, column: str,
    scan_id: str | None, scan_ids: Sequence[str] | None,
) -> tuple[str, ...]:
    owners = _scan_ids(scan_id, scan_ids)
    if len(owners) == 1:
        params.append(owners[0])
        clauses.append(f"{column}=${len(params)}")
    elif owners:
        params.append(list(owners))
        clauses.append(f"{column}=ANY(${len(params)}::uuid[])")
    return owners


def _search_pattern(value: str) -> str:
    """Literal ILIKE pattern; `%`, `_`, and backslash are ordinary search text."""
    escaped = (
        str(value).strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return f"%{escaped}%"


def _json_safe(value: Any) -> Any:
    """Timestamps and UUIDs arrive as driver objects; an export is JSON."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


async def read_transactions(
    conn,
    *,
    scan_id: str | None = None,
    scan_ids: Sequence[str] | None = None,
    hunt_run_id: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
    limit: int = 1_000,
    offset: int = 0,
    results_dir: Path | None = None,
    external_payload_budget: int = MAX_EXTERNAL_PAYLOAD_BYTES,
    payloads: bool = True,
) -> list[dict[str, Any]]:
    """The matching transactions. With ``payloads=False`` a row says which headers and bodies the
    archive holds (``LAZY_PAYLOADS``: field -> stored size) instead of carrying them, so an export
    can read them in batches within its budgets (``read_transaction_payloads``)."""
    clauses: list[str] = []
    params: list[Any] = []
    owners = _append_scan_clause(
        clauses, params, column="t.scan_id", scan_id=scan_id, scan_ids=scan_ids,
    )
    if not owners and hunt_run_id:
        params.append(hunt_run_id)
        clauses.append(f"t.hunt_run_id=${len(params)}")
    elif not owners:
        raise ValueError("an export must name a scan or a hunt")
    if method:
        params.append(str(method).upper())
        clauses.append(f"t.method=${len(params)}")
    if status_code is not None:
        params.append(int(status_code))
        clauses.append(f"t.status_code=${len(params)}")
    if search:
        params.append(_search_pattern(search))
        clauses.append(
            f"(COALESCE(t.capability_name,'') ILIKE ${len(params)} ESCAPE '\\'"
            f" OR COALESCE(t.adapter,'') ILIKE ${len(params)} ESCAPE '\\'"
            f" OR t.method ILIKE ${len(params)} ESCAPE '\\')"
        )
    where = " WHERE " + " AND ".join(clauses)
    params.extend([min(int(limit), MAX_EXPORT_ROWS), max(0, int(offset))])
    rows = await conn.fetch(
        f"{_SELECT if payloads else _SELECT_WITHOUT_PAYLOADS}{where} ORDER BY t.started_at, t.sequence, t.id"
        f" LIMIT ${len(params) - 1} OFFSET ${len(params)}",
        *params,
    )
    try:
        from runtime.archive_blob_secrets import PAYLOAD_FIELDS
    except ModuleNotFoundError:  # package import layout
        from .archive_blob_secrets import PAYLOAD_FIELDS
    rows = [dict(row) for row in rows]
    fields = PAYLOAD_FIELDS if payloads else ()
    loaded, omitted, _used = await _load_external_payloads(
        rows, fields,
        results_dir=results_dir or Path(os.environ.get("RESULTS_DIR") or "/results"),
        budget=external_payload_budget,
    )
    revealed = []
    for row in rows:
        metadata = _decoded(row.get("metadata_json")) or {}
        unavailable = set(metadata.get("payloads_unavailable") or ()) if isinstance(metadata, dict) else set()
        if not payloads:
            # Which payloads the archive holds, and their stored size, without their content:
            # ``read_transaction_payloads`` fetches them later, a batch at a time.
            stored: dict[str, int] = {}
            for key in PAYLOAD_FIELDS:
                size = row.pop(f"{key}_size_bytes", None)
                if row.pop(f"{key}_stored", False):
                    stored[key] = int(size or 0)
                row.pop(f"{key}_storage_uri", None)
                row.pop(f"{key}_content_sha256", None)
            row[LAZY_PAYLOADS] = stored
        omitted_fields = _reveal_payloads(row, fields, loaded, omitted, unavailable)
        if unavailable:
            row["payload_unavailable"] = sorted(unavailable)
        if omitted_fields:
            row["payload_omitted"] = sorted(omitted_fields)
        revealed.append(row)
    return revealed


def _reveal_payloads(
    row: dict[str, Any], fields: Sequence[str], loaded: Mapping[str, str | None], omitted: set[str],
    unavailable: set[str], *, legacy: bool = True,
) -> set[str]:
    """Decrypt each payload of ``row`` in place; the fields left out by the read budget."""
    try:
        from runtime.archive_blob_secrets import reveal_payload
    except ModuleNotFoundError:  # package import layout
        from .archive_blob_secrets import reveal_payload
    omitted_fields: set[str] = set()
    for key in fields:
        storage_uri = row.pop(f"{key}_storage_uri", None)
        content_sha256 = row.pop(f"{key}_content_sha256", None)
        row.pop(f"{key}_size_bytes", None)
        value, external = row.get(key), False
        if value is None and _is_external(storage_uri):
            if storage_uri in omitted:
                omitted_fields.add(key)
                continue
            value, external = loaded.get(storage_uri), True
            if value is None:
                unavailable.add(key)  # the file or object is gone or unreadable
                continue
        value, lost = reveal_payload(value)
        if external and not lost and not _names_plaintext(value, content_sha256):
            value, lost = None, True  # not the payload this row recorded
        if legacy and key in _BODY_FIELDS:
            value = legacy_body(value, recorded_sha256=row.get(f"{key}_sha256"))
        row[key] = value
        if lost:
            unavailable.add(key)
    return omitted_fields


async def read_transaction_payloads(
    conn, ids: Sequence[Any], *, external_payload_budget: int, results_dir: Path | None = None,
    scan_id: str | None = None, scan_ids: Sequence[str] | None = None, hunt_run_id: str | None = None,
) -> tuple[dict[str, dict[str, Any]], int]:
    """The headers and bodies of these transactions of one owner (a scan, its retests, or a
    hunt), decrypted but not legacy-decoded (the masking worker does that), with what could not
    be shown: ``({id: {field, "unavailable", "omitted"}}, bytes of external payload read)``.

    An id of another owner is not read: a caller cannot fetch payloads by bare id.
    """
    params: list[Any] = [list(ids)]
    clauses: list[str] = []
    owners = _append_scan_clause(clauses, params, column="t.scan_id", scan_id=scan_id, scan_ids=scan_ids)
    if not owners and hunt_run_id:
        params.append(hunt_run_id)
        clauses.append(f"t.hunt_run_id=${len(params)}")
    elif not owners:
        raise ValueError("payloads are read for one scan or one hunt")
    query = _SELECT_PAYLOADS + "".join(f" AND {clause}" for clause in clauses)
    rows = [dict(row) for row in await conn.fetch(query, *params)]
    loaded, omitted, used = await _load_external_payloads(
        rows, PAYLOAD_FIELDS,
        results_dir=results_dir or Path(os.environ.get("RESULTS_DIR") or "/results"),
        budget=external_payload_budget,
    )
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        unavailable: set[str] = set()
        omitted_fields = _reveal_payloads(row, PAYLOAD_FIELDS, loaded, omitted, unavailable, legacy=False)
        found[str(row["id"])] = {
            **{key: row.get(key) for key in PAYLOAD_FIELDS},
            "unavailable": unavailable, "omitted": omitted_fields,
        }
    return found, used


def _is_external(storage_uri: Any) -> bool:
    """The payload's object exists but is stored outside its row (a file or an S3 object)."""
    return isinstance(storage_uri, str) and bool(storage_uri) and not storage_uri.startswith("inline:")


def _read_external_payloads(
    storage_uris: Sequence[str], *, results_dir: Path, budget: int,
) -> tuple[dict[str, str | None], set[str], int]:
    """The stored text of each externalized payload, None where it cannot be read.

    Reads through the evidence store, so local paths stay contained under the results
    directory and S3 URIs are validated as for every other evidence read. No stored hash is
    passed: for a sealed payload it names the plaintext, not the stored envelope, so it is
    checked after decryption instead.
    """
    loaded: dict[str, str | None] = {}
    omitted: set[str] = set()
    remaining = start = max(0, int(budget))
    for storage_uri in storage_uris:
        if not remaining:
            omitted.add(storage_uri)
            continue
        try:
            result = hydrate_evidence_content(
                {"storage_uri": storage_uri}, results_dir=results_dir, max_stored_bytes=remaining,
            )
            remaining -= min(remaining, max(0, int(result.get("storage_bytes_read") or 0)))
            if result.get("storage_status") == "budget_exceeded":
                omitted.add(storage_uri)
                continue
            content = result.get("content")
        except Exception:  # noqa: BLE001 - one unreadable object must not fail the export
            content = None
        loaded[storage_uri] = content if isinstance(content, str) else None
    return loaded, omitted, start - remaining


async def _load_external_payloads(
    rows: Sequence[Mapping[str, Any]], fields: Sequence[str], *, results_dir: Path, budget: int,
) -> tuple[dict[str, str | None], set[str], int]:
    """Load the external payloads these rows reference, each once, within the byte budget."""
    wanted: dict[str, None] = {}
    for row in rows:
        for key in fields:
            storage_uri = row.get(f"{key}_storage_uri")
            if row.get(key) is None and _is_external(storage_uri):
                wanted.setdefault(storage_uri, None)
    if not wanted:
        return {}, set(), 0
    # File and S3 reads block; keep them off the event loop.
    return await asyncio.to_thread(
        _read_external_payloads, tuple(wanted), results_dir=results_dir, budget=budget,
    )


def _names_plaintext(value: Any, content_sha256: Any) -> bool:
    """Whether a revealed external payload is the one its object row names."""
    if not content_sha256:
        return True
    if not isinstance(value, str):
        return False
    actual = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
    return hmac.compare_digest(actual, str(content_sha256))


async def count_transactions(
    conn,
    *,
    scan_id: str | None,
    scan_ids: Sequence[str] | None = None,
    hunt_run_id: str | None,
    method: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
) -> int:
    """Count one archive, optionally using the same filters as ``read_transactions``."""
    clauses: list[str] = []
    params: list[Any] = []
    owners = _append_scan_clause(
        clauses, params, column="scan_id", scan_id=scan_id, scan_ids=scan_ids,
    )
    if not owners and hunt_run_id:
        params.append(hunt_run_id)
        clauses.append(f"hunt_run_id=${len(params)}")
    elif not owners:
        raise ValueError("an export must name a scan or a hunt")
    if method:
        params.append(str(method).upper())
        clauses.append(f"method=${len(params)}")
    if status_code is not None:
        params.append(int(status_code))
        clauses.append(f"status_code=${len(params)}")
    if search:
        params.append(_search_pattern(search))
        clauses.append(
            f"(COALESCE(capability_name,'') ILIKE ${len(params)} ESCAPE '\\'"
            f" OR COALESCE(adapter,'') ILIKE ${len(params)} ESCAPE '\\'"
            f" OR method ILIKE ${len(params)} ESCAPE '\\')"
        )
    return int(await conn.fetchval(
        "SELECT COUNT(*) FROM http_transactions WHERE " + " AND ".join(clauses),
        *params,
    ) or 0)


async def read_archive_stats(
    conn, *, scan_id: str | None, hunt_run_id: str | None,
    scan_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """What the archive attempted for this run, against what it holds."""
    owners = _scan_ids(scan_id, scan_ids)
    owner_kind = "scan" if owners else "hunt"
    owner_id = owners[0] if owners else hunt_run_id
    if len(owners) > 1:
        row = await conn.fetchrow(
            """SELECT COALESCE(SUM(attempted),0) AS attempted,
                      COALESCE(SUM(stored),0) AS stored,
                      COALESCE(SUM(failed),0) AS failed,
                      COALESCE(SUM(dropped),0) AS dropped
               FROM http_archive_stats
               WHERE owner_kind='scan' AND owner_id=ANY($1::uuid[])""",
            list(owners),
        )
    else:
        row = await conn.fetchrow(
            """SELECT attempted, stored, failed, dropped FROM http_archive_stats
               WHERE owner_kind=$1 AND owner_id=$2""",
            owner_kind, owner_id,
        )
    if row is None:
        return {}
    stats = {
        key: int(row[key] or 0)
        for key in ("attempted", "stored", "failed", "dropped")
    }
    if len(owners) > 1:
        capture_limited = await conn.fetchval(
            """SELECT COUNT(*) FROM http_transactions
               WHERE scan_id=ANY($1::uuid[])
                 AND COALESCE(metadata_json->>'fidelity','')
                     NOT IN ('wire_request','attempted_no_response')""",
            list(owners),
        )
    elif scan_id:
        capture_limited = await conn.fetchval(
            """SELECT COUNT(*) FROM http_transactions
               WHERE scan_id=$1
                 AND COALESCE(metadata_json->>'fidelity','')
                     NOT IN ('wire_request','attempted_no_response')""",
            scan_id,
        )
    else:
        capture_limited = await conn.fetchval(
            """SELECT COUNT(*) FROM http_transactions
               WHERE hunt_run_id=$1
                 AND COALESCE(metadata_json->>'fidelity','')
                     NOT IN ('wire_request','attempted_no_response')""",
            hunt_run_id,
        )
    stats["capture_limited"] = int(capture_limited or 0)
    if scan_id:
        scan_filter = (
            "action.scan_id=ANY($1::uuid[])" if len(owners) > 1
            else "action.scan_id=$1"
        )
        scan_param: Any = list(owners) if len(owners) > 1 else scan_id
        missing_rows = await conn.fetch(
            f"""SELECT action.capability_name, action.status,
                      COALESCE(NULLIF(
                          action.result_json->'budget_consumed'->>'http_requests',''
                      )::int,0) AS http_consumed
               FROM scan_capability_actions action
               WHERE {scan_filter}
                 AND COALESCE(NULLIF(action.requested_budget->>'http_requests','')::int,0) > 0
                 AND NOT EXISTS (
                     SELECT 1 FROM http_transactions tx
                     WHERE tx.scan_id=action.scan_id
                       AND tx.capability_name=action.capability_name
                 )
               ORDER BY action.capability_name""",
            scan_param,
        )
        missing = sorted({
            str(item["capability_name"]) for item in missing_rows
            if scan_action_sent_traffic(item)
        })
        external, engine = split_unarchived_capabilities(missing)
        stats["unarchived_external_tool_capabilities"] = external
        stats["unarchived_engine_capabilities"] = engine
    else:
        action_rows = await conn.fetch(
            """SELECT DISTINCT action.capability_name
               FROM hunt_actions action
               WHERE action.hunt_run_id=$1
                 AND (action.status IN ('completed','partial')
                      OR COALESCE(NULLIF(action.result_summary->'budget_consumed'->>'http_requests','')::int,0)>0)
                 AND NOT EXISTS (
                     SELECT 1 FROM http_transactions tx
                     WHERE tx.hunt_run_id=action.hunt_run_id
                       AND tx.hunt_action_id=action.id
                 )
               ORDER BY action.capability_name""",
            hunt_run_id,
        )
        missing = []
        for item in action_rows:
            name = str(item["capability_name"])
            try:
                spec = CAPABILITY_REGISTRY.require(name)
            except KeyError:
                continue
            if int(spec.budget_cost.get("http_requests") or 0) > 0:
                missing.append(name)
    stats["unarchived_http_capabilities"] = missing
    stats["unarchived_http_capability_count"] = len(missing)
    return stats


def _runs_external_scanner(name: str) -> bool:
    try:
        spec = CAPABILITY_REGISTRY.require(name)
    except KeyError:
        return False
    return bool(
        spec.process_tool_name or spec.binary
        or (spec.placement_requirements or {}).get("binary")
    )


def scan_action_sent_traffic(row: Mapping[str, Any]) -> bool:
    """Whether a Scan action's traffic belongs in the archive's account of the run.

    A verifier the wall stopped settles ``timed_out`` after sending real traffic: soak scans
    sent 340 and 905 SQLi verification requests under ``sqli.verify_batch`` actions that ended
    ``timed_out``, and the capture note, which read only success and partial actions, neither
    archived nor named them. Any action that consumed requests sent traffic, whatever it ended.
    """
    status = str(row.get("status") or "")
    try:
        consumed = int(row.get("http_consumed") or 0)
    except (TypeError, ValueError):
        consumed = 0
    return status in {"success", "partial", "timed_out"} or consumed > 0


def split_unarchived_capabilities(names: Sequence[str]) -> tuple[list[str], list[str]]:
    """Separate scanner-process gaps from engine gaps.

    External scanner tools reach the target through a CONNECT-only pinned tunnel, so their
    HTTPS traffic is ciphertext to the engine and cannot be archived. An engine capability
    with no rows is a different gap: its calls were in reach and were not recorded. Names
    the registry no longer knows are reported as engine gaps rather than hidden.
    """
    external = [name for name in names if _runs_external_scanner(name)]
    engine = [name for name in names if not _runs_external_scanner(name)]
    return external, engine


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
    capture_limited = int(stats.get("capture_limited") or 0)
    unarchived = [
        str(item) for item in stats.get("unarchived_http_capabilities") or []
        if str(item)
    ]
    if attempted == 0 and total == 0:
        return "unavailable", "no calls were recorded for this run"
    if failed or dropped or stored < attempted or capture_limited or unarchived:
        return "partial", (
            f"{stored} of {attempted} recorded calls were stored"
            + (f"; {dropped} were dropped at the capture ceiling" if dropped else "")
            + (
                f"; {capture_limited} calls have adapter-limited wire detail"
                if capture_limited else ""
            )
            + _unarchived_clauses(stats, unarchived)
        )
    return "complete", f"all {stored} recorded calls were stored"


def _unarchived_clauses(stats: Mapping[str, Any], unarchived: list[str]) -> str:
    if not unarchived:
        return ""
    if "unarchived_external_tool_capabilities" not in stats:
        # Hunt stats, and scan stats computed before the split, carry one list.
        return (
            "; HTTP-producing capabilities with no archived calls: "
            + ", ".join(unarchived[:10])
        )
    external = [
        str(item) for item in stats.get("unarchived_external_tool_capabilities") or []
        if str(item)
    ]
    engine = [
        str(item) for item in stats.get("unarchived_engine_capabilities") or [] if str(item)
    ]
    return (
        (
            "; external scanner traffic (relayed as an opaque pinned tunnel, not archived): "
            + ", ".join(external[:10])
            if external else ""
        )
        + (
            "; engine capabilities with no archived calls: " + ", ".join(engine[:10])
            if engine else ""
        )
    )


# --- Building an export -------------------------------------------------------------------------
# Every payload an export shows is decoded, redacted or masked (unless raw) and sized by
# ``archive_export_worker``: a body comes back as JSON text that the rendered response splices
# in at a placeholder, headers as the redacted mapping. ``export_document`` runs them in this
# process (its callers are synchronous); ``build_export`` runs them in a worker process pool,
# because the regex engine holds the interpreter lock for a whole pass and an API thread would
# still stall the event loop (external release audit, 2026-10-09). Both apply the same budgets in
# the same order, so they show the same text and omit the same payloads.

EXTERNAL_READ_BUDGET = "external_read_budget"
MASKING_BUDGET = "masking_budget"
HEADER_BUDGET = "header_budget"
_OMISSION_DETAIL = {
    EXTERNAL_READ_BUDGET: "stored externally beyond this export's read budget",
    MASKING_BUDGET: "beyond this export's masking budget",
    HEADER_BUDGET: "beyond this export's header budget",
    OVER_MASKING_LIMIT: "over the masking size limit, so only a raw export carries it",
    MASKING_FAILED: "could not be masked within the masking worker's memory",
}
_MASKING_OMISSIONS = frozenset({MASKING_BUDGET, OVER_MASKING_LIMIT, MASKING_FAILED})
_HEADER_FIELDS = ("request_headers", "response_headers")


def masked_export_budget() -> int:
    """Bytes of JSON body text one masked export may hold (SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES)."""
    raw = str(os.environ.get("SHAKERSCAN_HTTP_ARCHIVE_MASKED_EXPORT_BYTES") or "").strip()
    try:
        value = int(raw) if raw else DEFAULT_MASKED_EXPORT_BYTES
    except ValueError:
        value = DEFAULT_MASKED_EXPORT_BYTES
    return max(MIN_MASKED_EXPORT_BYTES, min(MAX_MASKED_EXPORT_BYTES, value))


def is_light_export(export_format: str, limit: int, *, redaction: str) -> bool:
    """A masked browse page (the UI's 25- and 250-row pages), not a download: bounded by its own
    small budgets, so it is admitted beside heavy exports instead of waiting behind them. A raw
    export has no body budget, so it is always heavy, however few rows it asks for."""
    return redaction != "raw" and export_format == "transactions" and 0 < int(limit) <= LIGHT_EXPORT_ROWS


def body_budget(redaction: str, *, light: bool = False) -> int | None:
    """Encoded body bytes an export may hold: none for a raw one, less for a browse page."""
    if redaction == "raw":
        return None
    budget = masked_export_budget()
    return min(budget, LIGHT_EXPORT_BODY_BYTES) if light else budget


def header_budget(*, light: bool = False) -> int:
    """Encoded header bytes any export may hold, raw included."""
    return LIGHT_EXPORT_HEADER_BYTES if light else MAX_EXPORT_HEADER_BYTES


def export_read_budget(redaction: str, *, light: bool = False) -> int:
    """External payload bytes to read for an export: never more than its budgets can show."""
    if redaction == "raw":
        return MAX_EXTERNAL_PAYLOAD_BYTES
    return min(MAX_EXTERNAL_PAYLOAD_BYTES, (body_budget(redaction, light=light) or 0) + header_budget(light=light))


class _Budget:
    """The encoded bytes one export may still hold of one kind of payload; once one does not
    fit, every later one is left out too, so an export is always a prefix plus what follows."""

    def __init__(self, limit: int | None) -> None:
        self.remaining = limit
        self.exhausted = False

    def fits(self, size: int) -> bool:
        return self.remaining is None or (not self.exhausted and size <= self.remaining)

    def charge(self, size: int, encoded: int) -> bool:
        if self.remaining is None:
            return True
        if not self.fits(size) or encoded > self.remaining:
            self.exhausted = True
            return False
        self.remaining -= encoded
        return True


class _Budgets:
    def __init__(self, bodies: int | None, headers: int | None) -> None:
        self.body = _Budget(bodies)
        self.headers = _Budget(headers)


class _PayloadJob:
    """One payload of one call: in hand (``value``) or still in the archive (``stored``)."""

    __slots__ = ("extra", "field", "index", "kind", "masked", "present", "reason", "size", "value")

    def __init__(
        self, index: int, field: str, value: Any, masked: bool, *,
        stored_size: int | None = None, extra: Any = None,
    ) -> None:
        self.index, self.field, self.value, self.masked = index, field, value, masked
        self.kind = "headers" if field in _HEADER_FIELDS else "body"
        # body: (recorded digest,) when legacy decoding is still due; headers: private workflow.
        self.extra = extra
        # A payload read later (``stored_size`` known) is present before it is in hand; an empty
        # header set has nothing to show or withhold.
        empty = self.kind == "headers" and isinstance(value, (dict, str)) and value in ({}, "", "{}")
        self.present = (value is not None and not empty) or stored_size is not None
        self.size = stored_body_size(value) if stored_size is None else stored_size
        self.reason: str | None = None  # set when the read could not deliver it


def _budget_of(job: _PayloadJob, budgets: _Budgets) -> _Budget:
    return budgets.headers if job.kind == "headers" else budgets.body


def _wants(job: _PayloadJob, budgets: _Budgets) -> bool:
    """Whether the payload is worth reading and encoding now (budgets only ever tighten)."""
    if not job.present or job.reason is not None:
        return False
    if job.kind == "body" and job.masked and job.size > MAX_MASKED_BODY_CHARS:
        return False
    return _budget_of(job, budgets).fits(job.size)


Outcome = tuple[Any, int, str | None]  # (body fragment or header mapping, encoded size, reason)
Settled = tuple[Any, str | None]


def _settle(job: _PayloadJob, budgets: _Budgets, outcome: Outcome | None) -> Settled:
    """The payload's final value or omission reason, decided in row order."""
    if job.reason is not None:
        return None, job.reason
    if not job.present:
        return None, None
    if job.kind == "body" and job.masked and job.size > MAX_MASKED_BODY_CHARS:
        return None, OVER_MASKING_LIMIT
    budget = _budget_of(job, budgets)
    if not budget.fits(job.size):
        budget.exhausted = True
        return None, HEADER_BUDGET if job.kind == "headers" else MASKING_BUDGET
    assert outcome is not None
    value, size, reason = outcome
    if reason is not None:
        return None, reason
    if value is not None and not budget.charge(job.size, size):
        return None, HEADER_BUDGET if job.kind == "headers" else MASKING_BUDGET
    return value, None


def _project_without_payloads(row: Mapping[str, Any], *, redaction: str) -> tuple[dict[str, Any], dict[str, bool], bool]:
    """One archived call redacted (unless raw), its payloads set aside:
    ``(item, body allowed, headers private)``."""
    item = dict(row)
    bodies = {key: True for key in _BODY_FIELDS}
    private = False
    item.pop(LAZY_PAYLOADS, None)
    for key in (*_BODY_FIELDS, *_HEADER_FIELDS):
        item[key] = None
    if redaction != "raw":
        # Payloads are redacted on their own (archive_export_worker): a value beside a
        # secret-named parameter or nested below a secret-named key is not under a sensitive
        # dictionary key, and a stored body is text (N39).
        item = redact_sensitive(item, redact_strings=True, scrub_text=True)
        # State-changing Hunt bodies can contain low-entropy pairing PINs or newly
        # issued credentials. Key-name redaction and an unsalted body digest are
        # insufficient: both the body and digest stay raw-export-only.
        if (
            item.get("plane") == "hunt"
            and item.get("capability_name") == "http.request"
            and str(item.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            bodies["request_body"] = False
            item["request_body_sha256"] = None
        metadata = _decoded(item.get("metadata_json"))
        private_workflow = isinstance(metadata, Mapping) and metadata.get("workflow_values_private") is True
        # A private-workflow marker binds on every plane: scan mutation verifiers replay
        # the same private collection requests a Hunt does.
        if private_workflow or (item.get("plane") == "hunt" and item.get("capability_name") in {
            "collections.replay_safe", "collections.replay_active",
        }):
            # Response captures and arbitrary header bindings can contain PINs or
            # tokens under any name, including on GET. Keep values and their
            # brute-forceable digests raw-export-only in every public archive view
            # (header values become "[REDACTED]" in the worker).
            private = True
            for prefix in ("request", "response"):
                bodies[prefix + "_body"] = False
                item[prefix + "_body_sha256"] = None
    return item, bodies, private


def _projection(item: Mapping[str, Any], shown: Mapping[str, Any], reasons: Mapping[str, str]) -> dict[str, Any]:
    """The exported shape of one call; ``shown`` holds what each payload shows (a body as its
    placeholder, headers as the redacted mapping)."""
    def side(prefix: str) -> dict[str, Any]:
        field = prefix + "_body"
        withheld = reasons.get(field) in _MASKING_OMISSIONS
        return {
            "headers": shown.get(prefix + "_headers") or {},
            "body": shown.get(field),
            # A body this export left out carries no digest, so nothing reads as present.
            "sha256": None if withheld else item.get(field + "_sha256"),
            "bytes": item.get(field + "_bytes"),
        }

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
        "request": side("request"),
        "response": side("response"),
        "remote_ip": item.get("remote_ip"),
        # Whether this call went to an operator-confirmed origin rather than the target's
        # resolved address. The two are not comparable evidence.
        "direct_origin": bool(item.get("direct_origin")),
        "started_at": _json_safe(item.get("started_at")),
        "elapsed_ms": item.get("elapsed_ms"),
        "error": item.get("error"),
        "truncated": bool(item.get("truncated")),
        "capture": item.get("metadata_json") or {},
        # Payloads this call recorded but the archive cannot show (see the export fidelity).
        "payload_unavailable": list(item.get("payload_unavailable") or ()),
        # Payloads the archive holds but this export left out, and why: never shown unmasked,
        # never shown as empty.
        "payload_omitted": sorted(reasons),
        "payload_omitted_reasons": dict(sorted(reasons.items())),
    }


class EncodedExport:
    """An export whose body strings are placeholders for already JSON-encoded fragments."""

    def __init__(self, document: dict[str, Any], fragments: dict[str, bytes], token: str) -> None:
        self.document = document
        self.fragments = fragments
        self._placeholder = re.compile(r'"\\u0000archive-body:' + token + r':(\d+)\\u0000"')
        self._prefix = f"\x00archive-body:{token}:"

    def render(self, document: Any | None = None) -> bytes:
        """The response bytes for ``document`` (this export by default, or a record holding it).

        Serialized as Starlette's JSONResponse serializes; each placeholder is replaced by its
        fragment, so no body is encoded in this process.
        """
        skeleton = json.dumps(
            self.document if document is None else document,
            ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":"),
        )
        pieces: list[bytes] = []
        cursor = 0
        for match in self._placeholder.finditer(skeleton):
            pieces.append(utf8(skeleton[cursor:match.start()]))
            pieces.append(self.fragments[match.group(1)])
            cursor = match.end()
        pieces.append(utf8(skeleton[cursor:]))
        return b"".join(pieces)

    def materialize(self, document: Any | None = None) -> Any:
        """``document`` with every placeholder replaced by its body text."""
        def walk(value: Any) -> Any:
            if isinstance(value, str) and value.startswith(self._prefix):
                return json.loads(self.fragments[value[len(self._prefix):-1]])
            if isinstance(value, dict):
                return {key: walk(item) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            return value

        return walk(self.document if document is None else document)



def _plan(rows: Sequence[Mapping[str, Any]], redaction: str) -> tuple[list[dict[str, Any]], list[_PayloadJob]]:
    items: list[dict[str, Any]] = []
    jobs: list[_PayloadJob] = []
    masked = redaction != "raw"
    for index, row in enumerate(rows):
        item, allowed, private = _project_without_payloads(row, redaction=redaction)
        items.append(item)
        stored = row.get(LAZY_PAYLOADS)
        for field in PAYLOAD_FIELDS:
            is_body = field in _BODY_FIELDS
            permitted = allowed[field] if is_body else True
            in_hand_extra = None if is_body else private
            if stored is None:
                jobs.append(_PayloadJob(index, field, row.get(field) if permitted else None, masked, extra=in_hand_extra))
            elif permitted and field in stored:
                jobs.append(_PayloadJob(
                    index, field, None, masked, stored_size=stored[field],
                    extra=(row.get(f"{field}_sha256"),) if is_body else private,
                ))
            else:
                jobs.append(_PayloadJob(index, field, None, masked))
    return items, jobs


def _assemble(
    rows: Sequence[Mapping[str, Any]],
    items: list[dict[str, Any]],
    jobs: list[_PayloadJob],
    outcomes: list[Settled],
    *,
    export_format: str,
    redaction: str,
    owner: Mapping[str, Any],
    total: int,
    archive_total: int | None,
    stats: Mapping[str, int] | None,
    creator_version: str,
) -> EncodedExport:
    token = secrets.token_hex(8)
    fragments: dict[str, bytes] = {}
    shown: list[dict[str, Any]] = [{} for _ in items]
    reasons: list[dict[str, str]] = [
        {field: EXTERNAL_READ_BUDGET for field in (row.get("payload_omitted") or ())} for row in rows
    ]
    for job, (value, reason) in zip(jobs, outcomes):
        if reason is not None:
            reasons[job.index][job.field] = reason
        elif value is not None and job.kind == "headers":
            shown[job.index][job.field] = value
        elif value is not None:
            key = str(len(fragments))
            fragments[key] = value
            shown[job.index][job.field] = f"\x00archive-body:{token}:{key}\x00"
    projected = [_projection(item, show, why) for item, show, why in zip(items, shown, reasons)]
    document = _envelope(
        rows, projected, export_format=export_format, redaction=redaction, owner=owner,
        total=total, archive_total=archive_total, stats=stats, creator_version=creator_version,
    )
    return EncodedExport(document, fragments, token)


def _omission_notes(projected: Sequence[Mapping[str, Any]]) -> list[str]:
    counts = {reason: 0 for reason in _OMISSION_DETAIL}
    for item in projected:
        for reason in set(item["payload_omitted_reasons"].values()):
            counts[reason] = counts.get(reason, 0) + 1
    notes = []
    if counts[EXTERNAL_READ_BUDGET]:
        notes.append(f"{counts[EXTERNAL_READ_BUDGET]} recorded call(s) have externally stored payloads "
                     "omitted from this export to bound its size; export fewer calls at a time to include them")
    if counts[MASKING_BUDGET]:
        notes.append(f"{counts[MASKING_BUDGET]} recorded call(s) have bodies left out because this masked "
                     "export reached its masking budget; export fewer calls at a time to include them")
    if counts[OVER_MASKING_LIMIT]:
        notes.append(f"{counts[OVER_MASKING_LIMIT]} recorded call(s) have a body over the "
                     f"{MAX_MASKED_BODY_CHARS}-character masking limit, withheld from every masked view")
    if counts[MASKING_FAILED]:
        notes.append(f"{counts[MASKING_FAILED]} recorded call(s) have a payload that could not be masked "
                     "safely, withheld from this export")
    if counts[HEADER_BUDGET]:
        notes.append(f"{counts[HEADER_BUDGET]} recorded call(s) have headers left out because this export "
                     "reached its header budget; export fewer calls at a time to include them")
    return notes


def _har_comment(entry_comment: str, reasons: Mapping[str, str]) -> str:
    parts = [entry_comment] if entry_comment else []
    parts.extend(
        f"{field.replace('_', ' ')} omitted: {_OMISSION_DETAIL.get(reason, reason)}"
        for field, reason in sorted(reasons.items())
    )
    return "; ".join(parts)


def _envelope(
    rows: Sequence[Mapping[str, Any]],
    projected: list[dict[str, Any]],
    *,
    export_format: str,
    redaction: str,
    owner: Mapping[str, Any],
    total: int,
    archive_total: int | None,
    stats: Mapping[str, int] | None,
    creator_version: str,
) -> dict[str, Any]:
    fidelity, fidelity_detail = archive_fidelity(
        stats or {}, total=archive_total if archive_total is not None else total,
    )
    # A recorded call whose headers or body could not be archived or decrypted is shown with its
    # metadata, but the archive does not claim it holds that call completely.
    missing = sum(1 for item in projected if item["payload_unavailable"])
    notes = []
    if missing:
        notes.append(f"{missing} recorded call(s) have payloads that are unavailable: archived "
                     "without an encryption key, sealed with a key this install does not have, or "
                     "stored in an external file or object that can no longer be read")
    notes.extend(_omission_notes(projected))
    for note in notes:
        fidelity, fidelity_detail = (
            ("partial", note) if fidelity == "complete" else (fidelity, f"{fidelity_detail}; {note}")
        )
    redaction_detail = (
        "Verbatim captured traffic; headers, cookies, request bodies, response bodies, and "
        "URL credentials may contain secrets. Treat this export as sensitive."
        if redaction == "raw"
        else "Known credential keys, headers, URL parameters, and common token shapes are masked; "
        "in bodies, every value under or beside a secret-named key (JSON, YAML, form fields, "
        "assignments) and every provider-format secret is withheld, as in exposure evidence; "
        "state-changing Hunt request bodies and their digests are omitted because they may contain "
        "low-entropy pairing secrets. Other arbitrary target-controlled bodies may still contain secrets."
    )
    if export_format == "har":
        # A masked HAR states that it is masked in its own log comment and creator, so it can never
        # pass for the verbatim request; verbatim HAR is an explicit, deployment-allowed choice.
        entries = []
        for row, item in zip(rows, projected):
            entry = har_entry(
                {**dict(row), **{
                    # The projection is the masked view; the row is what was captured.
                    "url": item["url"],
                    "request_headers": item["request"]["headers"],
                    "response_headers": item["response"]["headers"],
                }},
                request_body=item["request"]["body"],
                response_body=item["response"]["body"],
            )
            entry["comment"] = _har_comment(entry["comment"], item["payload_omitted_reasons"])
            entries.append(entry)
        document = har_document(entries, creator_version=creator_version)
        if redaction != "raw":
            document["log"]["creator"]["name"] = "ShakerScan (masked)"
        document["log"]["comment"] = json.dumps({
            "owner": dict(owner),
            "redaction": redaction,
            "redaction_detail": redaction_detail,
            "sensitive": redaction == "raw",
            "exported": len(entries),
            "total": total,
            "archive_total": archive_total if archive_total is not None else total,
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
        "redaction_detail": redaction_detail,
        "residual_secret_risk": redaction != "raw",
        # Backed by counters rather than inferred from the row count, because capture and
        # persistence failures are swallowed and one surviving row is not a whole run.
        "fidelity": fidelity,
        "fidelity_detail": fidelity_detail,
        "capture_stats": dict(stats or {}),
        "exported": len(projected),
        "total": total,
        # ``total`` is the number matching the current filters. This second count lets an
        # in-app browser say "3 matches in 418 calls" without downloading the archive.
        "archive_total": archive_total if archive_total is not None else total,
        "truncated_export": len(projected) < total,
        "transactions": projected,
    }



def _settle_in_process(jobs: list[_PayloadJob], budgets: _Budgets) -> list[Settled]:
    return [
        _settle(job, budgets, encode_payload(job.kind, job.value, job.masked, job.extra) if _wants(job, budgets) else None)
        for job in jobs
    ]


def _budgets_for(redaction: str, *, light: bool = False) -> _Budgets:
    return _Budgets(body_budget(redaction, light=light), header_budget(light=light))


def project(row: Mapping[str, Any], *, redaction: str) -> dict[str, Any]:
    """One archived call, redacted unless the caller explicitly asked for raw."""
    items, jobs = _plan([row], redaction)
    outcomes = _settle_in_process(jobs, _Budgets(None, None))
    reasons = {field: EXTERNAL_READ_BUDGET for field in (row.get("payload_omitted") or ())}
    shown: dict[str, Any] = {}
    for job, (value, reason) in zip(jobs, outcomes):
        if reason is not None:
            reasons[job.field] = reason
        elif value is not None:
            shown[job.field] = value if job.kind == "headers" else json.loads(value)
    return _projection(items[0], shown, reasons)


def export_document(
    rows: Sequence[Mapping[str, Any]],
    *,
    export_format: str,
    redaction: str,
    owner: Mapping[str, Any],
    total: int,
    archive_total: int | None = None,
    stats: Mapping[str, int] | None = None,
    creator_version: str = "2.0.0",
    light: bool = False,
) -> dict[str, Any]:
    """Build the export envelope in this process, stating what it is and what it is not."""
    items, jobs = _plan(rows, redaction)
    outcomes = _settle_in_process(jobs, _budgets_for(redaction, light=light))
    encoded = _assemble(
        rows, items, jobs, outcomes, export_format=export_format, redaction=redaction, owner=owner,
        total=total, archive_total=archive_total, stats=stats, creator_version=creator_version,
    )
    return encoded.materialize()


# --- Off the event loop -------------------------------------------------------------------------


class ExportBusy(RuntimeError):
    """No export slot came free for this caller within the admission wait: retry later."""


class ExportUnavailable(RuntimeError):
    """The masking workers failed; the export is refused rather than shown unmasked."""


class _ExportSlots:
    """``capacity`` export slots, at most ``per_caller`` of them held by one caller.

    Each slot holds one export's rows, a batch of payloads, fragments and response at once, so
    the slots, not the request rate, bound the memory exports use.
    """

    def __init__(self, capacity: int, per_caller: int | None) -> None:
        self.capacity, self.per_caller = capacity, per_caller
        self.active = 0
        self.callers: dict[str, int] = {}
        self.waiters: list[asyncio.Future[None]] = []

    def _free_for(self, caller: str | None) -> bool:
        if self.active >= self.capacity:
            return False
        return not (caller and self.per_caller and self.callers.get(caller, 0) >= self.per_caller)

    async def acquire(self, caller: str | None, wait_seconds: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        while not self._free_for(caller):
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ExportBusy("no archive export slot is free for this caller")
            waiter = loop.create_future()
            self.waiters.append(waiter)
            try:
                await asyncio.wait_for(waiter, remaining)
            except TimeoutError as exc:
                raise ExportBusy("no archive export slot is free for this caller") from exc
            finally:
                if waiter in self.waiters:
                    self.waiters.remove(waiter)
        self.active += 1
        if caller:
            self.callers[caller] = self.callers.get(caller, 0) + 1

    def release(self, caller: str | None) -> None:
        self.active -= 1
        if caller:
            left = self.callers.get(caller, 1) - 1
            if left > 0:
                self.callers[caller] = left
            else:
                self.callers.pop(caller, None)
        waiters, self.waiters = self.waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)


_admission: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, _ExportSlots]] = weakref.WeakKeyDictionary()
_payload_pool: ProcessPoolExecutor | None = None


@asynccontextmanager
async def export_admission(
    caller: str | None = None, wait_seconds: float | None = None, *, light: bool = False,
) -> AsyncIterator[None]:
    """An export slot, taken before any row is read.

    A heavy export (a download, a HAR, a Hunt record) takes one of ``MAX_CONCURRENT_EXPORT_BUILDS``
    slots, at most ``MAX_EXPORTS_PER_CALLER`` per caller. A browse page (``is_light_export``)
    takes one of ``MAX_CONCURRENT_BROWSE_PAGES`` separate slots with no per-caller rule, so a
    user's own browsing never waits behind their download. A request that cannot get a slot in
    time is refused with ``ExportBusy`` (503 with Retry-After) instead of queueing with its rows.
    """
    loop = asyncio.get_running_loop()
    pools = _admission.get(loop)
    if pools is None:
        pools = _admission[loop] = {
            "heavy": _ExportSlots(MAX_CONCURRENT_EXPORT_BUILDS, MAX_EXPORTS_PER_CALLER),
            "light": _ExportSlots(MAX_CONCURRENT_BROWSE_PAGES, None),
        }
    slots = pools["light" if light else "heavy"]
    default_wait = BROWSE_ADMISSION_WAIT_SECONDS if light else EXPORT_ADMISSION_WAIT_SECONDS
    await slots.acquire(caller, default_wait if wait_seconds is None else wait_seconds)
    try:
        yield
    finally:
        slots.release(caller)


def _workers() -> ProcessPoolExecutor:
    """The masking worker pool, started on the first export.

    Its processes import only the masking modules (``worker_context``) and are not recycled:
    a recycled worker paid a fresh interpreter start for every few hundred payloads.
    """
    global _payload_pool
    if _payload_pool is None:
        _payload_pool = ProcessPoolExecutor(
            max_workers=MASKING_WORKERS, mp_context=worker_context(), initializer=initialize_worker,
        )
    return _payload_pool


def _discard_workers() -> None:
    global _payload_pool
    pool, _payload_pool = _payload_pool, None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


async def _encode_in_workers(jobs: list[_PayloadJob], budgets: _Budgets) -> list[Settled]:
    """Every payload encoded in the worker pool and settled in order.

    Consecutive payloads travel in chunks of at most ``WORKER_CHUNK_BYTES`` (one at least) and
    ``WORKER_CHUNK_BODIES``, at most ``WORKER_CHUNKS_IN_FLIGHT`` chunks ahead: one round trip per
    payload cost more than masking a small one.
    """
    loop = asyncio.get_running_loop()
    pool = _workers()
    outcomes: list[Settled] = []
    chunk_of: dict[int, tuple[asyncio.Future[list[Outcome]], int]] = {}
    in_flight: list[asyncio.Future[list[Outcome]]] = []
    submitted = 0

    def submit_chunk() -> None:
        nonlocal submitted
        members: list[int] = []
        size = 0
        while submitted < len(jobs):
            job = jobs[submitted]
            if not (_wants(job, budgets) and job.value is not None):
                submitted += 1
                continue
            if members and (size + job.size > WORKER_CHUNK_BYTES or len(members) >= WORKER_CHUNK_BODIES):
                break
            members.append(submitted)
            size += job.size
            submitted += 1
        if members:
            future = loop.run_in_executor(
                pool, encode_payloads,
                [(jobs[i].kind, jobs[i].value, jobs[i].masked, jobs[i].extra) for i in members],
            )
            in_flight.append(future)
            for offset, index in enumerate(members):
                chunk_of[index] = (future, offset)

    try:
        for position, job in enumerate(jobs):
            in_flight[:] = [future for future in in_flight if not future.done()]
            while submitted < len(jobs) and len(in_flight) < WORKER_CHUNKS_IN_FLIGHT:
                before = submitted
                submit_chunk()
                if submitted == before:
                    break
            entry = chunk_of.pop(position, None)
            outcome = (await entry[0])[entry[1]] if entry is not None else None
            outcomes.append(_settle(job, budgets, outcome))
            job.value = None  # the settled value, if any, is all this export keeps
    except BrokenProcessPool as exc:
        _discard_workers()
        raise ExportUnavailable("the archive masking workers stopped") from exc
    finally:
        for future in in_flight:
            future.cancel()
    return outcomes


PayloadReader = Callable[[Sequence[Any], int], Awaitable[tuple[dict[str, dict[str, Any]], int]]]


def _batches(jobs: list[_PayloadJob]) -> Iterator[list[_PayloadJob]]:
    """Consecutive jobs holding at most ``EXPORT_BATCH_BYTES`` of stored payload (one at least)."""
    batch: list[_PayloadJob] = []
    size = 0
    for job in jobs:
        if batch and (size + job.size > EXPORT_BATCH_BYTES or len(batch) >= EXPORT_BATCH_BODIES):
            yield batch
            batch, size = [], 0
        batch.append(job)
        size += job.size
    if batch:
        yield batch


async def _encode_read_lazily(
    rows: Sequence[Mapping[str, Any]], items: list[dict[str, Any]], jobs: list[_PayloadJob],
    budgets: _Budgets, read_payloads: PayloadReader, read_budget: int,
) -> list[Settled]:
    """Read payloads a batch at a time, only those the budgets can still take, and encode them.

    The rows came without their payloads (``read_transactions(payloads=False)``), so an export
    holds one batch of stored headers and bodies at a time, never every payload it lists.
    """
    outcomes: list[Settled] = []
    for batch in _batches(jobs):
        wanted = [job for job in batch if job.value is None and _wants(job, budgets)]
        if wanted:
            ids = list(dict.fromkeys(rows[job.index]["id"] for job in wanted))
            found, used = await read_payloads(ids, read_budget)
            read_budget = max(0, read_budget - used)
            for job in wanted:
                payloads = found.get(str(rows[job.index]["id"]))
                if payloads is None or job.field in payloads["unavailable"]:
                    job.present = False  # purged since, or unreadable: the call says so
                    unavailable = items[job.index].setdefault("payload_unavailable", [])
                    if job.field not in unavailable:
                        unavailable.append(job.field)
                elif job.field in payloads["omitted"]:
                    job.reason = EXTERNAL_READ_BUDGET
                else:
                    job.value = payloads[job.field]
                    job.present = job.value is not None
            del found
        outcomes.extend(await _encode_in_workers(batch, budgets))
    return outcomes


async def build_export(
    rows: Sequence[Mapping[str, Any]],
    *,
    export_format: str,
    redaction: str,
    owner: Mapping[str, Any],
    total: int,
    archive_total: int | None = None,
    stats: Mapping[str, int] | None = None,
    creator_version: str = "2.0.0",
    read_payloads: PayloadReader | None = None,
    light: bool = False,
) -> EncodedExport:
    """``export_document`` with every payload decoded, redacted and encoded in the worker pool.

    A scanned service chooses what it returns, and the archive keeps it; masking that body
    for a later export must not stall every other request the API is serving (external
    release audit, 2026-10-09). Rows read without payloads get them from ``read_payloads`` a
    batch at a time. Call it holding ``export_admission``.
    """
    items, jobs = _plan(rows, redaction)
    budgets = _budgets_for(redaction, light=light)
    if read_payloads is None:
        outcomes = await _encode_in_workers(jobs, budgets)
    else:
        outcomes = await _encode_read_lazily(
            rows, items, jobs, budgets, read_payloads, export_read_budget(redaction, light=light),
        )
    return _assemble(
        rows, items, jobs, outcomes, export_format=export_format, redaction=redaction, owner=owner,
        total=total, archive_total=archive_total, stats=stats, creator_version=creator_version,
    )


async def purge_transactions(
    conn, *, scan_id: str | None, hunt_run_id: str | None, results_dir: Path | None = None,
    scan_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Delete a run's archived calls and the blobs only they referenced.

    The evidence retention sweep is target-scoped and reaches objects through a scan or
    finding, which a Hunt archive blob has neither of. Without a direct path the one store
    that certainly holds credentials would be the one an operator could never clear.
    Content-addressed blobs are shared, so an object is removed only once nothing else
    points at it.
    """
    # A visible scan's calls are archived under its worker child scans, and export shows the
    # whole tree. Purge the same set, or the operator clears the run they are looking at
    # while its child traffic (credential-bearing payloads included) stays behind.
    if scan_id:
        owners = list(dict.fromkeys(str(value) for value in (scan_ids or (scan_id,))))
        if str(scan_id) not in owners:
            owners.insert(0, str(scan_id))
        owner_clause, owner_id = "scan_id = ANY($1::uuid[])", owners
    else:
        owners = [str(hunt_run_id)]
        owner_clause, owner_id = "hunt_run_id=$1", hunt_run_id
    async with conn.transaction():
        objects = await conn.fetch(
            f"""SELECT DISTINCT eo.id AS object_id, eo.storage_uri
                FROM http_transactions tx
                CROSS JOIN LATERAL unnest(ARRAY[
                    tx.request_headers_object_id, tx.request_body_object_id,
                    tx.response_headers_object_id, tx.response_body_object_id
                ]) AS ref(object_id)
                JOIN evidence_objects eo ON eo.id=ref.object_id
                WHERE tx.{owner_clause}""",
            owner_id,
        )
        removed = await conn.fetchval(
            f"WITH gone AS (DELETE FROM http_transactions WHERE {owner_clause} RETURNING 1)"
            " SELECT COUNT(*) FROM gone",
            owner_id,
        )
        object_ids = [row["object_id"] for row in objects if row["object_id"]]
        deleted_objects: list[Any] = []
        if object_ids:
            deleted_objects = await conn.fetch(
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
                         AND NOT EXISTS (
                             SELECT 1 FROM evidence_instances i
                             WHERE i.evidence_object_id=eo.id
                         )
                         AND NOT EXISTS (
                             SELECT 1 FROM tool_receipts receipt
                             WHERE eo.id IN (
                                 receipt.stdout_evidence_object_id,
                                 receipt.stderr_evidence_object_id,
                                 receipt.output_artifact_id
                             )
                         )
                       RETURNING id, storage_uri
                   ) SELECT id, storage_uri FROM gone""",
                object_ids,
            )
        await conn.execute(
            "DELETE FROM http_archive_stats WHERE owner_kind=$1 AND owner_id = ANY($2::uuid[])",
            "scan" if scan_id else "hunt", owners,
        )
    deleted_files: list[str] = []
    missing_files: list[str] = []
    blob_errors: list[dict[str, str]] = []
    for item in deleted_objects:
        storage_uri = str(item.get("storage_uri") or "")
        still_shared = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM evidence_objects WHERE storage_uri=$1)",
            storage_uri,
        ) if storage_uri else False
        if still_shared:
            continue
        local_path = local_evidence_path(results_dir, storage_uri) if results_dir else None
        if local_path is not None:
            try:
                local_path.unlink()
                deleted_files.append(str(local_path))
            except FileNotFoundError:
                missing_files.append(str(local_path))
            except OSError as exc:
                blob_errors.append({"storage_uri": storage_uri, "error": type(exc).__name__})
        elif storage_uri.startswith("s3:evidence_objects/"):
            result = await asyncio.to_thread(delete_remote_evidence_object, storage_uri)
            if not result.get("deleted"):
                blob_errors.append({
                    "storage_uri": storage_uri,
                    "error": str(result.get("error") or result.get("status") or "delete_failed"),
                })
    return {
        "owner_kind": "scan" if scan_id else "hunt",
        "owner_ids": owners,
        "transactions_deleted": int(removed or 0),
        "blobs_deleted": len(deleted_objects),
        "blob_files_deleted": deleted_files,
        "blob_files_missing": missing_files,
        "blob_delete_errors": blob_errors,
    }


__all__ = [
    "EXPORT_FORMATS",
    "DEFAULT_MASKED_EXPORT_BYTES",
    "EXPORT_RETRY_AFTER_SECONDS",
    "EncodedExport",
    "LAZY_PAYLOADS",
    "ExportBusy",
    "ExportUnavailable",
    "MAX_CONCURRENT_EXPORT_BUILDS",
    "MAX_EXPORT_ROWS",
    "build_export",
    "export_admission",
    "export_read_budget",
    "is_light_export",
    "masked_export_budget",
    "REDACTION_MODES",
    "archive_fidelity",
    "count_transactions",
    "read_archive_stats",
    "export_document",
    "project",
    "purge_transactions",
    "read_transaction_payloads",
    "read_transactions",
]
