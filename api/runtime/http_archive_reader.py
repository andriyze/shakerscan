"""Read and export the HTTP transaction archive.

Export answers "what did this scan or hunt actually send", so two things it states
explicitly are the redaction mode and the fidelity. An export that quietly masks a token
looks like evidence the token was never sent, and a run that predates the archive has no
transactions at all -- reporting that as an empty list would read as "it sent nothing".
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import hmac
import json
import os
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


def _decoded(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _body_text(value: Any) -> str | None:
    """Project already decoded the storage serialization; strings are wire text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return json.dumps(value)


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
) -> list[dict[str, Any]]:
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
        f"{_SELECT}{where} ORDER BY t.started_at, t.sequence, t.id"
        f" LIMIT ${len(params) - 1} OFFSET ${len(params)}",
        *params,
    )
    try:
        from runtime.archive_blob_secrets import PAYLOAD_FIELDS, reveal_payload
    except ModuleNotFoundError:  # package import layout
        from .archive_blob_secrets import PAYLOAD_FIELDS, reveal_payload
    rows = [dict(row) for row in rows]
    loaded, omitted = await _load_external_payloads(
        rows, PAYLOAD_FIELDS,
        results_dir=results_dir or Path(os.environ.get("RESULTS_DIR") or "/results"),
        budget=external_payload_budget,
    )
    revealed = []
    for row in rows:
        metadata = _decoded(row.get("metadata_json")) or {}
        unavailable = set(metadata.get("payloads_unavailable") or ()) if isinstance(metadata, dict) else set()
        omitted_fields: set[str] = set()
        for key in PAYLOAD_FIELDS:
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
            if key in _BODY_FIELDS:
                value = _legacy_bytes_repr(value, recorded_sha256=row.get(f"{key}_sha256"))
                value = _legacy_json_string(value, recorded_sha256=row.get(f"{key}_sha256"))
            row[key] = value
            if lost:
                unavailable.add(key)
        if unavailable:
            row["payload_unavailable"] = sorted(unavailable)
        if omitted_fields:
            row["payload_omitted"] = sorted(omitted_fields)
        revealed.append(row)
    return revealed


def _is_external(storage_uri: Any) -> bool:
    """The payload's object exists but is stored outside its row (a file or an S3 object)."""
    return isinstance(storage_uri, str) and bool(storage_uri) and not storage_uri.startswith("inline:")


def _read_external_payloads(
    storage_uris: Sequence[str], *, results_dir: Path, budget: int,
) -> tuple[dict[str, str | None], set[str]]:
    """The stored text of each externalized payload, None where it cannot be read.

    Reads through the evidence store, so local paths stay contained under the results
    directory and S3 URIs are validated as for every other evidence read. No stored hash is
    passed: for a sealed payload it names the plaintext, not the stored envelope, so it is
    checked after decryption instead.
    """
    loaded: dict[str, str | None] = {}
    omitted: set[str] = set()
    remaining = max(0, int(budget))
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
    return loaded, omitted


async def _load_external_payloads(
    rows: Sequence[Mapping[str, Any]], fields: Sequence[str], *, results_dir: Path, budget: int,
) -> tuple[dict[str, str | None], set[str]]:
    """Load the external payloads these rows reference, each once, within the byte budget."""
    wanted: dict[str, None] = {}
    for row in rows:
        for key in fields:
            storage_uri = row.get(f"{key}_storage_uri")
            if row.get(key) is None and _is_external(storage_uri):
                wanted.setdefault(storage_uri, None)
    if not wanted:
        return {}, set()
    # File and S3 reads block; keep them off the event loop.
    return await asyncio.to_thread(
        _read_external_payloads, tuple(wanted), results_dir=results_dir, budget=budget,
    )


def _legacy_json_string(value: Any, *, recorded_sha256: Any) -> Any:
    """Unwrap an old extra JSON encoding only when the wire digest proves it.

    A valid JSON string body (including its quotes/whitespace) otherwise looks identical
    to double-encoded legacy text. Missing provenance must not guess away wire bytes.
    """
    text = _decoded(value)
    if not isinstance(text, str) or not recorded_sha256:
        return value
    if hmac.compare_digest(hashlib.sha256(text.encode()).hexdigest(), str(recorded_sha256)):
        return value
    unwrapped = _decoded(text)
    if isinstance(unwrapped, str) and hmac.compare_digest(
        hashlib.sha256(unwrapped.encode()).hexdigest(), str(recorded_sha256),
    ):
        return json.dumps(unwrapped)
    return value


def _names_plaintext(value: Any, content_sha256: Any) -> bool:
    """Whether a revealed external payload is the one its object row names."""
    if not content_sha256:
        return True
    if not isinstance(value, str):
        return False
    actual = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
    return hmac.compare_digest(actual, str(content_sha256))


def _legacy_bytes_repr(value: Any, *, recorded_sha256: Any) -> Any:
    """Compatibility for bodies archived before the batch writer decoded bytes.

    That writer serialized the bytes object itself, so a body was stored as its Python repr
    ("b'...'") instead of its text. Such a body is decoded here as the writer now stores it
    (UTF-8, undecodable bytes replaced). Text that merely looks like a bytes literal is kept
    when the recorded body digest shows it is the body verbatim, and text that is not
    entirely one bytes literal is never touched.
    """
    if not isinstance(value, str):
        return value
    text = _decoded(value)
    if (not isinstance(text, str) or len(text) < 3
            or text[:2] not in ("b'", 'b"') or text[-1] != text[1]):
        return value
    if recorded_sha256 and hmac.compare_digest(
        hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(), str(recorded_sha256),
    ):
        return value
    try:
        literal = ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return value
    if not isinstance(literal, bytes):
        return value
    return json.dumps(literal.decode("utf-8", errors="replace"))


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
            f"""SELECT DISTINCT action.capability_name
               FROM scan_capability_actions action
               WHERE {scan_filter}
                 AND action.status IN ('success','partial')
                 AND COALESCE(NULLIF(action.requested_budget->>'http_requests','')::int,0) > 0
                 AND NOT EXISTS (
                     SELECT 1 FROM http_transactions tx
                     WHERE tx.scan_id=action.scan_id
                       AND tx.capability_name=action.capability_name
                 )
               ORDER BY action.capability_name""",
            scan_param,
        )
        missing = [str(item["capability_name"]) for item in missing_rows]
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


def project(row: Mapping[str, Any], *, redaction: str) -> dict[str, Any]:
    """One archived call, redacted unless the caller explicitly asked for raw."""
    item = dict(row)
    for key in ("request_headers", "request_body", "response_headers", "response_body"):
        item[key] = _decoded(item.get(key))
    if redaction != "raw":
        item = redact_sensitive(item, redact_strings=True, scrub_text=True)
        # State-changing Hunt bodies can contain low-entropy pairing PINs or newly
        # issued credentials. Key-name redaction and an unsalted body digest are
        # insufficient: both the body and digest stay raw-export-only.
        if (
            item.get("plane") == "hunt"
            and item.get("capability_name") == "http.request"
            and str(item.get("method") or "").upper() in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            item["request_body"] = None
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
            # brute-forceable digests raw-export-only in every public archive view.
            for prefix in ("request", "response"):
                item[prefix + "_body"] = None
                item[prefix + "_body_sha256"] = None
                item[prefix + "_headers"] = {key: "[REDACTED]" for key in (item.get(prefix + "_headers") or {})}
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
        "capture": item.get("metadata_json") or {},
        # Payloads this call recorded but the archive cannot show (see the export fidelity).
        "payload_unavailable": list(item.get("payload_unavailable") or ()),
        # Payloads the archive holds but this export left out to bound its size.
        "payload_omitted": list(item.get("payload_omitted") or ()),
    }


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
) -> dict[str, Any]:
    """Build the export envelope, stating what it is and what it is not."""
    # A masked HAR states that it is masked in its own log comment and creator, so it can never
    # pass for the verbatim request; verbatim HAR is an explicit, deployment-allowed choice.
    projected = [project(row, redaction=redaction) for row in rows]
    fidelity, fidelity_detail = archive_fidelity(
        stats or {}, total=archive_total if archive_total is not None else total,
    )
    # A recorded call whose headers or body could not be archived or decrypted is shown with its
    # metadata, but the archive does not claim it holds that call completely.
    missing = sum(1 for row in rows if row.get("payload_unavailable"))
    omitted = sum(1 for row in rows if row.get("payload_omitted"))
    notes = []
    if missing:
        notes.append(f"{missing} recorded call(s) have payloads that are unavailable: archived "
                     "without an encryption key, sealed with a key this install does not have, or "
                     "stored in an external file or object that can no longer be read")
    if omitted:
        notes.append(f"{omitted} recorded call(s) have externally stored payloads omitted from "
                     "this export to bound its size; export fewer calls at a time to include them")
    for note in notes:
        fidelity, fidelity_detail = (
            ("partial", note) if fidelity == "complete" else (fidelity, f"{fidelity_detail}; {note}")
        )
    redaction_detail = (
        "Verbatim captured traffic; headers, cookies, request bodies, response bodies, and "
        "URL credentials may contain secrets. Treat this export as sensitive."
        if redaction == "raw"
        else "Known credential keys, headers, URL parameters, and common token shapes are masked; "
        "state-changing Hunt request bodies and their digests are omitted because they may contain "
        "low-entropy pairing secrets. Other arbitrary target-controlled bodies may still contain secrets."
    )
    if export_format == "har":
        entries = [
            har_entry(
                {**dict(row), **{
                    # The projection is the masked view; the row is what was captured.
                    "url": item["url"],
                    "request_headers": item["request"]["headers"],
                    "response_headers": item["response"]["headers"],
                }},
                request_body=item["request"]["body"],
                response_body=item["response"]["body"],
            )
            for row, item in zip(rows, projected)
        ]
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
