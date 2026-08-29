"""Durable record of every HTTP call a Scan or Hunt made.

ShakerScan was architected content-free: receipts carried redacted URLs, response header
names and body hashes, and the request meter kept the last hundred events in memory. That
makes a finding defensible and a scan unreviewable -- an operator could not answer "what did
it actually send", reproduce a result in Burp, or hand an auditor the traffic.

This module is the transaction plane. It stores one row per call with the identity of the
work that made it, and puts bodies and headers in the existing content-addressed blob store
so identical payloads collapse to one object. Bodies are kept whole up to a configurable
ceiling; past it the prefix is stored with the true full-body digest and length, and the row
says it was truncated. Nothing is silently dropped.

Storing request and response bodies is a deliberate reversal of the content-free stance, and
it means the archive holds credentials the scanner was given. It is bounded by the same
trusted-operator boundary as the rest of the deployment, redacted by default on the way out,
and swept by the existing evidence retention machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ARCHIVE_SCHEMA = "http-transaction/v1"
# These blobs hold request and response bodies as sent, so they are credential-bearing by
# construction. "sensitive" is both the accurate description and the only way the existing
# retention sweep can reach them: it accepts a fixed set of classes, and a bespoke
# "http_archive" class meant the one store that definitely holds secrets was the one the
# cleanup could never delete.
RETENTION_CLASS = "sensitive"

# Modes an operator can choose. "metadata" keeps the ledger without bodies, for a deployment
# that wants reviewability without holding payloads.
ARCHIVE_MODES = frozenset({"full", "metadata", "off"})
DEFAULT_MODE = "full"
# 10 MB. A response larger than this is almost never the evidence; the prefix plus the true
# digest is, and keeping the whole thing would make one scan's archive unbounded.
DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
# Rows are written in batches; a scan can make tens of thousands of calls and a round trip
# per request would dominate its runtime.
DEFAULT_BATCH_SIZE = 100


def archive_mode() -> str:
    mode = str(os.environ.get("SHAKERSCAN_HTTP_ARCHIVE") or DEFAULT_MODE).strip().lower()
    return mode if mode in ARCHIVE_MODES else DEFAULT_MODE


def archive_enabled() -> bool:
    return archive_mode() != "off"


def stores_bodies() -> bool:
    return archive_mode() == "full"


def max_body_bytes() -> int:
    raw = os.environ.get("HTTP_ARCHIVE_MAX_BODY_BYTES")
    try:
        value = int(str(raw).strip()) if raw else DEFAULT_MAX_BODY_BYTES
    except (TypeError, ValueError):
        return DEFAULT_MAX_BODY_BYTES
    return max(0, value)


@dataclass(frozen=True)
class HttpTransaction:
    """One request/response pair, with the work that produced it."""

    plane: str
    method: str
    url: str
    sequence: int = 0
    scan_id: str | None = None
    hunt_run_id: str | None = None
    hunt_action_id: str | None = None
    scan_action_id: str | None = None
    target_id: str | None = None
    device_target_id: str | None = None
    capability_name: str | None = None
    adapter: str | None = None
    principal_slot: str | None = None
    http_version: str | None = None
    status_code: int | None = None
    request_headers: Mapping[str, str] | None = None
    request_body: bytes | None = None
    response_headers: Mapping[str, str] | None = None
    response_body: bytes | None = None
    # When the executor retained only a prefix, metadata.response_digest_scope states whether
    # these describe the complete decoded body or only the observed prefix.
    response_body_sha256: str | None = None
    response_body_bytes: int | None = None
    # True when the executor stopped reading before the body ended. Without it the archive
    # measures the prefix it was handed and reports a cut response as complete.
    response_body_truncated: bool = False
    remote_ip: str | None = None
    direct_origin: bool = False
    redirect_of: str | None = None
    started_at: Any = None
    elapsed_ms: int | None = None
    error: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.plane not in {"scan", "hunt", "device", "interactive"}:
            raise ValueError("unsupported archive plane")
        if not str(self.method or "").strip():
            raise ValueError("an archived transaction needs a method")
        if not str(self.url or "").strip():
            raise ValueError("an archived transaction needs a URL")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def capped_body(payload: bytes | None, *, limit: int | None = None) -> dict[str, Any]:
    """Return the stored prefix plus the truth about the whole body.

    The digest and length always describe the complete body, never the prefix. A reader
    comparing a truncated row against a live response must be able to tell them apart, and a
    digest over the prefix would quietly say they matched something they did not.
    """
    if payload is None:
        return {"content": None, "sha256": None, "bytes": 0, "truncated": False}
    ceiling = max_body_bytes() if limit is None else max(0, limit)
    total = len(payload)
    return {
        "content": payload[:ceiling] if ceiling else b"",
        "sha256": _digest(payload),
        "bytes": total,
        "truncated": total > ceiling,
    }


def normalized_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Bounded, lower-cased header map. Values are stored as sent."""
    if not headers:
        return {}
    result: dict[str, str] = {}
    used = 0
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip().lower()
        value = str(raw_value)
        used += len(name) + len(value)
        if not name or used > MAX_HEADER_BYTES:
            break
        result[name] = value
    return result


def transaction_rows(
    transactions: Iterable[HttpTransaction],
    *,
    store_blob,
) -> list[dict[str, Any]]:
    """Project transactions into insertable rows, offloading bodies to the blob store.

    ``store_blob`` takes the content and returns the stored object's descriptor, so this
    stays pure enough to test and the caller decides where bytes land.
    """
    rows: list[dict[str, Any]] = []
    keep_bodies = stores_bodies()
    for item in transactions:
        request_body = capped_body(item.request_body if keep_bodies else None)
        response_body = capped_body(item.response_body if keep_bodies else None)
        if item.response_body_sha256 is not None:
            response_body["sha256"] = item.response_body_sha256
        if item.response_body_bytes is not None:
            response_body["bytes"] = int(item.response_body_bytes)
            response_body["truncated"] = bool(
                item.response_body_truncated
                or int(item.response_body_bytes) > len(item.response_body or b"")
            )
        rows.append({
            "schema_version": ARCHIVE_SCHEMA,
            "plane": item.plane,
            "sequence": int(item.sequence),
            "scan_id": item.scan_id,
            "hunt_run_id": item.hunt_run_id,
            "hunt_action_id": item.hunt_action_id,
            "scan_action_id": item.scan_action_id,
            "target_id": item.target_id,
            "device_target_id": item.device_target_id,
            "capability_name": item.capability_name,
            "adapter": item.adapter,
            "principal_slot": item.principal_slot,
            "method": str(item.method).upper()[:16],
            "url": str(item.url)[:8_000],
            "http_version": item.http_version,
            "status_code": item.status_code,
            "request_headers_object_id": store_blob(
                normalized_headers(item.request_headers)
            ) if item.request_headers else None,
            "request_body_object_id": store_blob(
                request_body["content"]
            ) if request_body["content"] else None,
            "request_body_sha256": request_body["sha256"],
            "request_body_bytes": request_body["bytes"],
            "response_headers_object_id": store_blob(
                normalized_headers(item.response_headers)
            ) if item.response_headers else None,
            "response_body_object_id": store_blob(
                response_body["content"]
            ) if response_body["content"] else None,
            "response_body_sha256": response_body["sha256"],
            "response_body_bytes": response_body["bytes"],
            "remote_ip": item.remote_ip,
            "direct_origin": bool(item.direct_origin),
            "redirect_of": item.redirect_of,
            "started_at": item.started_at,
            "elapsed_ms": item.elapsed_ms,
            "error": str(item.error)[:2_000] if item.error else None,
            "truncated": bool(
                request_body["truncated"]
                or response_body["truncated"]
                or item.response_body_truncated
            ),
            "retention_class": RETENTION_CLASS,
            "metadata_json": json.dumps(dict(item.metadata or {}))[:16_000],
        })
    return rows


__all__ = [
    "ARCHIVE_MODES",
    "ARCHIVE_SCHEMA",
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_MAX_BODY_BYTES",
    "MAX_HEADER_BYTES",
    "RETENTION_CLASS",
    "HttpTransaction",
    "archive_enabled",
    "archive_mode",
    "capped_body",
    "max_body_bytes",
    "normalized_headers",
    "stores_bodies",
    "archive_http_transactions",
    "archive_recorded_calls",
    "archive_scan_capture",
    "har_document",
    "scan_transactions_from_capture",
    "hunt_call_recorder",
    "har_entry",
    "persist_transactions",
    "record_archive_stats",
    "store_archive_blob",
    "transaction_rows",
]


INSERT_SQL = """
INSERT INTO http_transactions (
    plane, sequence, scan_id, hunt_run_id, hunt_action_id, scan_action_id,
    target_id, device_target_id, capability_name, adapter, principal_slot,
    method, url, http_version, status_code,
    request_headers_object_id, request_body_object_id, request_body_sha256, request_body_bytes,
    response_headers_object_id, response_body_object_id, response_body_sha256, response_body_bytes,
    remote_ip, direct_origin, redirect_of, started_at, elapsed_ms, error, truncated,
    retention_class, metadata_json
) SELECT
    r.plane, r.sequence, r.scan_id, r.hunt_run_id, r.hunt_action_id, r.scan_action_id,
    r.target_id, r.device_target_id, r.capability_name, r.adapter, r.principal_slot,
    r.method, r.url, r.http_version, r.status_code,
    r.request_headers_object_id, r.request_body_object_id, r.request_body_sha256, r.request_body_bytes,
    r.response_headers_object_id, r.response_body_object_id, r.response_body_sha256, r.response_body_bytes,
    r.remote_ip, r.direct_origin, r.redirect_of, r.started_at, r.elapsed_ms, r.error, r.truncated,
    r.retention_class, r.metadata_json
FROM jsonb_to_recordset($1::jsonb) AS r(
    plane text, sequence int, scan_id uuid, hunt_run_id uuid, hunt_action_id uuid,
    scan_action_id text, target_id uuid, device_target_id uuid, capability_name text,
    adapter text, principal_slot text, method text, url text, http_version text,
    status_code int, request_headers_object_id uuid, request_body_object_id uuid,
    request_body_sha256 text, request_body_bytes int, response_headers_object_id uuid,
    response_body_object_id uuid, response_body_sha256 text, response_body_bytes int,
    remote_ip text, direct_origin boolean, redirect_of uuid, started_at timestamptz,
    elapsed_ms int, error text, truncated boolean, retention_class text, metadata_json jsonb
)
"""


async def persist_transactions(conn, rows: Sequence[Mapping[str, Any]]) -> int:
    """Insert a batch of archive rows.

    One statement per batch rather than per row: a thorough scan makes tens of thousands of
    calls, and a round trip each would dominate its runtime.
    """
    payload = [dict(row) for row in rows if row]
    if not payload:
        return 0
    for row in payload:
        row.pop("schema_version", None)
        # Left as an object. Serializing it here and then serializing the payload again
        # stored a JSON string containing JSON, so metadata_json->>'fidelity' read null on
        # a row that carried it -- the same double-encode the blob writer had.
        metadata = row.get("metadata_json")
        if isinstance(metadata, str):
            try:
                row["metadata_json"] = json.loads(metadata)
            except json.JSONDecodeError:
                row["metadata_json"] = {"raw": metadata}
        started = row.get("started_at")
        if hasattr(started, "isoformat"):
            row["started_at"] = started.isoformat()
    await conn.execute(INSERT_SQL, json.dumps(payload, default=str))
    return len(payload)


def har_entry(row: Mapping[str, Any], *, request_body: str | None, response_body: str | None) -> dict[str, Any]:
    """Project one archived transaction into a HAR 1.2 entry.

    HAR because every proxy and browser already reads it. The ShakerScan-specific context a
    HAR cannot carry -- capability, action, principal, whether the call went to a confirmed
    origin -- is exported by the transactions format instead.
    """
    def headers(value: Any) -> list[dict[str, str]]:
        if not isinstance(value, Mapping):
            return []
        return [{"name": str(name), "value": str(item)} for name, item in value.items()]

    started = row.get("started_at")
    return {
        "startedDateTime": started.isoformat() if hasattr(started, "isoformat") else started,
        "time": int(row.get("elapsed_ms") or 0),
        "request": {
            "method": str(row.get("method") or "GET"),
            "url": str(row.get("url") or ""),
            "httpVersion": str(row.get("http_version") or "HTTP/1.1"),
            "cookies": [],
            "headers": headers(row.get("request_headers")),
            "queryString": [],
            "headersSize": -1,
            "bodySize": int(row.get("request_body_bytes") or 0),
            **({"postData": {"mimeType": "application/octet-stream", "text": request_body}}
               if request_body is not None else {}),
        },
        "response": {
            "status": int(row.get("status_code") or 0),
            "statusText": "",
            "httpVersion": str(row.get("http_version") or "HTTP/1.1"),
            "cookies": [],
            "headers": headers(row.get("response_headers")),
            "content": {
                "size": int(row.get("response_body_bytes") or 0),
                "mimeType": str((row.get("response_headers") or {}).get("content-type") or ""),
                **({"text": response_body} if response_body is not None else {}),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": int(row.get("response_body_bytes") or 0),
        },
        "cache": {},
        "timings": {"send": 0, "wait": int(row.get("elapsed_ms") or 0), "receive": 0},
        "serverIPAddress": row.get("remote_ip"),
        # Truncation is stated on the entry, so a reader never mistakes a stored prefix for
        # the whole body when comparing against a live response.
        "comment": "truncated" if row.get("truncated") else "",
    }


def har_document(entries: Sequence[Mapping[str, Any]], *, creator_version: str) -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "ShakerScan", "version": str(creator_version)},
            "entries": list(entries),
        }
    }


async def store_archive_blob(conn, content: Any, *, scan_id: str | None, store) -> str | None:
    """Put one header map or body in the content-addressed store and return its object id.

    Reuses the evidence object plane rather than adding a second blob table, so identical
    payloads across thousands of calls collapse to one stored object and the existing
    retention sweep can reach them.
    """
    if content is None:
        return None
    if isinstance(content, (bytes, bytearray)):
        content = bytes(content).decode("utf-8", errors="replace")
    stored = store(content)
    if not stored.get("content_sha256"):
        return None
    row = await conn.fetchrow(
        """INSERT INTO evidence_objects (
               scan_id, object_type, content_sha256, size_bytes, storage_uri,
               redaction_profile, retention_class, content
           ) VALUES ($1,'http_archive_blob',$2,$3,$4,'none',$5,$6)
           RETURNING id""",
        scan_id, stored.get("content_sha256"), stored.get("size_bytes"),
        stored.get("storage_uri"), RETENTION_CLASS,
        # store_evidence_content already returns serialized JSON, so this goes into the
        # JSONB column as-is. Encoding it again stored a JSON string containing JSON, and
        # a reader decoding once got the text back rather than the headers.
        stored.get("content"),
    )
    return str(row["id"]) if row else None


async def archive_http_transactions(
    conn,
    transactions: Sequence[HttpTransaction],
    *,
    store,
    scan_id: str | None = None,
) -> int:
    """Store a run's captured calls. Never raises into the caller's execution path."""
    if not archive_enabled() or not transactions:
        return 0
    blobs: dict[int, str | None] = {}

    async def _prepare() -> list[Mapping[str, Any]]:
        pending: list[dict[str, Any]] = []
        for item in transactions:
            body = capped_body(item.request_body if stores_bodies() else None)
            response = capped_body(item.response_body if stores_bodies() else None)
            if item.response_body_sha256 is not None:
                response["sha256"] = item.response_body_sha256
            if item.response_body_bytes is not None:
                response["bytes"] = int(item.response_body_bytes)
                response["truncated"] = bool(
                    item.response_body_truncated
                    or int(item.response_body_bytes) > len(item.response_body or b"")
                )
            owner_scan_id = item.scan_id or scan_id
            pending.append({
                "item": item,
                "request_headers": await store_archive_blob(
                    conn, normalized_headers(item.request_headers),
                    scan_id=owner_scan_id, store=store,
                ) if item.request_headers else None,
                "request_body": await store_archive_blob(
                    conn, body["content"], scan_id=owner_scan_id, store=store,
                ) if body["content"] else None,
                "response_headers": await store_archive_blob(
                    conn, normalized_headers(item.response_headers),
                    scan_id=owner_scan_id, store=store,
                ) if item.response_headers else None,
                "response_body": await store_archive_blob(
                    conn, response["content"], scan_id=owner_scan_id, store=store,
                ) if response["content"] else None,
                "request_meta": body,
                "response_meta": response,
            })
        return pending

    prepared = await _prepare()
    rows = []
    for entry in prepared:
        item = entry["item"]
        rows.append({
            "plane": item.plane, "sequence": int(item.sequence),
            "scan_id": item.scan_id, "hunt_run_id": item.hunt_run_id,
            "hunt_action_id": item.hunt_action_id, "scan_action_id": item.scan_action_id,
            "target_id": item.target_id, "device_target_id": item.device_target_id,
            "capability_name": item.capability_name, "adapter": item.adapter,
            "principal_slot": item.principal_slot,
            "method": str(item.method).upper()[:16], "url": str(item.url)[:8_000],
            "http_version": item.http_version, "status_code": item.status_code,
            "request_headers_object_id": entry["request_headers"],
            "request_body_object_id": entry["request_body"],
            "request_body_sha256": entry["request_meta"]["sha256"],
            "request_body_bytes": entry["request_meta"]["bytes"],
            "response_headers_object_id": entry["response_headers"],
            "response_body_object_id": entry["response_body"],
            "response_body_sha256": entry["response_meta"]["sha256"],
            "response_body_bytes": entry["response_meta"]["bytes"],
            "remote_ip": item.remote_ip, "direct_origin": bool(item.direct_origin),
            "redirect_of": item.redirect_of, "started_at": item.started_at,
            "elapsed_ms": item.elapsed_ms, "error": item.error,
            "truncated": bool(
                entry["request_meta"]["truncated"]
                or entry["response_meta"]["truncated"]
                or item.response_body_truncated
            ),
            "retention_class": RETENTION_CLASS,
            "metadata_json": dict(item.metadata or {}),
        })
    return await persist_transactions(conn, rows)


def hunt_call_recorder(
    *,
    hunt_run_id: str,
    hunt_action_id: str,
    capability_name: str,
    adapter: str,
    target_url: str,
    target_id: str | None = None,
    device_target_id: str | None = None,
    now=None,
) -> tuple[list[HttpTransaction], Any]:
    """Return the collected list and the callback that fills it.

    Built here rather than at each call site so every plane records the same fields and a
    new caller cannot quietly omit one.
    """
    from datetime import datetime, timezone

    collected: list[HttpTransaction] = []
    clock = now or (lambda: datetime.now(timezone.utc))

    def record(captured: Mapping[str, Any]) -> None:
        collected.append(HttpTransaction(
            plane="hunt",
            sequence=len(collected),
            hunt_run_id=hunt_run_id,
            hunt_action_id=hunt_action_id,
            target_id=target_id,
            device_target_id=device_target_id,
            capability_name=capability_name,
            adapter=adapter,
            principal_slot=captured.get("principal_slot"),
            method=captured.get("method") or "GET",
            url=captured.get("url") or target_url,
            http_version=captured.get("http_version"),
            status_code=captured.get("status_code"),
            request_headers=captured.get("request_headers"),
            request_body=captured.get("request_body"),
            response_headers=captured.get("response_headers"),
            response_body=captured.get("response_body"),
            response_body_sha256=captured.get("response_body_sha256"),
            response_body_bytes=captured.get("response_body_bytes"),
            remote_ip=captured.get("remote_ip"),
            direct_origin=bool(captured.get("direct_origin")),
            elapsed_ms=captured.get("elapsed_ms"),
            error=captured.get("error"),
            response_body_truncated=bool(captured.get("response_body_truncated")),
            started_at=captured.get("started_at") or clock(),
            metadata={
                "fidelity": captured.get("fidelity") or "wire_request",
                "response_digest_scope": captured.get("response_digest_scope"),
            },
        ))

    return collected, record


def hunt_run_call_recorder(
    run: Mapping[str, Any],
    *,
    action_id: Any,
    capability_name: str,
    adapter: str,
    target_url: str,
) -> tuple[list[HttpTransaction], Any]:
    """Build a recorder from the canonical Hunt row without duplicating owner wiring."""
    return hunt_call_recorder(
        hunt_run_id=str(run["id"]),
        hunt_action_id=str(action_id),
        capability_name=capability_name,
        adapter=adapter,
        target_url=target_url,
        target_id=str(run["target_id"]) if run.get("target_id") else None,
        device_target_id=(
            str(run["device_target_id"]) if run.get("device_target_id") else None
        ),
    )


def _default_store(results_dir):
    """The blob writer every plane uses. Built here so a caller does not have to know the
    evidence store's signature just to archive a call."""
    try:
        from evidence_storage import store_evidence_content
    except ModuleNotFoundError:  # package import layout
        from ..evidence_storage import store_evidence_content
    return lambda content: store_evidence_content(content, results_dir=results_dir)


async def archive_scan_capture(
    conn,
    captured: Mapping[str, Any],
    *,
    scan_id: str,
    target_id: Any,
    results_dir,
) -> None:
    """Project and persist one scan's captured calls in a single step."""
    await archive_recorded_calls(
        conn,
        scan_transactions_from_capture(captured, scan_id=scan_id, target_id=target_id),
        results_dir=results_dir,
        label=f"scan {scan_id}",
        owner_kind="scan",
        owner_id=scan_id,
        dropped=int(captured.get("dropped") or 0),
    )


async def drain_and_archive_scan_capture(
    pool,
    capture,
    *,
    scan_id: str,
    target_id: Any,
    results_dir,
) -> None:
    """Drain process-local scanner traffic and persist it without deciding scan success."""
    captured = capture.drain_capture()
    try:
        async with pool.acquire() as conn:
            await archive_scan_capture(
                conn, captured, scan_id=scan_id, target_id=target_id,
                results_dir=results_dir,
            )
    except Exception as exc:  # archive never decides scan success
        print(
            f"[http-archive] scan {scan_id}: capture not archived: {type(exc).__name__}",
            flush=True,
        )


def start_scan_capture(capture, broker_result: Any) -> bool:
    """Start process-local capture only for work executing in this process."""
    if broker_result:
        return False
    capture.start_capture()
    return True


def reset_scan_capture(capture, active: bool) -> None:
    """Clear an interrupted ContextVar capture before this process accepts more work."""
    if active:
        capture.drain_capture()


async def record_archive_stats(
    conn,
    *,
    owner_kind: str,
    owner_id: str,
    attempted: int,
    stored: int,
    failed: int,
    dropped: int,
) -> None:
    """Accumulate what the archive attempted against what it holds.

    Capture and persistence failures are swallowed so they cannot fail a scan, which means
    the row count alone cannot answer "is this the whole run". Without these counts an
    export would call one surviving transaction complete.
    """
    try:
        await conn.execute(
            """INSERT INTO http_archive_stats (
                   owner_kind, owner_id, attempted, stored, failed, dropped
               ) VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (owner_kind, owner_id) DO UPDATE SET
                   attempted = http_archive_stats.attempted + EXCLUDED.attempted,
                   stored = http_archive_stats.stored + EXCLUDED.stored,
                   failed = http_archive_stats.failed + EXCLUDED.failed,
                   dropped = GREATEST(http_archive_stats.dropped, EXCLUDED.dropped),
                   updated_at = NOW()""",
            owner_kind, owner_id, int(attempted), int(stored), int(failed), int(dropped),
        )
    except Exception as exc:  # pragma: no cover - stats must not fail the work either
        print(
            f"[http-archive] {owner_kind} {owner_id}: stats not recorded: "
            f"{type(exc).__name__}",
            flush=True,
        )


async def archive_recorded_calls(
    conn,
    collected: Sequence[HttpTransaction],
    *,
    results_dir,
    label: str,
    owner_kind: str | None = None,
    owner_id: str | None = None,
    dropped: int = 0,
) -> None:
    """Persist a run's calls, reporting a failure rather than raising into execution.

    A scan or hunt that dies because its own archive failed is worse than one whose archive
    has a hole. The hole is then visible in the stats rather than left to be inferred.
    """
    attempted = len(collected)
    stored = 0
    if collected:
        try:
            stored = await archive_http_transactions(
                conn, collected, store=_default_store(results_dir),
            ) or 0
        except Exception as exc:  # pragma: no cover - archiving must not fail the work
            print(
                f"[http-archive] {label}: calls not archived: {type(exc).__name__}: {exc}",
                flush=True,
            )
    if owner_kind and owner_id and (attempted or dropped):
        await record_archive_stats(
            conn, owner_kind=owner_kind, owner_id=owner_id,
            attempted=attempted, stored=stored,
            failed=max(0, attempted - stored), dropped=dropped,
        )


async def archive_hunt_capture(conn, collected, hunt_id, run_id, results_dir) -> None:
    """Persist one Hunt action's traffic outside its budget-settlement transaction."""
    await archive_recorded_calls(
        conn, collected, label=f"hunt {hunt_id}", results_dir=results_dir,
        owner_kind="hunt", owner_id=str(run_id),
    )


def _as_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return str(value).encode("utf-8", errors="replace")


def scan_transactions_from_capture(
    captured: Mapping[str, Any],
    *,
    scan_id: str,
    target_id: Any = None,
    now=None,
) -> list[HttpTransaction]:
    """Project a scanner-side capture into archive transactions.

    Fidelity differs by plane and travels with each row. curl exposes its argv and stdout
    but no response headers unless the caller dumped them, so a curl row is a partial
    record and says so; letting it look like a complete one would misrepresent the scan.
    """
    from datetime import datetime, timezone

    clock = now or (lambda: datetime.now(timezone.utc))
    calls = captured.get("calls") or []
    dropped = int(captured.get("dropped") or 0)
    transactions: list[HttpTransaction] = []
    for index, call in enumerate(calls):
        if not call.get("url"):
            continue
        transactions.append(HttpTransaction(
            plane="scan",
            sequence=index,
            scan_id=scan_id,
            target_id=str(target_id) if target_id else None,
            capability_name=str(call.get("source") or "scanner"),
            adapter=str(call.get("source") or "scanner"),
            method=call.get("method") or "GET",
            url=call.get("url"),
            status_code=call.get("status_code"),
            request_headers=call.get("request_headers") or None,
            request_body=_as_bytes(call.get("request_body")),
            response_headers=call.get("response_headers") or None,
            response_body=_as_bytes(call.get("response_body")),
            response_body_sha256=call.get("response_body_sha256"),
            response_body_bytes=call.get("response_body_bytes"),
            http_version=call.get("http_version"),
            principal_slot=call.get("principal_slot"),
            remote_ip=call.get("remote_ip"),
            direct_origin=bool(call.get("direct_origin")),
            elapsed_ms=call.get("elapsed_ms"),
            error=call.get("error"),
            response_body_truncated=bool(call.get("response_body_truncated")),
            started_at=call.get("started_at") or clock(),
            metadata={
                "fidelity": call.get("fidelity"),
                "response_digest_scope": call.get("response_digest_scope"),
                "redacted_argv": call.get("redacted_argv"),
                # Stated on every row so a bounded archive is never mistaken for the
                # complete traffic of the run.
                "dropped_calls": dropped,
            },
        ))
    return transactions
