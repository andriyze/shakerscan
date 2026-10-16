"""Browser-capture persistence: create, append a batch, close, and close idle captures.

A capture is one ``request_collections`` row (``format = 'capture'``) with its encrypted HAR
document, its redacted ``request_collection_requests`` index and one exact-origin binding to the
target it was created for. Its bookkeeping (open/closed, the last applied batch ``seq``, counts)
lives in ``metadata_json.capture``, so a capture needs no table or column of its own.

Every batch is applied under the collection row's lock: the server re-checks each flow's origin
against the binding, appends the in-scope flows to the document, re-encrypts it and indexes the
new rows. ``seq`` makes a retry idempotent: a batch whose ``seq`` was already applied is
acknowledged without change, and only the next ``seq`` is applied.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Mapping
import urllib.parse
import uuid

from fastapi import HTTPException

from .flows import (
    CAPTURE_FORMAT,
    CAPTURE_SCHEMA,
    IDLE_CLOSE_SECONDS,
    MAX_CAPTURE_FLOWS,
    MAX_DOCUMENT_BYTES,
    CaptureBatch,
    CaptureCreate,
    CaptureDropCounts,
    capture_limits,
    empty_capture_document,
    flow_origin,
    flow_tags,
    har_entry,
    in_scope,
    new_capture_state,
    public_capture_state,
)

try:
    from runtime.request_collection_store import canonical_collection_origin
    from secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret
    from targets.asset_collections import asset_collection_binding
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.request_collection_store import canonical_collection_origin
    from ..secret_store import SecretStoreUnavailable, decrypt_secret, encrypt_secret
    from ..targets.asset_collections import asset_collection_binding

try:
    from scanner_tools.request_collections import index_appended_har_entries
except ModuleNotFoundError:
    from scanner.scanner_tools.request_collections import index_appended_har_entries


IDLE_CLOSE_BATCH = 100
# Past the document cap a flow is kept as metadata only; these bytes over the cap hold up to the
# 20,000-request cap of such entries (method, URL, status, masked headers).
METADATA_HEADROOM_BYTES = 25 * 1024 * 1024


def _conflict(error: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=409, detail={"error": error, "message": message, **extra})


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _encrypt(value: Any) -> str:
    encrypted = encrypt_secret(json.dumps(value, separators=(",", ":"), ensure_ascii=False))
    if not str(encrypted or "").startswith("enc:fernet:"):
        raise HTTPException(
            status_code=503, detail="Encrypted request-collection document storage is unavailable",
        )
    return str(encrypted)


def _decrypt(value: Any) -> dict[str, Any]:
    try:
        raw = decrypt_secret(value)
    except SecretStoreUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="Encrypted request-collection document storage is unavailable",
        ) from exc
    if not isinstance(raw, str) or raw.startswith("enc:fernet:"):
        raise HTTPException(status_code=503, detail="The capture document could not be decrypted")
    payload = json.loads(raw)
    entries = (((payload or {}).get("document") or {}).get("log") or {}).get("entries")
    if payload.get("format") != "har" or not isinstance(entries, list):
        raise HTTPException(status_code=409, detail="The capture document is not a HAR log")
    return payload


def public_collection(row: Mapping[str, Any]) -> dict[str, Any]:
    """The collection row as every collection route shows it, plus its capture block."""
    item: dict[str, Any] = {}
    for key, value in dict(row).items():
        if key == "encrypted_payload":
            continue
        if isinstance(value, uuid.UUID):
            value = str(value)
        elif isinstance(value, datetime):
            value = value.isoformat()
        item[key] = value
    item["metadata_json"] = _json_object(item.get("metadata_json"))
    item["capture"] = public_capture_state(item["metadata_json"])
    item["storage_encrypted"] = True
    item["secret_values_visible"] = False
    return item


async def _resolve_target(conn: Any, request: CaptureCreate) -> Mapping[str, Any]:
    """The one active web target a capture is for: by id, or by a URL whose origin names it."""
    if request.target_id:
        try:
            target_uuid = uuid.UUID(str(request.target_id))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid target id") from exc
        row = await conn.fetchrow(
            "SELECT id, url, name FROM targets WHERE id=$1 AND is_active=true", target_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Active target not found")
        return row
    origin = flow_origin(str(request.target_url or ""))
    if origin is None:
        raise HTTPException(status_code=422, detail="target_url must be an absolute http(s) URL")
    parsed = urllib.parse.urlsplit(origin)
    # A bounded prefix lookup, then the exact canonical origin in Python (default ports, case).
    rows = await conn.fetch(
        """SELECT id, url, name FROM targets
           WHERE is_active=true AND lower(url) LIKE $1
           ORDER BY created_at, id LIMIT 50""",
        f"{parsed.scheme}://{parsed.hostname}%",
    )
    matches = [row for row in rows if flow_origin(str(row["url"] or "")) == origin]
    if not matches:
        raise HTTPException(status_code=404, detail=f"No active target has the origin {origin}")
    if len(matches) > 1:
        raise _conflict(
            "ambiguous_target", f"{len(matches)} targets have the origin {origin}; name one by id",
            candidates=[{"id": str(row["id"]), "name": row["name"], "url": row["url"]} for row in matches[:5]],
        )
    return matches[0]


async def create_capture(conn: Any, request: CaptureCreate, *, created_by: str) -> dict[str, Any]:
    target = await _resolve_target(conn, request)
    parsed = urllib.parse.urlsplit(str(target["url"] or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="A browser capture needs a web target with an http(s) URL")
    origin = canonical_collection_origin(f"{parsed.scheme}://{parsed.netloc.rsplit('@', 1)[-1]}")
    now = await conn.fetchval("SELECT NOW()")
    name = (request.name or "").strip() or f"Browser capture {now.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S} UTC"
    payload = empty_capture_document()
    async with conn.transaction():
        if await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM request_collections WHERE target_id=$1 AND name=$2)",
            target["id"], name,
        ):
            raise _conflict("name_in_use", "This target already has a collection with that name")
        state = new_capture_state(allowed_origins=[origin], opened_at=_iso(now))
        state["created_by"] = created_by
        metadata = {
            "schema_version": "request-collection/v2",
            "format": CAPTURE_FORMAT,
            "name": name,
            "secrets_redacted": True,
            "capture": state,
        }
        row = await conn.fetchrow(
            """INSERT INTO request_collections (
                   target_id, name, format, encrypted_payload, payload_sha256, request_count,
                   safe_request_count, potentially_mutating_request_count, metadata_json
               ) VALUES ($1,$2,$3,$4,$5,0,0,0,$6)
               RETURNING *""",
            target["id"], name, CAPTURE_FORMAT, _encrypt(payload), _digest(payload),
            json.dumps(metadata),
        )
        origins = await asset_collection_binding(
            conn, dict(row), target_kind="web", target_id=target["id"], allowed_origins=[origin],
        )
        binding = await conn.fetchrow(
            """INSERT INTO request_collection_bindings (
                   collection_id, target_kind, target_id, allowed_origins
               ) VALUES ($1,'web',$2,$3)
               RETURNING id, allowed_origins""",
            row["id"], target["id"], json.dumps(list(origins)),
        )
    collection = public_collection(row)
    return {
        "id": collection["id"],
        "name": name,
        "target_id": str(target["id"]),
        "target_url": str(target["url"]),
        "binding_id": str(binding["id"]),
        "allowed_origins": list(origins),
        "limits": capture_limits(),
        "state": "open",
        "capture": collection["capture"],
        "collection": collection,
        "secret_values_visible": False,
    }


def _merge_drops(state: dict[str, Any], drops: CaptureDropCounts | None) -> None:
    if drops is None:
        return
    current = dict(state.get("client_dropped") or {})
    state["client_dropped"] = {
        "out_of_scope": max(int(current.get("out_of_scope") or 0), drops.out_of_scope),
        "assets": max(int(current.get("assets") or 0), drops.assets),
    }


async def _locked_capture(conn: Any, collection_id: uuid.UUID) -> tuple[Mapping[str, Any], dict[str, Any], dict[str, Any]]:
    row = await conn.fetchrow(
        """SELECT *, NOW() AS db_now FROM request_collections
           WHERE id=$1 AND is_active=true FOR UPDATE""",
        collection_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Request collection not found")
    metadata = _json_object(row["metadata_json"])
    state = metadata.get("capture")
    if row["format"] != CAPTURE_FORMAT or not isinstance(state, dict) or state.get("schema") != CAPTURE_SCHEMA:
        raise HTTPException(status_code=422, detail={
            "error": "not_a_capture", "message": "This request collection is not a browser capture",
        })
    return row, metadata, state


def _idle(row: Mapping[str, Any]) -> bool:
    return row["db_now"] - row["updated_at"] > timedelta(seconds=IDLE_CLOSE_SECONDS)


def _closed(state: Mapping[str, Any]) -> HTTPException:
    return _conflict(
        "capture_closed", "This capture is closed and accepts no more batches",
        closed_reason=state.get("closed_reason"), last_seq=int(state.get("last_seq") or 0),
    )


def _ack(collection_id: uuid.UUID, state: Mapping[str, Any], *, seq: int, status: str,
         applied: Mapping[str, int] | None = None) -> dict[str, Any]:
    applied = applied or {}
    return {
        "id": str(collection_id),
        "seq": seq,
        "status": status,
        "accepted": int(applied.get("accepted", 0)),
        "refused_out_of_scope": int(applied.get("refused_out_of_scope", 0)),
        "refused_over_limit": int(applied.get("refused_over_limit", 0)),
        "bodies_dropped": int(applied.get("bodies_dropped", 0)),
        "first_flow_seq": applied.get("first_flow_seq"),
        "last_flow_seq": applied.get("last_flow_seq"),
        "capture": public_capture_state({"capture": state}),
        "secret_values_visible": False,
    }


async def apply_batch(conn: Any, collection_id: uuid.UUID, batch: CaptureBatch) -> dict[str, Any]:
    idle_closed: dict[str, Any] | None = None
    async with conn.transaction():
        row, metadata, state = await _locked_capture(conn, collection_id)
        last_seq = int(state.get("last_seq") or 0)
        if batch.seq <= last_seq:
            # A retry of a batch that was applied: acknowledge it, change nothing.
            return _ack(collection_id, state, seq=batch.seq, status="duplicate")
        if state.get("state") != "open":
            raise _closed(state)
        if _idle(row):
            state.update(state="closed", closed_reason="idle", closed_at=_iso(row["db_now"]))
            await conn.execute(
                "UPDATE request_collections SET metadata_json=$2, updated_at=NOW() WHERE id=$1",
                collection_id, json.dumps(metadata),
            )
            idle_closed = state
        elif batch.seq != last_seq + 1:
            raise _conflict(
                "capture_seq_gap", f"The next batch of this capture is seq {last_seq + 1}",
                expected_seq=last_seq + 1, last_seq=last_seq,
            )
        else:
            applied = await _append(conn, row, metadata, state, batch)
            return _ack(collection_id, state, seq=batch.seq, status="applied", applied=applied)
    raise _closed(idle_closed or state)


async def _append(conn: Any, row: Mapping[str, Any], metadata: dict[str, Any],
                  state: dict[str, Any], batch: CaptureBatch) -> dict[str, int]:
    binding_origins: set[str] = set()
    for binding in await conn.fetch(
        """SELECT allowed_origins FROM request_collection_bindings
           WHERE collection_id=$1 AND target_id=$2 AND is_active=true""",
        row["id"], row["target_id"],
    ):
        binding_origins.update(str(item) for item in (_json_list(binding["allowed_origins"])))
    if not binding_origins:
        raise _conflict("capture_unbound", "This capture has no active binding to its target")
    payload: dict[str, Any] | None = None
    entries: list[Any] = []
    flow_count = int(state.get("flow_count") or 0)
    document_bytes = int(state.get("document_bytes") or 0)
    accepted: list[dict[str, Any]] = []
    tags: list[list[str]] = []
    refused_scope = refused_limit = bodies_dropped = 0
    origins = sorted(binding_origins)
    for flow in batch.flows:
        # The recorder filters too, but scope is decided here, for every flow.
        if not in_scope(flow.url, origins):
            refused_scope += 1
            continue
        if flow_count + len(accepted) >= MAX_CAPTURE_FLOWS:
            refused_limit += 1
            continue
        entry, size = har_entry(flow)
        if document_bytes + size > MAX_DOCUMENT_BYTES:
            # The document is full: keep the request as metadata (no bodies, credential header
            # values withheld) so its endpoint still counts, up to the request cap.
            entry, size = har_entry(flow, metadata_only=True)
            bodies_dropped += 1
            if document_bytes + size > MAX_DOCUMENT_BYTES + METADATA_HEADROOM_BYTES:
                refused_limit += 1
                continue
        accepted.append(entry)
        tags.append(flow_tags(flow))
        document_bytes += size
    first = last = None
    columns = ""
    values: list[Any] = []
    if accepted:
        payload = _decrypt(row["encrypted_payload"])
        entries = payload["document"]["log"]["entries"]
        start = len(entries)
        entries.extend(accepted)
        index = index_appended_har_entries(accepted, start_index=start, tags=tags)
        await conn.executemany(
            """INSERT INTO request_collection_requests (
                   collection_id, request_id, ordinal, folder, name, method, redacted_url,
                   normalized_path, body_mode, auth_type, tags_json, content_type,
                   body_field_names_json, safe_method, supported
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""",
            [(
                row["id"], item["request_id"], item["ordinal"], item.get("folder"), item.get("name"),
                item["method"], item.get("redacted_url"), item.get("normalized_path"),
                item.get("body_mode"), item.get("auth_type"), json.dumps(item.get("tags") or []),
                item.get("content_type"), json.dumps(item.get("body_field_names") or []),
                bool(item.get("safe_method")), bool(item.get("supported", True)),
            ) for item in index],
        )
        flow_count = len(entries)
        first, last = start + 1, flow_count
        safe = sum(1 for item in index if item.get("safe_method"))
        state["endpoint_count"] = int(await conn.fetchval(
            """SELECT count(DISTINCT (method, normalized_path)) FROM request_collection_requests
               WHERE collection_id=$1""",
            row["id"],
        ) or 0)
        # A changed document retires the selections saved over the previous one, exactly as a
        # re-imported collection does; Scan and Hunt bind selections to the document digest.
        await conn.execute(
            """UPDATE request_collection_selections SET is_active=false, updated_at=NOW()
               WHERE collection_id=$1 AND is_active=true""",
            row["id"],
        )
        columns = (", encrypted_payload=$3, payload_sha256=$4, request_count=$5, "
                   "safe_request_count=safe_request_count+$6, "
                   "potentially_mutating_request_count=potentially_mutating_request_count+$7")
        values = [_encrypt(payload), _digest(payload), flow_count, safe, len(index) - safe]
    state.update(
        last_seq=batch.seq,
        flow_count=flow_count,
        document_bytes=document_bytes,
        refused_out_of_scope=int(state.get("refused_out_of_scope") or 0) + refused_scope,
        refused_over_limit=int(state.get("refused_over_limit") or 0) + refused_limit,
        bodies_dropped=int(state.get("bodies_dropped") or 0) + bodies_dropped,
        last_batch_at=_iso(row["db_now"]),
    )
    if refused_limit:
        state["limit_reached"] = True
    _merge_drops(state, batch.client_dropped)
    await conn.execute(
        f"UPDATE request_collections SET metadata_json=$2, updated_at=NOW(){columns} WHERE id=$1",
        row["id"], json.dumps(metadata), *values,
    )
    return {
        "accepted": len(accepted), "refused_out_of_scope": refused_scope,
        "refused_over_limit": refused_limit, "bodies_dropped": bodies_dropped,
        "first_flow_seq": first, "last_flow_seq": last,
    }


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return list(value) if isinstance(value, list) else []


async def close_capture(conn: Any, collection_id: uuid.UUID, drops: CaptureDropCounts | None) -> dict[str, Any]:
    async with conn.transaction():
        row, metadata, state = await _locked_capture(conn, collection_id)
        if state.get("state") == "closed":
            status = "already_closed"
        else:
            status = "closed"
            state.update(state="closed", closed_reason="client", closed_at=_iso(row["db_now"]))
            _merge_drops(state, drops)
            row = await conn.fetchrow(
                """UPDATE request_collections SET metadata_json=$2, updated_at=NOW()
                   WHERE id=$1 RETURNING *""",
                collection_id, json.dumps(metadata),
            )
    collection = public_collection(row)
    return {
        "id": str(collection_id), "status": status, "state": "closed",
        "capture": collection["capture"], "collection": collection, "secret_values_visible": False,
    }


async def close_idle_captures(pool: Any, *, idle_seconds: int = IDLE_CLOSE_SECONDS,
                              limit: int = IDLE_CLOSE_BATCH) -> int:
    """Close open captures with no batch for ``idle_seconds`` (a recorder that crashed or lost
    its network), at most ``limit`` per call; rows another transaction holds are left for the
    next tick. Safe to run twice: it only ever moves an open capture to closed. A failure is
    reported and skipped so the rest of the maintenance tick still runs."""
    try:
        return await _close_idle(pool, idle_seconds=idle_seconds, limit=limit)
    except Exception as exc:  # noqa: BLE001 - maintenance must not stop the tick
        print(f"[capture] idle close failed: {type(exc).__name__}", flush=True)
        return 0


async def _close_idle(pool: Any, *, idle_seconds: int, limit: int) -> int:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """WITH idle AS (
                   SELECT id FROM request_collections
                   WHERE is_active=true AND format='capture'
                     AND metadata_json->'capture'->>'state'='open'
                     AND updated_at < NOW() - make_interval(secs => $1)
                   ORDER BY updated_at LIMIT $2
                   FOR UPDATE SKIP LOCKED
               )
               UPDATE request_collections c
               SET metadata_json = jsonb_set(c.metadata_json, '{capture}',
                       (c.metadata_json->'capture') || jsonb_build_object(
                           'state', 'closed', 'closed_reason', 'idle',
                           'closed_at', to_char(NOW() AT TIME ZONE 'UTC',
                                                'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'))),
                   updated_at = NOW()
               FROM idle WHERE c.id = idle.id
               RETURNING c.id""",
            float(idle_seconds), int(limit),
        )
    return len(rows)


__all__ = [
    "apply_batch",
    "close_capture",
    "close_idle_captures",
    "create_capture",
    "public_collection",
]
