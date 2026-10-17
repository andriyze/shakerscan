"""Browser-capture persistence: create, append a batch, close, and close idle captures.

A capture is one ``request_collections`` row (``format = 'capture'``) with its encrypted
document, its redacted ``request_collection_requests`` index and one exact-origin binding to the
target it was created for. Its bookkeeping (open/closed, the last applied batch ``seq``, counts,
who opened it) lives in ``metadata_json.capture``.

Batches are stored append-only: each applied batch is one ``request_collection_capture_batches``
row holding that batch's HAR entries, encrypted on their own, and the digest of what was sent. A
batch never decrypts or rewrites what came before it. Closing the capture (the recorder, or the
idle close) assembles the batches into the collection's encrypted document once; until then the
document is empty and the capture cannot be selected for a Scan or Hunt (``refuse_open_capture``),
so every consumer reads a complete, final document exactly as it reads an imported HAR.

``seq`` makes a retry idempotent: a batch whose ``seq`` was applied with the same content is
acknowledged without change, the same ``seq`` with other content is refused, and only the next
``seq`` is applied. Encryption and JSON work runs in a worker thread, off the event loop.
"""

from __future__ import annotations

import asyncio
import weakref
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
    LOCAL_OPERATOR,
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
    stored_size,
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


def _canonical(value: Any) -> str:
    """The JSON text the digest is computed over (and every stored capture text uses)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _encrypt(value: Any) -> str:
    return _encrypt_text(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def _encrypt_text(text: str) -> str:
    encrypted = encrypt_secret(text)
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
    if payload.get("format") != CAPTURE_FORMAT or not isinstance(entries, list):
        raise HTTPException(status_code=409, detail="The capture document is not a capture HAR log")
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


_TARGET_MATCH_LIMIT = 50


def _like_prefix(value: str) -> str:
    """``value`` as a literal LIKE prefix: ``%``, ``_`` and the escape character match only
    themselves (the query says ``ESCAPE '\\'``)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


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
    # A bounded literal prefix lookup, then the exact canonical origin in Python (default ports,
    # case). One row past the bound says the lookup was cut short, which is refused, never guessed.
    rows = await conn.fetch(
        """SELECT id, url, name FROM targets
           WHERE is_active=true AND lower(url) LIKE $1 ESCAPE '\\'
           ORDER BY created_at, id LIMIT $2""",
        _like_prefix(f"{parsed.scheme}://{parsed.hostname}"), _TARGET_MATCH_LIMIT + 1,
    )
    if len(rows) > _TARGET_MATCH_LIMIT:
        raise _conflict(
            "ambiguous_target",
            f"More than {_TARGET_MATCH_LIMIT} targets start with {parsed.scheme}://{parsed.hostname}; "
            "name the target by id",
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
    encrypted = await asyncio.to_thread(_encrypt, payload)
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
            target["id"], name, CAPTURE_FORMAT, encrypted, _digest(payload),
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


def _require_owner(state: Mapping[str, Any], actor: str) -> None:
    """Only the operator who opened a capture adds to it or closes it. Without a gateway identity
    (the open-source engine) every request is ``local-operator``, so this always holds there."""
    owner = str(state.get("created_by") or LOCAL_OPERATOR)
    if owner != LOCAL_OPERATOR and actor != owner:
        raise HTTPException(status_code=403, detail={
            "error": "capture_owner_mismatch",
            "message": "Only the operator who opened this capture can add to it or close it",
        })


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


async def apply_batch(conn: Any, collection_id: uuid.UUID, batch: CaptureBatch, *,
                      actor: str = LOCAL_OPERATOR) -> dict[str, Any]:
    digest = await asyncio.to_thread(batch.digest)
    async with conn.transaction():
        row, metadata, state = await _locked_capture(conn, collection_id)
        _require_owner(state, actor)
        last_seq = int(state.get("last_seq") or 0)
        if batch.seq <= last_seq:
            stored = await conn.fetchval(
                """SELECT batch_sha256 FROM request_collection_capture_batches
                   WHERE collection_id=$1 AND seq=$2""",
                collection_id, batch.seq,
            )
            if stored is not None and str(stored) != digest:
                raise _conflict(
                    "capture_seq_conflict",
                    f"Batch seq {batch.seq} was already applied with different flows",
                    seq=batch.seq, last_seq=last_seq,
                )
            # A retry of a batch that was applied: acknowledge it, change nothing.
            return _ack(collection_id, state, seq=batch.seq, status="duplicate")
        if state.get("state") != "open":
            raise _closed(state)
        if not _idle(row):
            if batch.seq != last_seq + 1:
                raise _conflict(
                    "capture_seq_gap", f"The next batch of this capture is seq {last_seq + 1}",
                    expected_seq=last_seq + 1, last_seq=last_seq,
                )
            applied = await _append(conn, row, metadata, state, batch, digest)
            return _ack(collection_id, state, seq=batch.seq, status="applied", applied=applied)
        # Idle past the limit: the batch is late; the capture closes as the idle close would.
        await _finalize(conn, row, metadata, state, reason="idle")
    raise _closed(state)


async def _binding_origins(conn: Any, row: Mapping[str, Any]) -> list[str]:
    origins: set[str] = set()
    for binding in await conn.fetch(
        """SELECT allowed_origins FROM request_collection_bindings
           WHERE collection_id=$1 AND target_id=$2 AND is_active=true""",
        row["id"], row["target_id"],
    ):
        origins.update(str(item) for item in _json_list(binding["allowed_origins"]))
    if not origins:
        raise _conflict("capture_unbound", "This capture has no active binding to its target")
    return sorted(origins)


def _build_entries(batch: CaptureBatch, origins: list[str], *, flow_count: int,
                   document_bytes: int) -> dict[str, Any]:
    """The batch's in-scope flows as stored HAR entries, sized in stored bytes (pure, CPU work:
    run in a thread)."""
    accepted: list[dict[str, Any]] = []
    tags: list[list[str]] = []
    refused_scope = refused_limit = bodies_dropped = 0
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
    index = index_appended_har_entries(accepted, start_index=flow_count, tags=tags) if accepted else []
    return {
        "entries": accepted, "index": index, "document_bytes": document_bytes,
        "refused_scope": refused_scope, "refused_limit": refused_limit,
        "bodies_dropped": bodies_dropped,
        "encrypted": _encrypt_text(_canonical(accepted)) if accepted else None,
        "stored_bytes": stored_size(accepted) if accepted else 0,
    }


async def _append(conn: Any, row: Mapping[str, Any], metadata: dict[str, Any],
                  state: dict[str, Any], batch: CaptureBatch, digest: str) -> dict[str, int]:
    origins = await _binding_origins(conn, row)
    flow_count = int(state.get("flow_count") or 0)
    built = await asyncio.to_thread(
        _build_entries, batch, origins, flow_count=flow_count,
        document_bytes=int(state.get("document_bytes") or 0),
    )
    accepted, index = built["entries"], built["index"]
    await conn.execute(
        """INSERT INTO request_collection_capture_batches (
               collection_id, seq, batch_sha256, first_ordinal, entry_count, stored_bytes,
               encrypted_entries
           ) VALUES ($1,$2,$3,$4,$5,$6,$7)""",
        row["id"], batch.seq, digest, flow_count, len(accepted), built["stored_bytes"],
        built["encrypted"],
    )
    first = last = None
    columns = ""
    values: list[Any] = []
    if accepted:
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
        first, last = flow_count + 1, flow_count + len(accepted)
        flow_count = last
        safe = sum(1 for item in index if item.get("safe_method"))
        state["endpoint_count"] = int(await conn.fetchval(
            """SELECT count(DISTINCT (method, normalized_path)) FROM request_collection_requests
               WHERE collection_id=$1""",
            row["id"],
        ) or 0)
        columns = (", request_count=$3, safe_request_count=safe_request_count+$4, "
                   "potentially_mutating_request_count=potentially_mutating_request_count+$5")
        values = [flow_count, safe, len(index) - safe]
    state.update(
        last_seq=batch.seq,
        flow_count=flow_count,
        document_bytes=built["document_bytes"],
        refused_out_of_scope=int(state.get("refused_out_of_scope") or 0) + built["refused_scope"],
        refused_over_limit=int(state.get("refused_over_limit") or 0) + built["refused_limit"],
        bodies_dropped=int(state.get("bodies_dropped") or 0) + built["bodies_dropped"],
        last_batch_at=_iso(row["db_now"]),
    )
    if built["refused_limit"]:
        state["limit_reached"] = True
    _merge_drops(state, batch.client_dropped)
    await conn.execute(
        f"UPDATE request_collections SET metadata_json=$2, updated_at=NOW(){columns} WHERE id=$1",
        row["id"], json.dumps(metadata), *values,
    )
    return {
        "accepted": len(accepted), "refused_out_of_scope": built["refused_scope"],
        "refused_over_limit": built["refused_limit"], "bodies_dropped": built["bodies_dropped"],
        "first_flow_seq": first, "last_flow_seq": last,
    }


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return list(value) if isinstance(value, list) else []


_ENTRIES_SLOT = '"entries":[]'


def _assemble(encrypted_batches: list[str]) -> tuple[str, str]:
    """The capture's final encrypted document and its digest, from its batches in ``seq`` order
    (CPU work: run in a thread).

    Each batch holds its entries as canonical JSON (sorted keys, compact), so the document's
    canonical text is the empty document's with the batches' array contents spliced into its
    ``entries``: no batch is parsed and the document is never re-serialized. The digest is the
    one every consumer recomputes (sorted keys over the parsed payload), hashed piece by piece.
    Peak memory is the decrypted batch texts and the joined text plus Fernet's own copies while
    encrypting (about 8.7x a 52 MiB, 20,000-flow document in total): see
    tests/test_browser_capture.py::test_assembly_peak_memory_is_bounded."""
    prefix, _slot, suffix = _canonical(empty_capture_document()).partition(_ENTRIES_SLOT)
    parts: list[str] = []
    for encrypted in encrypted_batches:
        try:
            raw = decrypt_secret(encrypted)
        except SecretStoreUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="Encrypted request-collection document storage is unavailable",
            ) from exc
        if not isinstance(raw, str) or raw.startswith("enc:fernet:") or not (
            raw.startswith("[") and raw.endswith("]")
        ):
            raise HTTPException(status_code=503, detail="A capture batch could not be decrypted")
        if len(raw) > 2:
            parts.append(raw[1:-1])
    # The digest is computed piece by piece, so the document's UTF-8 bytes are never held whole.
    hasher = hashlib.sha256((prefix + '"entries":[').encode("utf-8"))
    for index, part in enumerate(parts):
        hasher.update((("," if index else "") + part).encode("utf-8"))
    hasher.update(("]" + suffix).encode("utf-8"))
    text = prefix + '"entries":[' + ",".join(parts) + "]" + suffix
    parts.clear()
    return _encrypt_text(text), hasher.hexdigest()


# Assembling a full capture peaks at several hundred MiB (see _assemble), so one API process
# assembles one capture at a time; other processes are serialized per capture by the row lock.
# The wait stays below the Enterprise gateway's default 30 s upstream timeout, so a busy close
# reaches the client as this 503 with Retry-After rather than as a gateway timeout.
ASSEMBLY_WAIT_SECONDS = 20.0
ASSEMBLY_RETRY_AFTER_SECONDS = 10
_assembly_slots: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
    weakref.WeakKeyDictionary()
)


class AssemblyBusy(HTTPException):
    """Another capture is being assembled in this process: answered 503 with Retry-After."""

    def __init__(self) -> None:
        super().__init__(
            status_code=503,
            detail={"error": "capture_assembly_busy",
                    "message": "Another capture is being assembled; retry the close shortly"},
            headers={"Retry-After": str(ASSEMBLY_RETRY_AFTER_SECONDS)},
        )


def _assembly_slot() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    slot = _assembly_slots.get(loop)
    if slot is None:
        slot = _assembly_slots[loop] = asyncio.Semaphore(1)
    return slot


async def _finalize(conn: Any, row: Mapping[str, Any], metadata: dict[str, Any],
                    state: dict[str, Any], *, reason: str,
                    wait_seconds: float | None = None) -> Mapping[str, Any]:
    """Close a locked open capture: assemble its batches into the encrypted document (once),
    clear the per-batch copies (their digests stay) and record why it closed.

    The assembly waits at most ``wait_seconds`` (default ASSEMBLY_WAIT_SECONDS; 0: not at all)
    for this process's one assembly slot, then raises AssemblyBusy with nothing changed."""
    slot = _assembly_slot()
    wait = ASSEMBLY_WAIT_SECONDS if wait_seconds is None else wait_seconds
    if wait <= 0:
        if slot.locked():
            raise AssemblyBusy()
        await slot.acquire()
    else:
        try:
            await asyncio.wait_for(slot.acquire(), timeout=wait)
        except asyncio.TimeoutError:
            raise AssemblyBusy() from None
    try:
        batches = await conn.fetch(
            """SELECT encrypted_entries FROM request_collection_capture_batches
               WHERE collection_id=$1 AND encrypted_entries IS NOT NULL ORDER BY seq""",
            row["id"],
        )
        encrypted, digest = await asyncio.to_thread(
            _assemble, [str(item["encrypted_entries"]) for item in batches],
        )
        del batches
    finally:
        slot.release()
    state.update(state="closed", closed_reason=reason, closed_at=_iso(row["db_now"]))
    updated = await conn.fetchrow(
        """UPDATE request_collections
           SET metadata_json=$2, encrypted_payload=$3, payload_sha256=$4, updated_at=NOW()
           WHERE id=$1 RETURNING *""",
        row["id"], json.dumps(metadata), encrypted, digest,
    )
    await conn.execute(
        """UPDATE request_collection_capture_batches SET encrypted_entries=NULL
           WHERE collection_id=$1 AND encrypted_entries IS NOT NULL""",
        row["id"],
    )
    # No selection can exist over an open capture (refuse_open_capture); any that does is over
    # a document that no longer exists, so it is revoked, never left admissible.
    await conn.execute(
        """UPDATE request_collection_selections
           SET is_active=false, revoked_at=COALESCE(revoked_at, NOW()), updated_at=NOW()
           WHERE collection_id=$1 AND revoked_at IS NULL""",
        row["id"],
    )
    return updated


async def close_capture(conn: Any, collection_id: uuid.UUID, drops: CaptureDropCounts | None, *,
                        actor: str = LOCAL_OPERATOR) -> dict[str, Any]:
    async with conn.transaction():
        row, metadata, state = await _locked_capture(conn, collection_id)
        _require_owner(state, actor)
        if state.get("state") == "closed":
            status = "already_closed"
        else:
            status = "closed"
            _merge_drops(state, drops)
            row = await _finalize(conn, row, metadata, state, reason="client")
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
    closed = 0
    async with pool.acquire() as conn:
        candidates = await conn.fetch(
            """SELECT id FROM request_collections
               WHERE is_active=true AND format='capture'
                 AND metadata_json->'capture'->>'state'='open'
                 AND updated_at < NOW() - make_interval(secs => $1)
               ORDER BY updated_at LIMIT $2""",
            float(idle_seconds), int(limit),
        )
        for candidate in candidates:
            async with conn.transaction():
                # Re-checked under the row lock; a capture a batch holds is left for next time.
                row = await conn.fetchrow(
                    """SELECT *, NOW() AS db_now FROM request_collections
                       WHERE id=$1 AND is_active=true AND format='capture'
                         AND metadata_json->'capture'->>'state'='open'
                         AND updated_at < NOW() - make_interval(secs => $2)
                       FOR UPDATE SKIP LOCKED""",
                    candidate["id"], float(idle_seconds),
                )
                if not row:
                    continue
                metadata = _json_object(row["metadata_json"])
                state = metadata.get("capture")
                if not isinstance(state, dict) or state.get("schema") != CAPTURE_SCHEMA:
                    continue
                try:
                    async with conn.transaction():  # a savepoint: a failed assembly changes nothing
                        # Never queues behind a client close: a busy slot leaves it for next tick.
                        await _finalize(conn, row, metadata, state, reason="idle", wait_seconds=0)
                except AssemblyBusy:
                    continue
                except Exception as exc:  # noqa: BLE001 - one capture must not stop the others
                    # Closed without a document so it is not retried every tick; its batches
                    # stay encrypted for an operator to recover. Only the type is logged.
                    print(f"[capture] idle close: assembly failed for {row['id']}: {type(exc).__name__}",
                          flush=True)
                    state.update(state="closed", closed_reason="assembly_failed",
                                 closed_at=_iso(row["db_now"]))
                    await conn.execute(
                        "UPDATE request_collections SET metadata_json=$2, updated_at=NOW() WHERE id=$1",
                        row["id"], json.dumps(metadata),
                    )
                closed += 1
    return closed


async def close_on_deactivate(conn: Any, collection_id: uuid.UUID) -> None:
    """Called inside a deactivation's transaction: an open capture is closed first, so its
    batches become its document instead of ciphertext no close will ever assemble."""
    row = await conn.fetchrow(
        """SELECT *, NOW() AS db_now FROM request_collections
           WHERE id=$1 AND format='capture' FOR UPDATE""",
        collection_id,
    )
    if not row:
        return
    metadata = _json_object(row["metadata_json"])
    state = metadata.get("capture")
    if isinstance(state, dict) and state.get("schema") == CAPTURE_SCHEMA and state.get("state") == "open":
        await _finalize(conn, row, metadata, state, reason="deactivated")


def refuse_open_capture(row: Mapping[str, Any] | None) -> None:
    """A capture still recording has no document to select yet: it is refused for a selection,
    a Scan and a Hunt with a 409 that says what to do. ``row`` has the collection's ``format``
    and either its ``metadata_json`` or a ``capture_state`` column."""
    if not row or row.get("format") != CAPTURE_FORMAT:
        return
    state = row.get("capture_state")
    if state is None:
        capture = _json_object(row.get("metadata_json")).get("capture")
        state = capture.get("state") if isinstance(capture, Mapping) else None
    if state == "open":
        raise _conflict(
            "capture_open",
            "This browser capture is still recording; close it first (finish `shakerscan record`, "
            f"or POST /request-collections/{row.get('id')}/capture-close), then select or scan it",
            collection_id=str(row.get("id") or ""),
        )


__all__ = [
    "apply_batch",
    "close_capture",
    "close_idle_captures",
    "close_on_deactivate",
    "create_capture",
    "public_collection",
    "refuse_open_capture",
]
