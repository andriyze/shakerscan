"""Encrypted, target-bound request collection HTTP API.

This module owns the collection CRUD behavior and public schemas.  Scan and
Hunt consume only the content-free selection helpers exported at the bottom;
the primary API module does not own a second collection router.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from typing import Any, Callable, Literal, Mapping, Optional, Sequence
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    from runtime.request_collection_store import (
        REPLAY_POLICIES,
        RequestCollectionContractError,
        RequestCollectionSelection,
        canonical_collection_origin,
        canonical_collection_origins,
        request_collection_selection_digest,
    )
except ModuleNotFoundError:
    from api.runtime.request_collection_store import (
        REPLAY_POLICIES,
        RequestCollectionContractError,
        RequestCollectionSelection,
        canonical_collection_origin,
        canonical_collection_origins,
        request_collection_selection_digest,
    )

try:
    from scanner_tools.request_collections import (
        RequestImportError,
        validate_and_index as validate_and_index_request_collection,
    )
except ModuleNotFoundError:
    from scanner.scanner_tools.request_collections import (
        RequestImportError,
        validate_and_index as validate_and_index_request_collection,
    )

try:
    from secret_store import encrypt_secret
except ModuleNotFoundError:
    from api.secret_store import encrypt_secret


router = APIRouter(tags=["request-collections"])
_pool_provider: Callable[[], Any] | None = None


def configure_request_collection_router(pool_provider: Callable[[], Any]) -> None:
    """Bind the application database without importing the API monolith."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool() -> Any:
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="request collection database is unavailable")
    return pool


class RequestCollectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str
    name: Optional[str] = Field(default=None, max_length=300)
    format: Literal["auto", "postman_collection", "har", "openapi"] = "auto"
    document: Any
    environment: Any = None
    environment_name: Optional[str] = Field(default=None, max_length=160)
    base_url: Optional[str] = Field(default=None, max_length=2048)
    import_limit: int = Field(default=5000, ge=1, le=20000)
    max_document_bytes: int = Field(
        default=25 * 1024 * 1024, ge=1, le=50 * 1024 * 1024,
    )


class RequestCollectionSelect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_ids: list[str] = Field(default_factory=list, max_length=2000)
    folders: list[str] = Field(default_factory=list, max_length=200)
    methods: list[str] = Field(default_factory=list, max_length=20)
    path_regex: Optional[str] = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=200)
    safe_methods_only: bool = True
    limit: int = Field(default=500, ge=1, le=2000)


class RequestCollectionEnvironmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    document: dict[str, Any]


class RequestCollectionBindingUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_kind: Literal["web", "api", "device"]
    target_id: str
    allowed_origins: list[str] = Field(min_length=1, max_length=32)
    environment_id: Optional[str] = None


class RequestCollectionSelectionUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    binding_id: str
    replay_policy: Literal[
        "discovery_only", "safe_reads", "safe_authentication", "confirmed_active",
    ] = (
        "safe_reads"
    )
    request_ids: list[str] = Field(default_factory=list, max_length=2000)
    folders: list[str] = Field(default_factory=list, max_length=200)
    methods: list[str] = Field(default_factory=list, max_length=20)
    path_regex: Optional[str] = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=200)
    safe_methods_only: bool = True
    max_requests: int = Field(default=500, ge=1, le=2000)
    disposable_credentials: bool = False


def _uuid_or_400(value: str, name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {name}") from exc


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def _row_to_dict(row: Any) -> dict[str, Any]:
    item = dict(row or {})
    for key, value in tuple(item.items()):
        if isinstance(value, uuid.UUID):
            item[key] = str(value)
        elif isinstance(value, datetime):
            item[key] = value.isoformat()
    return item


def _public_request_collection(row: Any) -> dict[str, Any]:
    item = _row_to_dict(row)
    item.pop("encrypted_payload", None)
    item["id"] = str(item.get("id")) if item.get("id") else None
    item["target_id"] = str(item.get("target_id")) if item.get("target_id") else None
    item["device_target_id"] = (
        str(item.get("device_target_id")) if item.get("device_target_id") else None
    )
    item["storage_encrypted"] = True
    item["secret_values_visible"] = False
    return item


def _public_request_collection_environment(row: Any) -> dict[str, Any]:
    item = _row_to_dict(row)
    item.pop("encrypted_payload", None)
    item["id"] = str(item.get("id")) if item.get("id") else None
    item["collection_id"] = (
        str(item.get("collection_id")) if item.get("collection_id") else None
    )
    item["storage_encrypted"] = True
    item["secret_values_visible"] = False
    return item


def _public_request_collection_binding(row: Any) -> dict[str, Any]:
    item = _row_to_dict(row)
    for key in ("id", "collection_id", "target_id", "environment_id"):
        item[key] = str(item.get(key)) if item.get(key) else None
    item["allowed_origins"] = list(
        _decode_json_value(item.get("allowed_origins")) or []
    )
    item["secret_values_visible"] = False
    return item


def _public_request_collection_selection(row: Any) -> dict[str, Any]:
    item = _row_to_dict(row)
    for key in ("id", "collection_id", "binding_id"):
        item[key] = str(item.get(key)) if item.get(key) else None
    item["selector"] = _decode_json_value(item.pop("selector_json", None)) or {}
    item["secret_values_visible"] = False
    return item


def _request_collection_json_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()


def _encrypt_request_collection_payload(value: Any, *, kind: str) -> str:
    encrypted = encrypt_secret(json.dumps(
        value, separators=(",", ":"), ensure_ascii=False,
    ))
    if not str(encrypted or "").startswith("enc:fernet:"):
        raise HTTPException(
            status_code=503,
            detail=f"Encrypted request-collection {kind} storage is unavailable",
        )
    return str(encrypted)


def _request_collection_environment_count(document: Mapping[str, Any]) -> int:
    values = document.get("values")
    if not isinstance(values, list):
        values = document.get("variable")
    return len([item for item in values or [] if isinstance(item, Mapping)])


def request_collection_selector(value: Any) -> RequestCollectionSelection:
    try:
        if isinstance(value, RequestCollectionSelect):
            raw = value.model_dump(mode="json")
            raw["max_requests"] = raw.pop("limit")
        elif isinstance(value, RequestCollectionSelectionUpsert):
            raw = value.model_dump(
                mode="json", exclude={"name", "binding_id", "replay_policy"},
            )
        elif isinstance(value, Mapping):
            raw = dict(value)
        else:
            raw = {}
        return RequestCollectionSelection.from_mapping(raw)
    except RequestCollectionContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _request_collection_index_item(row: Any) -> dict[str, Any]:
    item = _row_to_dict(row)
    item["tags"] = list(_decode_json_value(item.pop("tags_json", None)) or [])
    item["body_field_names"] = list(
        _decode_json_value(item.pop("body_field_names_json", None)) or []
    )
    return item


def select_request_collection_index_rows(
    rows: Sequence[Any], selector: RequestCollectionSelection,
) -> list[dict[str, Any]]:
    ids = set(selector.request_ids)
    folders = set(selector.folders)
    methods = set(selector.methods)
    tags = set(selector.tags)
    try:
        path_pattern = re.compile(selector.path_regex) if selector.path_regex else None
    except re.error as exc:
        raise HTTPException(
            status_code=422, detail="selection path_regex is invalid",
        ) from exc
    selected: list[dict[str, Any]] = []
    for raw in rows:
        item = _request_collection_index_item(raw)
        if selector.safe_methods_only and not item.get("safe_method"):
            continue
        if ids and item.get("request_id") not in ids:
            continue
        if folders and item.get("folder") not in folders:
            continue
        if methods and item.get("method") not in methods:
            continue
        if tags and not tags.intersection(str(tag) for tag in item.get("tags") or []):
            continue
        if path_pattern and not path_pattern.search(
            str(item.get("normalized_path") or "")
        ):
            continue
        selected.append(item)
        if len(selected) >= selector.max_requests:
            break
    return selected


async def _request_collection_owner(
    conn: Any, collection_id: uuid.UUID,
) -> dict[str, Any]:
    row = await conn.fetchrow(
        """SELECT rc.*, t.url AS target_url, d.primary_locator AS device_locator
           FROM request_collections rc
           LEFT JOIN targets t ON t.id=rc.target_id
           LEFT JOIN device_targets d ON d.id=rc.device_target_id
           WHERE rc.id=$1 AND rc.is_active=true""",
        collection_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Request collection not found")
    return dict(row)


def _request_collection_owner_binding(
    collection: Mapping[str, Any], *, target_kind: str, target_id: uuid.UUID,
    allowed_origins: Sequence[str],
) -> tuple[str, ...]:
    owner_id = collection.get("target_id") or collection.get("device_target_id")
    if str(owner_id or "") != str(target_id):
        raise HTTPException(
            status_code=422,
            detail="request collection binding target does not match its owner",
        )
    expected_kind = "device" if collection.get("device_target_id") else target_kind
    if collection.get("device_target_id") and target_kind != "device":
        raise HTTPException(
            status_code=422, detail="device collection requires a device binding",
        )
    if not collection.get("device_target_id") and target_kind not in {"web", "api"}:
        raise HTTPException(
            status_code=422, detail="web collection requires a web or API binding",
        )
    try:
        origins = canonical_collection_origins(list(allowed_origins))
    except RequestCollectionContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    expected_host = urllib.parse.urlsplit(
        str(collection.get("target_url") or "")
    ).hostname
    if expected_kind == "device":
        expected_host = str(
            collection.get("device_locator") or ""
        ).strip().lower().rstrip(".")
    if expected_host and any(
        urllib.parse.urlsplit(origin).hostname != expected_host.lower().rstrip(".")
        for origin in origins
    ):
        raise HTTPException(
            status_code=422,
            detail="request collection binding origin is outside the exact target host",
        )
    return origins


@router.post("/request-collections")
async def create_request_collection(request: RequestCollectionCreate):
    target_uuid = _uuid_or_400(request.target_id, "target id")
    try:
        payload, summary, index = validate_and_index_request_collection(
            request.document,
            request.environment,
            requested_name=request.name,
            import_format=request.format,
            base_url=request.base_url,
            import_limit=request.import_limit,
            max_document_bytes=request.max_document_bytes,
        )
    except RequestImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    collection_payload = dict(payload)
    environment_payload = collection_payload.pop("environment", None)
    collection_digest = _request_collection_json_digest(collection_payload)
    encrypted_payload = _encrypt_request_collection_payload(
        collection_payload, kind="document",
    )
    summary = {
        **dict(summary),
        "document_sha256": collection_digest,
        "payload_sha256": collection_digest,
        "environment_stored_separately": environment_payload is not None,
    }
    async with _pool().acquire() as conn:
        web_target = await conn.fetchrow(
            "SELECT id, url FROM targets WHERE id=$1 AND is_active=true", target_uuid,
        )
        device_target = None if web_target else await conn.fetchrow(
            """SELECT id, primary_locator FROM device_targets
               WHERE id=$1 AND is_active=true""",
            target_uuid,
        )
        if not web_target and not device_target:
            raise HTTPException(
                status_code=404, detail="Active web or device target not found",
            )
        async with conn.transaction():
            collection_name = summary.get("name") or request.name or "Request collection"
            existing = await conn.fetchrow(
                """SELECT id, payload_sha256 FROM request_collections
                   WHERE name=$1 AND (($2::uuid IS NOT NULL AND target_id=$2) OR
                                      ($3::uuid IS NOT NULL AND device_target_id=$3))
                   FOR UPDATE""",
                collection_name,
                target_uuid if web_target else None,
                target_uuid if device_target else None,
            )
            collection_id = existing["id"] if existing else uuid.uuid4()
            row = await conn.fetchrow(
                """INSERT INTO request_collections (
                       id, target_id, device_target_id, name, format, encrypted_payload,
                       payload_sha256, request_count, safe_request_count,
                       potentially_mutating_request_count, metadata_json
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                   ON CONFLICT (id)
                   DO UPDATE SET format=EXCLUDED.format, encrypted_payload=EXCLUDED.encrypted_payload,
                       payload_sha256=EXCLUDED.payload_sha256, request_count=EXCLUDED.request_count,
                       safe_request_count=EXCLUDED.safe_request_count,
                       potentially_mutating_request_count=EXCLUDED.potentially_mutating_request_count,
                       metadata_json=EXCLUDED.metadata_json, updated_at=NOW(), is_active=true
                   RETURNING *""",
                collection_id,
                target_uuid if web_target else None,
                target_uuid if device_target else None,
                collection_name,
                summary.get("format") or request.format,
                encrypted_payload,
                collection_digest,
                int(summary.get("request_count") or len(index)),
                sum(1 for item in index if item.get("safe_method")),
                sum(1 for item in index if not item.get("safe_method")),
                json.dumps({
                    key: value for key, value in summary.items() if key != "requests"
                }, default=str),
            )
            await conn.execute(
                "DELETE FROM request_collection_requests WHERE collection_id=$1",
                row["id"],
            )
            if index:
                await conn.executemany(
                    """INSERT INTO request_collection_requests (
                           collection_id, request_id, ordinal, folder, name, method,
                           redacted_url, normalized_path, body_mode, auth_type, tags_json,
                           content_type, body_field_names_json, safe_method, supported
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""",
                    [(
                        row["id"], item["request_id"], item["ordinal"],
                        item.get("folder"), item.get("name"), item["method"],
                        item.get("redacted_url"), item.get("normalized_path"),
                        item.get("body_mode"), item.get("auth_type"),
                        json.dumps(item.get("tags") or []),
                        item.get("content_type"),
                        json.dumps(item.get("body_field_names") or []),
                        item.get("safe_method", False), item.get("supported", True),
                    ) for item in index],
                )
            if existing and str(existing.get("payload_sha256") or "") != collection_digest:
                await conn.execute(
                    """UPDATE request_collection_selections
                       SET is_active=false, updated_at=NOW()
                       WHERE collection_id=$1 AND is_active=true""",
                    row["id"],
                )

            environment_row = None
            if environment_payload is not None:
                if not isinstance(environment_payload, Mapping):
                    raise HTTPException(
                        status_code=422,
                        detail="Postman environment must be one JSON object",
                    )
                environment_digest = _request_collection_json_digest(environment_payload)
                environment_name = str(
                    request.environment_name
                    or environment_payload.get("name")
                    or "Default environment"
                ).strip()[:160]
                existing_environment = await conn.fetchrow(
                    """SELECT id, payload_sha256
                       FROM request_collection_environments
                       WHERE collection_id=$1 AND name=$2 FOR UPDATE""",
                    row["id"], environment_name,
                )
                environment_row = await conn.fetchrow(
                    """INSERT INTO request_collection_environments (
                           collection_id, name, encrypted_payload, payload_sha256,
                           variable_count, metadata_json
                       ) VALUES ($1,$2,$3,$4,$5,$6)
                       ON CONFLICT (collection_id, name) DO UPDATE SET
                           encrypted_payload=EXCLUDED.encrypted_payload,
                           payload_sha256=EXCLUDED.payload_sha256,
                           variable_count=EXCLUDED.variable_count,
                           metadata_json=EXCLUDED.metadata_json,
                           is_active=true, updated_at=NOW()
                       RETURNING *""",
                    row["id"],
                    environment_name,
                    _encrypt_request_collection_payload(
                        environment_payload, kind="environment",
                    ),
                    environment_digest,
                    _request_collection_environment_count(environment_payload),
                    json.dumps({
                        "schema_version": "request-collection-environment/v1",
                        "secret_values_visible": False,
                    }),
                )
                if (
                    existing_environment
                    and str(existing_environment.get("payload_sha256") or "")
                    != environment_digest
                ):
                    await conn.execute(
                        """UPDATE request_collection_selections s
                           SET is_active=false, updated_at=NOW()
                           FROM request_collection_bindings b
                           WHERE s.binding_id=b.id
                             AND b.environment_id=$1
                             AND s.is_active=true""",
                        environment_row["id"],
                    )

            binding_row = None
            binding_origin = None
            binding_kind = "web"
            if web_target:
                parsed_target = urllib.parse.urlsplit(str(web_target["url"] or ""))
                binding_origin = canonical_collection_origin(
                    f"{parsed_target.scheme}://{parsed_target.netloc}"
                )
            elif request.base_url:
                parsed_base = urllib.parse.urlsplit(request.base_url)
                binding_origin = canonical_collection_origin(
                    f"{parsed_base.scheme}://{parsed_base.netloc}"
                )
                binding_kind = "device"
            if binding_origin:
                binding_row = await conn.fetchrow(
                    """INSERT INTO request_collection_bindings (
                           collection_id, target_kind, target_id, allowed_origins,
                           environment_id
                       ) VALUES ($1,$2,$3,$4,$5)
                       ON CONFLICT (collection_id, target_kind, target_id) DO UPDATE SET
                           allowed_origins=EXCLUDED.allowed_origins,
                           environment_id=COALESCE(EXCLUDED.environment_id,
                               request_collection_bindings.environment_id),
                           is_active=true, updated_at=NOW()
                       RETURNING *""",
                    row["id"], binding_kind, target_uuid,
                    json.dumps([binding_origin]),
                    environment_row["id"] if environment_row else None,
                )
    result = _public_request_collection(row)
    result["environment"] = (
        _public_request_collection_environment(environment_row)
        if environment_row else None
    )
    result["binding"] = (
        _public_request_collection_binding(binding_row) if binding_row else None
    )
    return result


@router.get("/request-collections")
async def list_request_collections(
    target_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM request_collections
               WHERE is_active=true AND (target_id=$1 OR device_target_id=$1)
               ORDER BY updated_at DESC LIMIT $2 OFFSET $3""",
            target_uuid, limit, offset,
        )
    return {
        "collections": [_public_request_collection(row) for row in rows],
        "count": len(rows), "limit": limit, "offset": offset,
    }


@router.get("/request-collections/{collection_id}/requests")
async def list_request_collection_requests(
    collection_id: str,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    async with _pool().acquire() as conn:
        exists = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM request_collections WHERE id=$1 AND is_active=true)",
            collection_uuid,
        )
        if not exists:
            raise HTTPException(status_code=404, detail="Request collection not found")
        rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url,
                      normalized_path, body_mode, auth_type, tags_json, safe_method,
                      supported, content_type, body_field_names_json
               FROM request_collection_requests WHERE collection_id=$1
               ORDER BY ordinal LIMIT $2 OFFSET $3""",
            collection_uuid, limit, offset,
        )
        total = int(await conn.fetchval(
            "SELECT COUNT(*) FROM request_collection_requests WHERE collection_id=$1",
            collection_uuid,
        ) or 0)
    return {
        "requests": [_request_collection_index_item(row) for row in rows],
        "count": len(rows), "total": total, "offset": offset, "limit": limit,
        "next_offset": (
            offset + len(rows) if offset + len(rows) < total else None
        ),
        "secret_values_visible": False,
    }


@router.post("/request-collections/{collection_id}/select")
async def select_request_collection_index(
    collection_id: str, request: RequestCollectionSelect,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    selector = request_collection_selector(request)
    async with _pool().acquire() as conn:
        exists = await conn.fetchval(
            "SELECT EXISTS(SELECT 1 FROM request_collections WHERE id=$1 AND is_active=true)",
            collection_uuid,
        )
        if not exists:
            raise HTTPException(status_code=404, detail="Request collection not found")
        rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url,
                      normalized_path, body_mode, auth_type, tags_json, safe_method,
                      supported, content_type, body_field_names_json
               FROM request_collection_requests
               WHERE collection_id=$1 ORDER BY ordinal LIMIT 20000""",
            collection_uuid,
        )
    selected = select_request_collection_index_rows(rows, selector)
    return {
        "collection_id": collection_id, "requests": selected,
        "count": len(selected), "limit": selector.max_requests,
        "secret_values_visible": False,
    }


@router.get("/request-collections/{collection_id}")
async def get_request_collection(collection_id: str):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    async with _pool().acquire() as conn:
        collection = await _request_collection_owner(conn, collection_uuid)
        environments = await conn.fetch(
            """SELECT id, collection_id, name, payload_sha256, variable_count,
                      metadata_json, is_active, created_at, updated_at
               FROM request_collection_environments
               WHERE collection_id=$1 AND is_active=true
               ORDER BY lower(name), id""",
            collection_uuid,
        )
        bindings = await conn.fetch(
            """SELECT * FROM request_collection_bindings
               WHERE collection_id=$1 AND is_active=true
               ORDER BY target_kind, target_id, id""",
            collection_uuid,
        )
        selections = await conn.fetch(
            """SELECT * FROM request_collection_selections
               WHERE collection_id=$1 AND is_active=true
               ORDER BY lower(name), id""",
            collection_uuid,
        )
    return {
        "collection": _public_request_collection(collection),
        "environments": [
            _public_request_collection_environment(row) for row in environments
        ],
        "bindings": [_public_request_collection_binding(row) for row in bindings],
        "selections": [
            _public_request_collection_selection(row) for row in selections
        ],
        "secret_values_visible": False,
    }


@router.post("/request-collections/{collection_id}/environments")
async def upsert_request_collection_environment(
    collection_id: str, request: RequestCollectionEnvironmentCreate,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    try:
        serialized = json.dumps(
            request.document, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422, detail="Postman environment must be valid JSON",
        ) from exc
    if len(serialized) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=422, detail="Postman environment exceeds the 2 MiB limit",
        )
    digest = _request_collection_json_digest(request.document)
    async with _pool().acquire() as conn:
        await _request_collection_owner(conn, collection_uuid)
        async with conn.transaction():
            existing = await conn.fetchrow(
                """SELECT id, payload_sha256 FROM request_collection_environments
                   WHERE collection_id=$1 AND name=$2 FOR UPDATE""",
                collection_uuid, request.name,
            )
            row = await conn.fetchrow(
                """INSERT INTO request_collection_environments (
                       collection_id, name, encrypted_payload, payload_sha256,
                       variable_count, metadata_json
                   ) VALUES ($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (collection_id, name) DO UPDATE SET
                       encrypted_payload=EXCLUDED.encrypted_payload,
                       payload_sha256=EXCLUDED.payload_sha256,
                       variable_count=EXCLUDED.variable_count,
                       metadata_json=EXCLUDED.metadata_json,
                       is_active=true, updated_at=NOW()
                   RETURNING *""",
                collection_uuid, request.name,
                _encrypt_request_collection_payload(
                    request.document, kind="environment",
                ),
                digest,
                _request_collection_environment_count(request.document),
                json.dumps({
                    "schema_version": "request-collection-environment/v1",
                    "secret_values_visible": False,
                }),
            )
            if existing and str(existing.get("payload_sha256") or "") != digest:
                await conn.execute(
                    """UPDATE request_collection_selections s
                       SET is_active=false, updated_at=NOW()
                       FROM request_collection_bindings b
                       WHERE s.binding_id=b.id
                         AND b.environment_id=$1
                         AND s.is_active=true""",
                    row["id"],
                )
    return {"environment": _public_request_collection_environment(row)}


@router.delete("/request-collections/{collection_id}/environments/{environment_id}")
async def deactivate_request_collection_environment(
    collection_id: str, environment_id: str,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    environment_uuid = _uuid_or_400(
        environment_id, "request collection environment id",
    )
    async with _pool().acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """UPDATE request_collection_environments
                   SET is_active=false, updated_at=NOW()
                   WHERE id=$1 AND collection_id=$2 AND is_active=true
                   RETURNING id, collection_id, name, payload_sha256, variable_count,
                             metadata_json, is_active, created_at, updated_at""",
                environment_uuid, collection_uuid,
            )
            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Request collection environment not found",
                )
            await conn.execute(
                """UPDATE request_collection_bindings
                   SET environment_id=NULL, updated_at=NOW()
                   WHERE collection_id=$1 AND environment_id=$2""",
                collection_uuid, environment_uuid,
            )
            await conn.execute(
                """UPDATE request_collection_selections s
                   SET is_active=false, updated_at=NOW()
                   FROM request_collection_bindings b
                   WHERE s.binding_id=b.id AND b.collection_id=$1""",
                collection_uuid,
            )
    return {
        "status": "deactivated",
        "environment": _public_request_collection_environment(row),
    }


@router.post("/request-collections/{collection_id}/bindings")
async def upsert_request_collection_binding(
    collection_id: str, request: RequestCollectionBindingUpsert,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    target_uuid = _uuid_or_400(
        request.target_id, "request collection target id",
    )
    environment_uuid = (
        _uuid_or_400(
            request.environment_id, "request collection environment id",
        ) if request.environment_id else None
    )
    async with _pool().acquire() as conn:
        collection = await _request_collection_owner(conn, collection_uuid)
        origins = _request_collection_owner_binding(
            collection,
            target_kind=request.target_kind,
            target_id=target_uuid,
            allowed_origins=request.allowed_origins,
        )
        if environment_uuid and not await conn.fetchval(
            """SELECT EXISTS(
                   SELECT 1 FROM request_collection_environments
                   WHERE id=$1 AND collection_id=$2 AND is_active=true
               )""",
            environment_uuid, collection_uuid,
        ):
            raise HTTPException(
                status_code=422,
                detail=(
                    "request collection environment is unavailable or belongs "
                    "to another collection"
                ),
            )
        async with conn.transaction():
            existing = await conn.fetchrow(
                """SELECT * FROM request_collection_bindings
                   WHERE collection_id=$1 AND target_kind=$2 AND target_id=$3
                   FOR UPDATE""",
                collection_uuid, request.target_kind, target_uuid,
            )
            row = await conn.fetchrow(
                """INSERT INTO request_collection_bindings (
                       collection_id, target_kind, target_id, allowed_origins,
                       environment_id
                   ) VALUES ($1,$2,$3,$4,$5)
                   ON CONFLICT (collection_id, target_kind, target_id) DO UPDATE SET
                       allowed_origins=EXCLUDED.allowed_origins,
                       environment_id=EXCLUDED.environment_id,
                       is_active=true, updated_at=NOW()
                   RETURNING *""",
                collection_uuid, request.target_kind, target_uuid,
                json.dumps(origins), environment_uuid,
            )
            if existing and (
                tuple(_decode_json_value(existing.get("allowed_origins")) or ())
                != origins
                or str(existing.get("environment_id") or "")
                != str(environment_uuid or "")
            ):
                await conn.execute(
                    """UPDATE request_collection_selections
                       SET is_active=false, updated_at=NOW()
                       WHERE binding_id=$1 AND is_active=true""",
                    row["id"],
                )
    return {"binding": _public_request_collection_binding(row)}


@router.post("/request-collections/{collection_id}/selections")
async def upsert_request_collection_selection(
    collection_id: str, request: RequestCollectionSelectionUpsert,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    binding_uuid = _uuid_or_400(
        request.binding_id, "request collection binding id",
    )
    selector = request_collection_selector(request)
    if request.replay_policy not in REPLAY_POLICIES:
        raise HTTPException(
            status_code=422,
            detail="request collection replay policy is invalid",
        )
    async with _pool().acquire() as conn:
        collection = await _request_collection_owner(conn, collection_uuid)
        binding = await conn.fetchrow(
            """SELECT b.*, e.payload_sha256 AS environment_sha256
               FROM request_collection_bindings b
               LEFT JOIN request_collection_environments e
                 ON e.id=b.environment_id AND e.is_active=true
               WHERE b.id=$1 AND b.collection_id=$2 AND b.is_active=true""",
            binding_uuid, collection_uuid,
        )
        if not binding:
            raise HTTPException(
                status_code=422,
                detail=(
                    "request collection binding is unavailable or belongs to "
                    "another collection"
                ),
            )
        rows = await conn.fetch(
            """SELECT request_id, ordinal, folder, name, method, redacted_url,
                      normalized_path, body_mode, auth_type, tags_json,
                      safe_method, supported, content_type, body_field_names_json
               FROM request_collection_requests
               WHERE collection_id=$1 ORDER BY ordinal LIMIT 20000""",
            collection_uuid,
        )
        selected = select_request_collection_index_rows(rows, selector)
        if not selected:
            raise HTTPException(
                status_code=422, detail="request collection selection is empty",
            )
        if request.replay_policy == "safe_authentication":
            auth_path = re.compile(
                r"/(?:login|signin|authenticate|token|session)/?$", re.IGNORECASE,
            )
            if any(
                str(item.get("method") or "").upper() != "POST"
                or item.get("supported") is not True
                or not auth_path.search(str(item.get("normalized_path") or ""))
                or not any(marker in str(item.get("body_mode") or "").lower()
                           for marker in ("json", "form", "urlencoded", "raw"))
                for item in selected
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "safe_authentication accepts only supported exact POST "
                        "login/token requests with JSON or form bodies"
                    ),
                )
            identifier_fields = {"user", "username", "email", "login", "client_id"}
            secret_fields = {"password", "pass", "passwd", "secret", "client_secret", "token"}
            if any(
                not (
                    {
                        str(field).lower().rsplit(".", 1)[-1].removesuffix("[]")
                        for field in item.get("body_field_names") or []
                    }.intersection(identifier_fields)
                    and {
                        str(field).lower().rsplit(".", 1)[-1].removesuffix("[]")
                        for field in item.get("body_field_names") or []
                    }.intersection(secret_fields)
                )
                for item in selected
            ):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "safe_authentication requests must expose credential field "
                        "names in their redacted body metadata"
                    ),
                )
        try:
            digest = request_collection_selection_digest(
                collection_id=collection_uuid,
                payload_sha256=str(collection.get("payload_sha256") or ""),
                binding_id=binding_uuid,
                allowed_origins=(
                    _decode_json_value(binding.get("allowed_origins")) or []
                ),
                selector=selector,
                replay_policy=request.replay_policy,
                environment_sha256=binding.get("environment_sha256"),
            )
        except RequestCollectionContractError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        mutating_count = sum(
            1 for item in selected if not item.get("safe_method")
        )
        async with conn.transaction():
            previous = await conn.fetchrow(
                """SELECT id, selection_digest
                   FROM request_collection_selections
                   WHERE binding_id=$1 AND lower(name)=lower($2) AND is_active=true
                   FOR UPDATE""",
                binding_uuid, request.name,
            )
            if previous and str(previous["selection_digest"] or "") == digest:
                row = await conn.fetchrow(
                    """UPDATE request_collection_selections
                       SET name=$2, updated_at=NOW()
                       WHERE id=$1 RETURNING *""",
                    previous["id"], request.name,
                )
            else:
                if previous:
                    await conn.execute(
                        """UPDATE request_collection_selections
                           SET is_active=false, updated_at=NOW()
                           WHERE id=$1""",
                        previous["id"],
                    )
                row = await conn.fetchrow(
                    """INSERT INTO request_collection_selections (
                           collection_id, binding_id, name, replay_policy,
                           selector_json, selection_digest,
                           selected_request_count, selected_mutating_count
                       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                       RETURNING *""",
                    collection_uuid, binding_uuid, request.name,
                    request.replay_policy, json.dumps(selector.public_dict()),
                    digest, len(selected), mutating_count,
                )
    return {
        "selection": _public_request_collection_selection(row),
        "replaced_selection_id": (
            str(previous["id"])
            if previous and str(previous["selection_digest"] or "") != digest
            else None
        ),
        "preview": {
            "requests": selected[:200],
            "count": len(selected),
            "preview_truncated": len(selected) > 200,
            "secret_values_visible": False,
        },
    }


@router.delete("/request-collections/{collection_id}/selections/{selection_id}")
async def deactivate_request_collection_selection(
    collection_id: str, selection_id: str,
):
    collection_uuid = _uuid_or_400(collection_id, "request collection id")
    selection_uuid = _uuid_or_400(
        selection_id, "request collection selection id",
    )
    async with _pool().acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE request_collection_selections
               SET is_active=false, revoked_at=NOW(), updated_at=NOW()
               WHERE id=$1 AND collection_id=$2 AND revoked_at IS NULL
               RETURNING *""",
            selection_uuid, collection_uuid,
        )
    if not row:
        raise HTTPException(
            status_code=404, detail="Request collection selection not found",
        )
    return {
        "status": "revoked",
        "selection": _public_request_collection_selection(row),
    }


__all__ = [
    "RequestCollectionBindingUpsert",
    "RequestCollectionCreate",
    "RequestCollectionEnvironmentCreate",
    "RequestCollectionSelect",
    "RequestCollectionSelectionUpsert",
    "configure_request_collection_router",
    "request_collection_selector",
    "router",
    "select_request_collection_index_rows",
]
