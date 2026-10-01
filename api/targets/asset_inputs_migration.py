"""Retire device-only input stores without changing references or exposing secrets."""
from __future__ import annotations

import json
from typing import Any

from .asset_inputs_schema import INPUTS_MIGRATION, INPUTS_SCHEMA_SQL, INPUTS_VIEW_SQL
from .asset_migration import _retarget_foreign_keys


def object_value(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    return dict(value) if isinstance(value, dict) else {}


def collection_index(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Legacy summaries are already redacted. Retain only the shared public index fields."""
    try:
        from scanner_tools.request_collections import redacted_index
    except ModuleNotFoundError:
        from scanner.scanner_tools.request_collections import redacted_index
    indexed = []
    for ordinal, row in enumerate(summary.get("requests") or []):
        if not isinstance(row, dict):
            raise RuntimeError("legacy request index contains an invalid row")
        if "request_id" not in row:
            row = redacted_index([row])[0]
        if not row.get("request_id"):
            raise RuntimeError("legacy request index has no stable request id")
        indexed.append({
            key: row.get(key) for key in (
                "request_id", "folder", "name", "method", "redacted_url", "normalized_path",
                "body_mode", "auth_type", "tags", "content_type", "body_field_names",
                "safe_method", "supported",
            )
        } | {"ordinal": ordinal})
    return indexed


async def migrate_asset_inputs(conn: Any) -> None:
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", INPUTS_MIGRATION):
        return
    try:
        from runtime.credential_migration import sync_legacy_device_credential
    except ModuleNotFoundError:
        from api.runtime.credential_migration import sync_legacy_device_credential
    # Preserve the latest generic version when it is newer; the existing migration helper
    # validates stable IDs and handles any legacy write not synchronized before upgrade.
    profiles = await conn.fetch("SELECT id FROM device_credential_profiles ORDER BY id")
    for row in profiles:
        await sync_legacy_device_credential(conn, row["id"])
    await conn.execute(INPUTS_SCHEMA_SQL)
    await conn.execute("""UPDATE credential_profiles p SET service_port=d.port
        FROM device_credential_profiles d WHERE p.id=d.id""")
    await _retarget_foreign_keys(conn, "device_credential_profiles", "credential_profiles")
    collections = await conn.fetch("SELECT * FROM device_request_collections ORDER BY created_at,id")
    for legacy in collections:
        summary = object_value(legacy["summary_json"])
        index = collection_index(summary)
        existing = await conn.fetchrow("SELECT id,payload_sha256 FROM request_collections WHERE id=$1", legacy["id"])
        if existing:
            if str(existing["payload_sha256"]) != str(legacy["document_sha256"]):
                raise RuntimeError("device collection ID conflicts with a different shared collection")
            continue
        name = str(legacy["name"])
        if await conn.fetchval("SELECT 1 FROM request_collections WHERE target_id=$1 AND name=$2", legacy["device_target_id"], name):
            name = f"{name[:260]} (device {str(legacy['id'])[:8]})"
        metadata = {key: value for key, value in summary.items() if key != "requests"}
        metadata.update({"legacy_source": "device_request_collections", "environment_stored_separately": False})
        await conn.execute("""INSERT INTO request_collections (
            id,target_id,device_target_id,name,format,encrypted_payload,payload_sha256,
            request_count,safe_request_count,potentially_mutating_request_count,
            metadata_json,is_active,created_at,updated_at
        ) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
            legacy["id"],legacy["device_target_id"],name,legacy["format"],
            legacy["encrypted_payload"],legacy["document_sha256"],
            int(summary.get("request_count") or len(index)),
            sum(bool(row.get("safe_method")) for row in index),
            int(summary.get("state_changing_request_count") or sum(not row.get("safe_method") for row in index)),
            json.dumps(metadata),legacy["is_active"],legacy["created_at"],legacy["updated_at"])
        if index:
            await conn.executemany("""INSERT INTO request_collection_requests (
                collection_id,request_id,ordinal,folder,name,method,redacted_url,normalized_path,
                body_mode,auth_type,tags_json,content_type,body_field_names_json,safe_method,supported
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)""", [(
                legacy["id"],row["request_id"],row["ordinal"],row.get("folder"),row.get("name"),
                row.get("method") or "GET",row.get("redacted_url"),row.get("normalized_path") or "/",
                row.get("body_mode"),row.get("auth_type"),json.dumps(row.get("tags") or []),
                row.get("content_type"),json.dumps(row.get("body_field_names") or []),
                bool(row.get("safe_method")),row.get("supported") is not False,
            ) for row in index])
    await _retarget_foreign_keys(conn, "device_request_collections", "request_collections")
    await conn.execute("DROP TABLE device_credential_profiles; DROP TABLE device_request_collections")
    await conn.execute(INPUTS_VIEW_SQL)
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", INPUTS_MIGRATION)
