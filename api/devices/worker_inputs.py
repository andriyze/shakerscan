"""Worker-only hydration from canonical asset inputs; never a public secret API."""
from __future__ import annotations
from datetime import datetime
import hashlib
import json
from typing import Any
import uuid
try:
    from secret_store import decrypt_secret
except ModuleNotFoundError:
    from ..secret_store import decrypt_secret
from .shared_credentials import resolve_device_credential

async def hydrate_device_scan_credentials(options: dict[str, Any], scan_id: str, *, pool: Any, ssh_daily_cap: int, ssh_cooldown_seconds: int, utc_now: Any) -> dict[str, Any]:
    """Resolve device-bound credentials in worker memory without persisting secrets."""
    hydrated = dict(options or {})
    raw_refs = hydrated.get("device_credential_profiles")
    if not isinstance(raw_refs, list) or not raw_refs:
        return hydrated
    if str(hydrated.get("safety_profile") or "") != "authenticated_active":
        raise ValueError("device credentials require safety_profile=authenticated_active")
    refs = [dict(item) for item in raw_refs if isinstance(item, dict)][:2]
    roles = [str(item.get("role") or "") for item in refs]
    if len(roles) != len(set(roles)) or not all(role in {"ssh", "web"} for role in roles):
        raise ValueError("invalid device credential profile references")
    try:
        profile_ids = [uuid.UUID(str(item.get("profile_id") or "")) for item in refs]
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise ValueError("invalid device credential profile id") from exc
    async with pool.acquire() as conn:
        device_id = await conn.fetchval('SELECT device_target_id FROM scans WHERE id=$1', scan_uuid)
        if device_id is None:
            raise ValueError('Device scan target is unavailable')
        rows = await conn.fetch(
            """SELECT cp.id, cp.auth_kind, cp.username, cp.secret_value,
                      cp.login_path, cp.port
               FROM scans s
               JOIN device_credential_profiles cp ON cp.device_target_id=s.device_target_id
               WHERE s.id=$1 AND cp.id=ANY($2::uuid[]) AND cp.is_active=true
                 AND (cp.expires_at IS NULL OR cp.expires_at > NOW())""",
            scan_uuid,
            profile_ids,
        )
        attempt_rows = await conn.fetch(
            """WITH latest_success AS (
                   SELECT credential_profile_id, MAX(attempted_at) AS succeeded_at
                   FROM device_credential_attempts
                   WHERE credential_profile_id=ANY($1::uuid[]) AND outcome='succeeded'
                   GROUP BY credential_profile_id
               )
               SELECT a.credential_profile_id,
                      COUNT(*) FILTER (WHERE a.outcome IN ('rejected','error')) AS failure_count,
                      MAX(a.attempted_at) FILTER (WHERE a.outcome IN ('rejected','error')) AS last_failure_at
               FROM device_credential_attempts a
               LEFT JOIN latest_success s ON s.credential_profile_id=a.credential_profile_id
               WHERE a.credential_profile_id=ANY($1::uuid[])
                 AND a.attempted_at >= NOW() - INTERVAL '24 hours'
                 AND (s.succeeded_at IS NULL OR a.attempted_at > s.succeeded_at)
               GROUP BY a.credential_profile_id""",
            profile_ids,
        )
    by_id = {str(row["id"]): dict(row) for row in rows}
    attempts_by_id = {str(row["credential_profile_id"]): dict(row) for row in attempt_rows}
    resolved: list[dict[str, Any]] = []
    for ref in refs:
        role = str(ref["role"])
        profile_id = str(ref["profile_id"])
        row = by_id.get(profile_id)
        if row is None:
            raise ValueError(f"device {role} credential profile is unavailable")
        auth_kind = str(row.get("auth_kind") or "")
        if (role == "ssh") != auth_kind.startswith("ssh_"):
            raise ValueError(f"device {role} credential profile kind mismatch")
        if role == "ssh":
            attempt_state = attempts_by_id.get(profile_id, {})
            failure_count = int(attempt_state.get("failure_count") or 0)
            last_failure_at = attempt_state.get("last_failure_at")
            if failure_count >= ssh_daily_cap:
                raise ValueError("device SSH credential daily authentication failure cap is active")
            if last_failure_at:
                now = utc_now()
                if last_failure_at.tzinfo is None:
                    now = datetime.now()
                if (now - last_failure_at).total_seconds() < ssh_cooldown_seconds:
                    raise ValueError("device SSH credential authentication cooldown is active")
        async with pool.acquire() as conn:
            resolved.append(await resolve_device_credential(conn, device_id, ref))
    hydrated["_resolved_device_credentials"] = resolved
    return hydrated

async def hydrate_device_request_collections(options: dict[str, Any], scan_id: str, *, pool: Any) -> dict[str, Any]:
    """Resolve encrypted device-bound request documents only in worker memory."""
    hydrated = dict(options or {})
    refs = [dict(item) for item in hydrated.get("device_request_collections") or [] if isinstance(item, dict)][:8]
    if not refs:
        return hydrated
    if not hydrated.get("confirm_request_replay") or not hydrated.get("include_web_dast"):
        raise ValueError("imported device requests require confirmed Web DAST execution")
    try:
        collection_ids = [uuid.UUID(str(item.get("collection_id") or "")) for item in refs]
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise ValueError("invalid device request collection reference") from exc
    if len(collection_ids) != len(set(collection_ids)):
        raise ValueError("duplicate device request collection reference")
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT c.id, c.name, c.document_sha256, c.encrypted_payload
               FROM scans s
               JOIN device_request_collections c ON c.device_target_id=s.device_target_id
               WHERE s.id=$1 AND c.id=ANY($2::uuid[]) AND c.is_active=true""",
            scan_uuid, collection_ids,
        )
    by_id = {str(row["id"]): dict(row) for row in rows}
    resolved: list[dict[str, Any]] = []
    total_bytes = 0
    for ref in refs:
        collection_id = str(ref.get("collection_id") or "")
        row = by_id.get(collection_id)
        if row is None:
            raise ValueError("device request collection is unavailable")
        raw = str(decrypt_secret(row.get("encrypted_payload")) or "")
        if not raw or raw.startswith("enc:fernet:"):
            raise ValueError("device request collection could not be decrypted")
        total_bytes += len(raw.encode("utf-8"))
        if total_bytes > 7 * 1024 * 1024:
            raise ValueError("selected device request collections exceed the execution size limit")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("device request collection has an invalid encrypted payload") from exc
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        expected = str(ref.get("document_sha256") or row.get("document_sha256") or "")
        if digest != expected or digest != str(row.get("document_sha256") or ""):
            raise ValueError("device request collection integrity check failed")
        resolved.append({
            "collection_id": collection_id,
            "name": str(row.get("name") or ref.get("name") or "Imported requests"),
            "document_sha256": digest,
            "payload": payload,
        })
    hydrated["_resolved_device_request_collections"] = resolved
    return hydrated
