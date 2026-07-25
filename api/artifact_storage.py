"""Central scan-artifact storage and durable manifest helpers.

Object keys are deterministic per scan/shard/type. Re-delivery therefore
overwrites the same logical object and the manifest upsert stays idempotent.
The content hash in Postgres is verified before an API response is served.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from typing import Any
import urllib.error
import uuid

from evidence_storage import _s3_config, _s3_request


LOCAL_PREFIX = "local:scan_artifacts/"
S3_PREFIX = "s3:scan_artifacts/"
VALID_ARTIFACT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
DEFAULT_RETENTION_DAYS = {
    "checkpoint": 14,
    "diagnostic": 30,
    "screenshot": 90,
    "attachment": 90,
    "result": 365,
}


class ArtifactStorageError(RuntimeError):
    """The artifact plane could not durably persist or verify an object."""


def _truthy(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def backend() -> str:
    return str(
        os.environ.get("ARTIFACT_STORAGE_BACKEND")
        or os.environ.get("EVIDENCE_STORAGE_BACKEND")
        or "local"
    ).strip().lower()


def remote_enabled() -> bool:
    return backend() in {"s3", "minio", "s3-compatible", "s3_compatible"}


def remote_required() -> bool:
    """Joined nodes fail closed unless an operator explicitly opts out.

    A local all-in-one install is intentionally still useful without MinIO.
    Worker-only fleet containers always receive SHAKERSCAN_NODE_ID, which makes
    remote durability the safe default for cross-host execution.
    """
    configured = os.environ.get("ARTIFACT_STORAGE_REQUIRED")
    if configured is not None:
        return _truthy("ARTIFACT_STORAGE_REQUIRED")
    return bool(str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip())


def retention_days(artifact_type: str) -> int | None:
    specific = f"ARTIFACT_RETENTION_{str(artifact_type).upper()}_DAYS"
    raw = os.environ.get(specific)
    if raw is None:
        raw = os.environ.get("ARTIFACT_RETENTION_DAYS")
    if raw is None:
        return DEFAULT_RETENTION_DAYS.get(str(artifact_type), 90)
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS.get(str(artifact_type), 90)
    # Zero is the explicit keep-forever setting.
    return None if days <= 0 else days


def _safe_component(value: Any, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip()).strip(".-")
    return cleaned[:96] or fallback


def object_key(
    *,
    scan_id: str,
    artifact_type: str,
    shard_index: int | None = None,
    filename: str | None = None,
) -> str:
    if not VALID_ARTIFACT_TYPE.fullmatch(str(artifact_type or "")):
        raise ValueError("invalid artifact_type")
    scan = str(uuid.UUID(str(scan_id)))
    shard = "standalone" if shard_index is None else f"shard-{int(shard_index)}"
    leaf = _safe_component(filename, f"{artifact_type}.bin")
    cfg = _s3_config(namespace="ARTIFACT")
    relative = f"{scan}/{shard}/{artifact_type}/{leaf}"
    return f"{cfg['prefix']}/{relative}" if cfg["prefix"] else relative


def _local_relative(scan_id: str, artifact_type: str, shard_index: int | None, filename: str | None) -> Path:
    key = object_key(
        scan_id=scan_id,
        artifact_type=artifact_type,
        shard_index=shard_index,
        filename=filename,
    )
    cfg = _s3_config(namespace="ARTIFACT")
    prefix = str(cfg.get("prefix") or "").strip("/")
    if prefix and key.startswith(prefix + "/"):
        key = key[len(prefix) + 1 :]
    return Path(key)


def _storage_uri(bucket: str, key: str) -> str:
    return f"{S3_PREFIX}{bucket}/{key.lstrip('/')}"


def parse_s3_uri(storage_uri: str) -> tuple[str, str] | None:
    if not str(storage_uri or "").startswith(S3_PREFIX):
        return None
    remainder = storage_uri[len(S3_PREFIX) :]
    bucket, sep, key = remainder.partition("/")
    key_path = Path(key)
    if not sep or not bucket or not key or key_path.is_absolute() or ".." in key_path.parts:
        return None
    return bucket, key


def local_path(results_dir: Path, storage_uri: str) -> Path | None:
    if not str(storage_uri or "").startswith(LOCAL_PREFIX):
        return None
    relative = Path(storage_uri[len(LOCAL_PREFIX) :])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return results_dir / "scan-artifacts" / relative


def store_bytes(
    data: bytes,
    *,
    results_dir: Path,
    scan_id: str,
    artifact_type: str,
    shard_index: int | None = None,
    filename: str | None = None,
    content_type: str = "application/octet-stream",
) -> dict[str, Any]:
    raw = bytes(data)
    sha = hashlib.sha256(raw).hexdigest()
    key = object_key(
        scan_id=scan_id,
        artifact_type=artifact_type,
        shard_index=shard_index,
        filename=filename,
    )
    if remote_enabled():
        cfg = _s3_config(namespace="ARTIFACT")
        if not cfg["bucket"]:
            raise ArtifactStorageError("ARTIFACT_S3_BUCKET or EVIDENCE_S3_BUCKET is required")
        try:
            _s3_request("PUT", cfg["bucket"], key, body=raw, content_type=content_type, config=cfg)
        except Exception as exc:
            if remote_required():
                raise ArtifactStorageError(f"remote artifact upload failed ({type(exc).__name__})") from exc
        else:
            return {
                "storage_uri": _storage_uri(cfg["bucket"], key),
                "storage_backend": "s3",
                "content_sha256": sha,
                "size_bytes": len(raw),
                "content_type": content_type,
                "status": "available",
            }
    elif remote_required():
        raise ArtifactStorageError("fleet worker requires ARTIFACT_STORAGE_BACKEND=s3")

    relative = _local_relative(scan_id, artifact_type, shard_index, filename)
    path = results_dir / "scan-artifacts" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, path)
    return {
        "storage_uri": f"{LOCAL_PREFIX}{relative.as_posix()}",
        "storage_backend": "local",
        "content_sha256": sha,
        "size_bytes": len(raw),
        "content_type": content_type,
        "status": "available",
    }


def store_json(value: Any, **kwargs: Any) -> dict[str, Any]:
    raw = json.dumps(value, sort_keys=True, default=str, indent=2).encode("utf-8")
    return store_bytes(raw, content_type="application/json", **kwargs)


def read_bytes(*, results_dir: Path, storage_uri: str, expected_sha256: str | None = None) -> bytes:
    parsed = parse_s3_uri(storage_uri)
    try:
        if parsed:
            bucket, key = parsed
            raw = _s3_request("GET", bucket, key, config=_s3_config(namespace="ARTIFACT"))
        else:
            path = local_path(results_dir, storage_uri)
            if path is None or not path.is_file() or path.is_symlink():
                raise FileNotFoundError("artifact object is missing")
            raw = path.read_bytes()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError("artifact object is missing") from exc
        raise ArtifactStorageError(f"remote artifact read failed (HTTP {exc.code})") from exc
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise ArtifactStorageError(f"artifact read failed ({type(exc).__name__})") from exc
    actual = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and actual != expected_sha256:
        raise ArtifactStorageError("artifact integrity mismatch")
    return raw


def delete_object(storage_uri: str, *, results_dir: Path) -> bool:
    parsed = parse_s3_uri(storage_uri)
    if parsed:
        bucket, key = parsed
        try:
            _s3_request("DELETE", bucket, key, config=_s3_config(namespace="ARTIFACT"))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise ArtifactStorageError(f"remote artifact delete failed (HTTP {exc.code})") from exc
        return True
    path = local_path(results_dir, storage_uri)
    if path is None:
        return False
    path.unlink(missing_ok=True)
    return True


def storage_health(*, results_dir: Path, write_probe: bool = False) -> dict[str, Any]:
    """Validate configuration and optionally exercise PUT/GET/DELETE."""
    if remote_enabled():
        cfg = _s3_config(namespace="ARTIFACT")
        missing = [name for name in ("bucket", "access_key", "secret_key") if not cfg.get(name)]
        if missing:
            return {"status": "error", "backend": "s3", "error": "missing_config"}
        if not write_probe:
            return {"status": "configured", "backend": "s3"}
        key = f"{cfg['prefix']}/.health/{uuid.uuid4().hex}" if cfg["prefix"] else f".health/{uuid.uuid4().hex}"
        payload = b"shakerscan-artifact-health-v1"
        try:
            _s3_request("PUT", cfg["bucket"], key, body=payload, content_type="application/octet-stream", config=cfg)
            received = _s3_request("GET", cfg["bucket"], key, config=cfg)
            if received != payload:
                raise ArtifactStorageError("artifact health probe integrity mismatch")
            _s3_request("DELETE", cfg["bucket"], key, config=cfg)
        except Exception as exc:
            return {"status": "error", "backend": "s3", "error": type(exc).__name__}
        return {"status": "ok", "backend": "s3", "write_probe": True}

    if remote_required():
        return {"status": "error", "backend": "local", "error": "remote_required"}
    if not write_probe:
        return {"status": "configured", "backend": "local"}
    try:
        directory = results_dir / "scan-artifacts" / ".health"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / uuid.uuid4().hex
        path.write_bytes(b"ok")
        path.unlink()
    except OSError as exc:
        return {"status": "error", "backend": "local", "error": type(exc).__name__}
    return {"status": "ok", "backend": "local", "write_probe": True}


def guess_content_type(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


async def upsert_manifest(
    conn: Any,
    *,
    scan_id: str,
    artifact_type: str,
    descriptor: dict[str, Any],
    artifact_key: str,
    parent_scan_id: str | None = None,
    shard_index: int | None = None,
    metadata: dict[str, Any] | None = None,
    executing_node_id: str | None = None,
) -> dict[str, Any]:
    node_id = (
        str(executing_node_id or "").strip()
        or str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip()
        or None
    )
    try:
        node_uuid = uuid.UUID(node_id) if node_id else None
    except ValueError:
        node_uuid = None
    days = retention_days(artifact_type)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=days)
        if days is not None
        else None
    )
    row = await conn.fetchrow(
        """
        INSERT INTO scan_artifacts (
            scan_id, parent_scan_id, shard_index, executing_node_id,
            artifact_type, artifact_key, content_type, storage_uri,
            storage_backend, content_sha256, size_bytes, status, metadata,
            expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
        )
        ON CONFLICT (scan_id, artifact_type, artifact_key) DO UPDATE SET
            parent_scan_id=EXCLUDED.parent_scan_id,
            shard_index=EXCLUDED.shard_index,
            executing_node_id=EXCLUDED.executing_node_id,
            content_type=EXCLUDED.content_type,
            storage_uri=EXCLUDED.storage_uri,
            storage_backend=EXCLUDED.storage_backend,
            content_sha256=EXCLUDED.content_sha256,
            size_bytes=EXCLUDED.size_bytes,
            status=EXCLUDED.status,
            metadata=EXCLUDED.metadata,
            expires_at=EXCLUDED.expires_at,
            updated_at=NOW(),
            deleted_at=NULL
        RETURNING *
        """,
        uuid.UUID(str(scan_id)),
        uuid.UUID(str(parent_scan_id)) if parent_scan_id else None,
        shard_index,
        node_uuid,
        artifact_type,
        artifact_key,
        descriptor.get("content_type"),
        descriptor.get("storage_uri"),
        descriptor.get("storage_backend"),
        descriptor.get("content_sha256"),
        int(descriptor.get("size_bytes") or 0),
        descriptor.get("status") or "available",
        json.dumps(metadata or {}),
        expires_at,
    )
    return dict(row)
