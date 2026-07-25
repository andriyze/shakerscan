"""Evidence-object storage helpers.

The DB row remains the canonical index. Large redacted evidence payloads can be
stored beside result artifacts or in an S3-compatible object store and referenced
by content hash so API reads can hydrate and verify them without changing finding
truth.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


INLINE_STORAGE_URI = "inline:evidence_objects"
LOCAL_STORAGE_PREFIX = "local:evidence_objects/"
S3_STORAGE_PREFIX = "s3:evidence_objects/"
DEFAULT_INLINE_MAX_BYTES = 32_768
DEFAULT_REMOTE_TIMEOUT_SECONDS = 15


def evidence_inline_max_bytes() -> int:
    try:
        configured = os.environ.get("EVIDENCE_INLINE_MAX_BYTES", str(DEFAULT_INLINE_MAX_BYTES))
        return max(0, int(configured))
    except (TypeError, ValueError):
        return DEFAULT_INLINE_MAX_BYTES


def serialize_evidence_content(content: Any) -> tuple[str | None, str | None, int]:
    if content is None:
        return None, None, 0
    raw = json.dumps(content, sort_keys=True, default=str)
    raw_bytes = raw.encode("utf-8", "ignore")
    return raw, hashlib.sha256(raw_bytes).hexdigest(), len(raw_bytes)


def _local_relative_path(content_sha256: str) -> Path:
    return Path(content_sha256[:2]) / f"{content_sha256}.json"


def _local_storage_uri(content_sha256: str) -> str:
    return f"{LOCAL_STORAGE_PREFIX}{_local_relative_path(content_sha256).as_posix()}"


def local_evidence_path(results_dir: Path, storage_uri: str) -> Path | None:
    if not storage_uri.startswith(LOCAL_STORAGE_PREFIX):
        return None
    relative = storage_uri[len(LOCAL_STORAGE_PREFIX):]
    rel_path = Path(relative)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        return None
    return results_dir / "evidence-objects" / rel_path


def _remote_backend() -> str:
    return str(os.environ.get("EVIDENCE_STORAGE_BACKEND") or "local").strip().lower()


def _s3_enabled() -> bool:
    return _remote_backend() in {"s3", "minio", "s3-compatible", "s3_compatible"}


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _remote_timeout_seconds() -> int:
    try:
        return max(1, int(os.environ.get("EVIDENCE_S3_TIMEOUT_SECONDS", str(DEFAULT_REMOTE_TIMEOUT_SECONDS))))
    except (TypeError, ValueError):
        return DEFAULT_REMOTE_TIMEOUT_SECONDS


def _s3_config(*, namespace: str = "EVIDENCE") -> dict[str, Any]:
    """Return S3 settings for evidence or general scan artifacts.

    Artifact-specific settings are optional; every ARTIFACT_S3_* value falls
    back to the established EVIDENCE_S3_* contract so existing MinIO/S3
    deployments become the shared object plane without duplicate credentials.
    """
    prefix = str(namespace or "EVIDENCE").strip().upper()

    def configured(name: str, fallback: str | None = None) -> str:
        value = os.environ.get(f"{prefix}_{name}")
        if value is None and fallback:
            value = os.environ.get(f"EVIDENCE_{fallback}")
        return str(value or "")

    endpoint = (configured("S3_ENDPOINT_URL", "S3_ENDPOINT_URL") or os.environ.get("AWS_ENDPOINT_URL_S3") or "").strip()
    default_path_style = bool(endpoint)
    timeout_value = configured("S3_TIMEOUT_SECONDS", "S3_TIMEOUT_SECONDS")
    try:
        timeout = max(1, int(timeout_value)) if timeout_value else _remote_timeout_seconds()
    except (TypeError, ValueError):
        timeout = _remote_timeout_seconds()
    configured_prefix = str(os.environ.get(f"{prefix}_S3_PREFIX") or "").strip().strip("/")
    return {
        "bucket": configured("S3_BUCKET", "S3_BUCKET").strip(),
        "prefix": configured_prefix or ("evidence-objects" if prefix == "EVIDENCE" else "scan-artifacts"),
        "endpoint": endpoint.rstrip("/"),
        "region": (configured("S3_REGION", "S3_REGION") or os.environ.get("AWS_REGION") or "us-east-1").strip() or "us-east-1",
        "access_key": (configured("S3_ACCESS_KEY_ID", "S3_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID") or "").strip(),
        "secret_key": configured("S3_SECRET_ACCESS_KEY", "S3_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY") or "",
        "session_token": configured("S3_SESSION_TOKEN", "S3_SESSION_TOKEN") or os.environ.get("AWS_SESSION_TOKEN") or "",
        "path_style": _env_bool(
            f"{prefix}_S3_FORCE_PATH_STYLE",
            _env_bool("EVIDENCE_S3_FORCE_PATH_STYLE", default_path_style),
        ),
        "timeout": timeout,
    }


def _s3_object_key(content_sha256: str) -> str:
    cfg = _s3_config()
    relative = _local_relative_path(content_sha256).as_posix()
    return f"{cfg['prefix']}/{relative}" if cfg["prefix"] else relative


def _s3_storage_uri(bucket: str, key: str) -> str:
    return f"{S3_STORAGE_PREFIX}{bucket}/{key.lstrip('/')}"


def _parse_s3_storage_uri(storage_uri: str) -> tuple[str, str] | None:
    if not storage_uri.startswith(S3_STORAGE_PREFIX):
        return None
    remainder = storage_uri[len(S3_STORAGE_PREFIX):]
    bucket, sep, key = remainder.partition("/")
    if not sep or not bucket or not key:
        return None
    key_path = Path(key)
    if key_path.is_absolute() or ".." in key_path.parts:
        return None
    return bucket, key


def _s3_url(bucket: str, key: str, cfg: dict[str, Any]) -> str:
    encoded_key = urllib.parse.quote(key.lstrip("/"), safe="/~")
    if cfg["endpoint"]:
        parsed = urllib.parse.urlparse(cfg["endpoint"])
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("EVIDENCE_S3_ENDPOINT_URL must include scheme and host")
        if cfg["path_style"]:
            return f"{cfg['endpoint']}/{urllib.parse.quote(bucket, safe='')}/{encoded_key}"
        return f"{parsed.scheme}://{urllib.parse.quote(bucket, safe='')}.{parsed.netloc}/{encoded_key}"
    region = cfg["region"]
    return f"https://{urllib.parse.quote(bucket, safe='')}.s3.{region}.amazonaws.com/{encoded_key}"


def _signing_key(secret_key: str, date_stamp: str, region: str) -> bytes:
    k_date = hmac.new(("AWS4" + secret_key).encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
    return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


def _s3_signed_headers(
    *,
    method: str,
    url: str,
    body: bytes,
    cfg: dict[str, Any],
    content_type: str | None = None,
) -> dict[str, str]:
    if not cfg["access_key"] or not cfg["secret_key"]:
        raise ValueError("S3 evidence storage requires access key and secret key")
    parsed = urllib.parse.urlparse(url)
    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {
        "host": parsed.netloc,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if cfg["session_token"]:
        headers["x-amz-security-token"] = str(cfg["session_token"])
    if content_type:
        headers["content-type"] = content_type

    canonical_headers = "".join(f"{name}:{str(headers[name]).strip()}\n" for name in sorted(headers))
    signed_headers = ";".join(sorted(headers))
    canonical_request = "\n".join([
        method.upper(),
        urllib.parse.quote(parsed.path or "/", safe="/~"),
        parsed.query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{cfg['region']}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(_signing_key(cfg["secret_key"], date_stamp, cfg["region"]), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        "AWS4-HMAC-SHA256 "
        f"Credential={cfg['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


def _s3_request(
    method: str,
    bucket: str,
    key: str,
    *,
    body: bytes = b"",
    content_type: str | None = None,
    config: dict[str, Any] | None = None,
) -> bytes:
    cfg = config or _s3_config()
    url = _s3_url(bucket, key, cfg)
    headers = _s3_signed_headers(method=method, url=url, body=body, cfg=cfg, content_type=content_type)
    request = urllib.request.Request(
        url,
        data=body if method.upper() in {"PUT", "POST"} else None,
        headers=headers,
        method=method.upper(),
    )
    with urllib.request.urlopen(request, timeout=cfg["timeout"]) as response:  # noqa: S310 - operator-configured evidence store
        return response.read()


def _store_s3_evidence(raw: str, content_sha256: str) -> dict[str, Any] | None:
    if not _s3_enabled():
        return None
    cfg = _s3_config()
    if not cfg["bucket"]:
        raise ValueError("EVIDENCE_S3_BUCKET is required when EVIDENCE_STORAGE_BACKEND=s3")
    key = _s3_object_key(content_sha256)
    _s3_request(
        "PUT",
        cfg["bucket"],
        key,
        body=raw.encode("utf-8"),
        content_type="application/json",
    )
    return {
        "storage_uri": _s3_storage_uri(cfg["bucket"], key),
        "externalized": True,
        "remote": True,
    }


def store_evidence_content(
    content: Any,
    *,
    results_dir: Path,
    inline_max_bytes: int | None = None,
) -> dict[str, Any]:
    raw, sha, size = serialize_evidence_content(content)
    if raw is None or sha is None:
        return {
            "content_sha256": None,
            "size_bytes": 0,
            "storage_uri": INLINE_STORAGE_URI,
            "content": None,
            "externalized": False,
        }

    max_inline = (
        evidence_inline_max_bytes()
        if inline_max_bytes is None
        else max(0, int(inline_max_bytes))
    )
    if size <= max_inline:
        return {
            "content_sha256": sha,
            "size_bytes": size,
            "storage_uri": INLINE_STORAGE_URI,
            "content": raw,
            "externalized": False,
        }

    remote_error: str | None = None
    try:
        remote = _store_s3_evidence(raw, sha)
    except Exception as exc:
        remote = None
        remote_error = f"{type(exc).__name__}: {exc}"
    if remote:
        return {
            "content_sha256": sha,
            "size_bytes": size,
            "storage_uri": remote["storage_uri"],
            "content": None,
            "externalized": True,
            "remote": True,
        }

    path = results_dir / "evidence-objects" / _local_relative_path(sha)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    tmp_path.write_text(raw, encoding="utf-8")
    os.replace(tmp_path, path)
    return {
        "content_sha256": sha,
        "size_bytes": size,
        "storage_uri": _local_storage_uri(sha),
        "content": None,
        "externalized": True,
        "remote_error": remote_error,
    }


def _hydrate_s3_evidence(row: dict[str, Any], storage_uri: str) -> dict[str, Any]:
    parsed = _parse_s3_storage_uri(storage_uri)
    row["storage_status"] = "remote"
    if parsed is None:
        row["storage_status"] = "invalid_uri"
        row["content"] = None
        return row
    bucket, key = parsed
    try:
        raw_bytes = _s3_request("GET", bucket, key)
    except urllib.error.HTTPError as exc:
        row["content"] = None
        row["storage_status"] = "missing" if exc.code == 404 else "remote_error"
        row["storage_error"] = f"HTTPError: {exc.code}"
        return row
    except Exception as exc:
        row["content"] = None
        row["storage_status"] = "remote_error"
        row["storage_error"] = f"remote evidence read failed ({type(exc).__name__})"
        return row
    sha = hashlib.sha256(raw_bytes).hexdigest()
    expected = str(row.get("content_sha256") or "")
    if expected and sha != expected:
        row["storage_integrity"] = "mismatch"
        row["content"] = None
        return row
    row["storage_integrity"] = "verified" if expected else "not_checked"
    row["content"] = raw_bytes.decode("utf-8", "replace")
    return row


def delete_remote_evidence_object(storage_uri: str) -> dict[str, Any]:
    """Delete an S3-compatible evidence object by storage URI.

    Retention sweeps use the DB row as the durable index. Returning a structured
    status lets the caller keep that row when the remote delete fails, so the
    object remains retryable instead of becoming an orphaned blob.
    """
    parsed = _parse_s3_storage_uri(str(storage_uri or ""))
    if parsed is None:
        return {
            "storage_uri": storage_uri,
            "storage_backend": "unknown",
            "status": "invalid_uri",
            "deleted": False,
            "retryable": False,
        }
    bucket, key = parsed
    try:
        _s3_request("DELETE", bucket, key)
        return {
            "storage_uri": storage_uri,
            "storage_backend": "s3",
            "bucket": bucket,
            "key": key,
            "status": "deleted",
            "deleted": True,
            "retryable": False,
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "storage_uri": storage_uri,
                "storage_backend": "s3",
                "bucket": bucket,
                "key": key,
                "status": "missing",
                "deleted": True,
                "retryable": False,
                "error": f"HTTPError: {exc.code}",
            }
        return {
            "storage_uri": storage_uri,
            "storage_backend": "s3",
            "bucket": bucket,
            "key": key,
            "status": "remote_error",
            "deleted": False,
            "retryable": True,
            "error": f"HTTPError: {exc.code}",
        }
    except Exception as exc:
        return {
            "storage_uri": storage_uri,
            "storage_backend": "s3",
            "bucket": bucket,
            "key": key,
            "status": "remote_error",
            "deleted": False,
            "retryable": True,
            "error": f"{type(exc).__name__}: {exc}",
        }


def hydrate_evidence_content(row: dict[str, Any], *, results_dir: Path) -> dict[str, Any]:
    storage_uri = str(row.get("storage_uri") or "")
    if storage_uri.startswith(S3_STORAGE_PREFIX):
        return _hydrate_s3_evidence(row, storage_uri)
    if not storage_uri.startswith(LOCAL_STORAGE_PREFIX):
        row.setdefault("storage_status", "inline")
        return row

    path = local_evidence_path(results_dir, storage_uri)
    row["storage_status"] = "external"
    if path is None:
        row["storage_status"] = "invalid_uri"
        row["content"] = None
        return row
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        row["storage_status"] = "missing"
        row["content"] = None
        return row

    sha = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    expected = str(row.get("content_sha256") or "")
    if not expected:
        # No stored hash to verify against (legacy object): return content but
        # mark it unverified rather than claiming integrity.
        row["storage_integrity"] = "not_checked"
        row["content"] = raw
    elif sha == expected:
        row["storage_integrity"] = "verified"
        row["content"] = raw
    else:
        # On-disk content does not match the recorded hash: withhold the tampered
        # bytes instead of serving them as if they were the real evidence.
        row["storage_integrity"] = "mismatch"
        row["content"] = None
    return row
