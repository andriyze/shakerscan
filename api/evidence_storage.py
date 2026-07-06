"""Local evidence-object storage helpers.

The DB row remains the canonical index. Large redacted evidence payloads can be
stored beside result artifacts and referenced by content hash so API reads can
hydrate and verify them without changing finding truth.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


INLINE_STORAGE_URI = "inline:evidence_objects"
LOCAL_STORAGE_PREFIX = "local:evidence_objects/"
DEFAULT_INLINE_MAX_BYTES = 32_768


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
    }


def hydrate_evidence_content(row: dict[str, Any], *, results_dir: Path) -> dict[str, Any]:
    storage_uri = str(row.get("storage_uri") or "")
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
