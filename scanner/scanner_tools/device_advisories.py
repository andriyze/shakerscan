"""Offline connected-device advisory matching for compact CPE-native snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from typing import Any


MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


def load_verified_snapshot(
    path: Any, expected_sha256: Any, *, max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Load a regular, no-symlink advisory snapshot only when its pinned digest matches."""
    location = str(path or "").strip()
    expected = str(expected_sha256 or "").strip().lower()
    if not location:
        return {"status": "not_configured", "advisories": []}
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        return {"status": "untrusted_snapshot", "advisories": [], "error": "sha256_required"}
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(location, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return {"status": "unavailable", "advisories": [], "error": "not_regular_file"}
        if before.st_size > max(1, int(max_bytes)):
            return {
                "status": "snapshot_too_large", "advisories": [],
                "size_bytes": before.st_size, "max_bytes": max_bytes,
            }
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            return {"status": "unavailable", "advisories": [], "error": "snapshot_changed_during_read"}
        if len(raw) > max_bytes:
            return {"status": "snapshot_too_large", "advisories": [], "size_bytes": len(raw), "max_bytes": max_bytes}
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            return {
                "status": "integrity_mismatch", "advisories": [],
                "expected_sha256": expected, "actual_sha256": actual,
            }
        decoded = json.loads(bytes(raw).decode("utf-8"))
        records = decoded if isinstance(decoded, list) else decoded.get("advisories", []) if isinstance(decoded, dict) else []
        records = [item for item in records if isinstance(item, dict)][:100_000]
        return {
            "status": "available", "advisories": records,
            "snapshot_sha256": actual, "record_count": len(records),
            "generated_at": decoded.get("generated_at") if isinstance(decoded, dict) else None,
        }
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "advisories": [], "error": type(exc).__name__}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _version_parts(value: Any) -> tuple[tuple[int, Any], ...]:
    text = str(value or "").strip().lower()
    parts: list[tuple[int, Any]] = []
    for token in re.findall(r"\d+|[a-z]+", text):
        parts.append((1, int(token)) if token.isdigit() else (0, token))
    return tuple(parts)


def compare_versions(left: Any, right: Any) -> int:
    """Compare common embedded-firmware versions without claiming full vendor semantics."""
    a, b = list(_version_parts(left)), list(_version_parts(right))
    width = max(len(a), len(b))
    a.extend([(1, 0)] * (width - len(a)))
    b.extend([(1, 0)] * (width - len(b)))
    return (a > b) - (a < b)


def version_in_range(version: Any, advisory: dict[str, Any]) -> bool | None:
    current = str(version or "").strip()
    exact = str(advisory.get("version") or "").strip()
    bounds = {
        "start_including": advisory.get("version_start_including"),
        "start_excluding": advisory.get("version_start_excluding"),
        "end_including": advisory.get("version_end_including"),
        "end_excluding": advisory.get("version_end_excluding"),
    }
    if exact and exact not in {"*", "-"}:
        return compare_versions(current, exact) == 0 if current else None
    if not any(value not in (None, "") for value in bounds.values()):
        return True if current else None
    if not current:
        return None
    if bounds["start_including"] not in (None, "") and compare_versions(current, bounds["start_including"]) < 0:
        return False
    if bounds["start_excluding"] not in (None, "") and compare_versions(current, bounds["start_excluding"]) <= 0:
        return False
    if bounds["end_including"] not in (None, "") and compare_versions(current, bounds["end_including"]) > 0:
        return False
    if bounds["end_excluding"] not in (None, "") and compare_versions(current, bounds["end_excluding"]) >= 0:
        return False
    return True


def _cpe_identity(value: Any) -> tuple[str, str, str] | None:
    text = str(value or "").strip()
    parts = text.split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].lower(), parts[4].lower(), parts[5]
    # Retain compatibility with the still-common CPE 2.2 URI binding.
    if text.startswith("cpe:/"):
        uri_parts = text[5:].split(":")
        if len(uri_parts) >= 3:
            return uri_parts[1].lower(), uri_parts[2].lower(), uri_parts[3] if len(uri_parts) > 3 else ""
    return None


def match_advisories(
    records: Any, *, cpe: str | None, product: str | None, version: str | None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query_cpe = str(cpe or "").strip()
    query_identity = _cpe_identity(query_cpe)
    query_product = str(product or "").strip().lower()
    query_version = str(version or "").strip() or (query_identity[2] if query_identity else "")
    matches: list[dict[str, Any]] = []
    for raw in list(records or [])[:100_000]:
        if not isinstance(raw, dict):
            continue
        advisory_cpe = str(raw.get("cpe") or "").strip()
        advisory_identity = _cpe_identity(advisory_cpe)
        exact_identity = bool(
            query_identity and advisory_identity
            and query_identity[:2] == advisory_identity[:2]
        )
        heuristic_identity = bool(
            not exact_identity and query_product
            and query_product == str(raw.get("product") or "").strip().lower()
        )
        if not exact_identity and not heuristic_identity:
            continue
        affected = version_in_range(query_version, raw)
        if affected is False:
            continue
        exact_and_bounded = exact_identity and affected is True and bool(query_version)
        matches.append({
            "advisory_id": str(raw.get("advisory_id") or raw.get("cve") or "")[:100],
            "title": str(raw.get("title") or "")[:500],
            "severity": str(raw.get("severity") or "unknown")[:30],
            "reference": str(raw.get("reference") or "")[:1000],
            "match_type": "exact_cpe_version_range" if exact_and_bounded else (
                "exact_cpe_version_unknown" if exact_identity else "heuristic_product"
            ),
            "version_evaluation": "affected" if affected is True else "unknown",
            "confidence": "high" if exact_and_bounded else ("medium" if exact_identity else "low"),
            "proof_basis": "advisory_matched" if exact_and_bounded else "signal_only",
            "promotable": exact_and_bounded,
            "version_range": {
                key: raw.get(key) for key in (
                    "version", "version_start_including", "version_start_excluding",
                    "version_end_including", "version_end_excluding",
                ) if raw.get(key) not in (None, "")
            },
        })
        if len(matches) >= max(1, min(int(limit), 200)):
            break
    return matches
