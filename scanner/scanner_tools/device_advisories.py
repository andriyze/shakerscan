"""Offline connected-device advisory matching for compact CPE-native snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.parse
from dataclasses import dataclass
from typing import Any


MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
BUNDLED_SNAPSHOT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "device_advisories.json",
)
BUNDLED_SNAPSHOT_SHA256 = "3c9c66b400f2fe2d931066d9f92fd2cbb3de5030e50ec1570eef0fc018cdfb0a"


def load_verified_snapshot(
    path: Any, expected_sha256: Any, *, max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Load a regular, no-symlink advisory snapshot only when its pinned digest matches."""
    location = str(path or "").strip()
    expected = str(expected_sha256 or "").strip().lower()
    if not location and not expected:
        location = BUNDLED_SNAPSHOT_PATH
        expected = BUNDLED_SNAPSHOT_SHA256
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


@dataclass(frozen=True)
class _CPEComponent:
    value: str
    wildcard: bool = False
    not_applicable: bool = False


def _split_cpe23_components(value: str) -> list[str]:
    """Split a formatted CPE while preserving escaped delimiters for normalization."""
    components: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    components.append("".join(current))
    return components


def _cpe_component(raw: Any, *, uri_binding: bool = False) -> _CPEComponent:
    value = urllib.parse.unquote(str(raw or "")) if uri_binding else str(raw or "")
    if value == "*":
        return _CPEComponent("", wildcard=True)
    if value == "-":
        return _CPEComponent("", not_applicable=True)
    if not uri_binding:
        value = re.sub(r"\\(.)", r"\1", value)
    return _CPEComponent(value.strip().lower())


def _cpe_identity(value: Any) -> tuple[_CPEComponent, _CPEComponent, _CPEComponent, _CPEComponent] | None:
    """Return part/vendor/product/version without collapsing CPE wildcard semantics."""
    text = str(value or "").strip()
    if text.startswith("cpe:2.3:"):
        components = _split_cpe23_components(text[len("cpe:2.3:"):])
        if len(components) >= 4:
            return tuple(_cpe_component(item) for item in components[:4])  # type: ignore[return-value]
    # Retain compatibility with the still-common CPE 2.2 URI binding.
    if text.startswith("cpe:/"):
        components = text[5:].split(":")
        if len(components) >= 3:
            padded = (components + [""])[:4]
            return tuple(_cpe_component(item, uri_binding=True) for item in padded)  # type: ignore[return-value]
    return None


def _concrete_identity_matches(
    query: tuple[_CPEComponent, ...], advisory: tuple[_CPEComponent, ...],
) -> bool:
    # A high-confidence software identity requires the same concrete CPE part, vendor, and
    # product. Wildcards remain useful for version evaluation but cannot erase the application /
    # operating-system boundary or manufacture an exact product claim.
    return all(
        not left.wildcard and not left.not_applicable
        and not right.wildcard and not right.not_applicable
        and bool(left.value) and left.value == right.value
        for left, right in zip(query[:3], advisory[:3])
    )


def match_advisories(
    records: Any, *, cpe: str | None, product: str | None, version: str | None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    query_cpe = str(cpe or "").strip()
    query_identity = _cpe_identity(query_cpe)
    query_product = str(product or "").strip().lower()
    query_version = str(version or "").strip()
    if not query_version and query_identity:
        identity_version = query_identity[3]
        if not identity_version.wildcard and not identity_version.not_applicable:
            query_version = identity_version.value
    matches: list[dict[str, Any]] = []
    for raw in list(records or [])[:100_000]:
        if not isinstance(raw, dict):
            continue
        advisory_cpe = str(raw.get("cpe") or "").strip()
        advisory_identity = _cpe_identity(advisory_cpe)
        exact_identity = bool(
            query_identity and advisory_identity
            and _concrete_identity_matches(query_identity, advisory_identity)
        )
        heuristic_identity = bool(
            not exact_identity and query_product
            and query_product == str(raw.get("product") or "").strip().lower()
        )
        if not exact_identity and not heuristic_identity:
            continue
        evaluation_record = raw
        if advisory_identity and not any(
            raw.get(key) not in (None, "") for key in (
                "version", "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            )
        ):
            advisory_version = advisory_identity[3]
            if not advisory_version.wildcard and not advisory_version.not_applicable and advisory_version.value:
                evaluation_record = {**raw, "version": advisory_version.value}
        affected = version_in_range(query_version, evaluation_record)
        if affected is False:
            continue
        has_version_constraint = any(
            evaluation_record.get(key) not in (None, "", "*", "-") for key in (
                "version", "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            )
        )
        exact_and_bounded = (
            exact_identity and affected is True and bool(query_version) and has_version_constraint
        )
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
                    key: evaluation_record.get(key) for key in (
                    "version", "version_start_including", "version_start_excluding",
                    "version_end_including", "version_end_excluding",
                ) if evaluation_record.get(key) not in (None, "")
            },
        })
        if len(matches) >= max(1, min(int(limit), 200)):
            break
    return matches
