"""Offline connected-device advisory matching for compact CPE-native snapshots."""

from __future__ import annotations

import re
from typing import Any


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
