"""Propagate real observed object ids onto consumer/write routes.

Discovery concretizes templated routes with a static placeholder
(``/users/{id}`` -> ``/users/1`` in ``discovery.py``). On apps with
non-sequential identifiers (crAPI vehicles/orders, Juice Shop baskets) that
placeholder 404s, so the consumer route's SQLi/XSS/BOLA probes never reach the
vulnerable code path.

This module harvests the *real* object ids observed anywhere on a resource's
discovered surface and re-emits the resource's other routes (different methods
or sub-resources) using those ids — e.g. a vehicle uuid seen on
``GET /vehicle/<uuid>`` is applied to ``PUT /vehicle/1`` and
``GET /vehicle/1/location`` so a live object is actually exercised. Purely
additive (never drops endpoints), deduped, and capped.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any


# A concrete (already-resolved) object identifier segment. Templated segments
# ({id}, :id) are intentionally excluded — discovery resolves those upstream.
_CONCRETE_ID_RE = re.compile(
    r"^(?:"
    r"\d{1,18}"                                                              # numeric
    r"|[0-9a-fA-F]{24}"                                                       # mongo ObjectId
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # uuid
    r")$"
)

MAX_EXTRA_IDS_PER_RESOURCE = 2
MAX_TOTAL_PROPAGATED = 200


def _split_path(path: str) -> list[str]:
    return [seg for seg in str(path or "").split("/") if seg]


def _first_id_index(segments: list[str]) -> int:
    for index, segment in enumerate(segments):
        if _CONCRETE_ID_RE.match(segment):
            return index
    return -1


def _id_realness(object_id: str) -> int:
    """Rank ids by how likely they name a real object: uuid/objectid > big int > "1"."""
    if "-" in object_id or len(object_id) == 24:
        return 2
    if object_id.isdigit() and object_id != "1":
        return 1
    return 0  # the bare "1" placeholder (or similar) — never propagate outward


def _parse_path(raw: str) -> tuple[str, urllib.parse.ParseResult]:
    absolute = "://" in raw
    parsed = urllib.parse.urlparse(
        raw if absolute else "http://x" + (raw if raw.startswith("/") else "/" + raw)
    )
    return ("absolute" if absolute else "relative"), parsed


def _rebuild_url(raw: str, new_path: str) -> str:
    kind, parsed = _parse_path(str(raw or ""))
    if kind == "absolute":
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment)
        )
    return new_path + (f"?{parsed.query}" if parsed.query else "")


def enrich_endpoints_with_resource_ids(
    endpoints: list[dict[str, Any]],
    *,
    max_extra_per_resource: int = MAX_EXTRA_IDS_PER_RESOURCE,
    max_total: int = MAX_TOTAL_PROPAGATED,
) -> list[dict[str, Any]]:
    """Return ``endpoints`` plus consumer-route variants using real observed ids."""
    if not endpoints:
        return list(endpoints or [])

    parsed_meta: list[tuple[dict[str, Any], tuple[list[str], int, str] | None]] = []
    ids_by_collection: dict[str, list[str]] = {}
    existing_keys: set[tuple[str, str]] = set()

    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            parsed_meta.append((endpoint, None))
            continue
        raw = endpoint.get("url") or endpoint.get("path") or ""
        method = str(endpoint.get("method") or "GET").upper()
        _, parsed = _parse_path(str(raw))
        path = parsed.path or "/"
        existing_keys.add((method, path))
        segments = _split_path(path)
        id_index = _first_id_index(segments)
        if id_index < 0:
            parsed_meta.append((endpoint, None))
            continue
        collection = "/" + "/".join(segments[:id_index])
        bucket = ids_by_collection.setdefault(collection, [])
        if segments[id_index] not in bucket:
            bucket.append(segments[id_index])
        parsed_meta.append((endpoint, (segments, id_index, collection)))

    result = list(endpoints)
    added = 0
    added_keys: set[tuple[str, str]] = set()

    for endpoint, meta in parsed_meta:
        if added >= max_total or not meta:
            continue
        segments, id_index, collection = meta
        current = segments[id_index]
        candidates = [
            cid for cid in ids_by_collection.get(collection, [])
            if cid != current and _id_realness(cid) >= 1
        ]
        candidates.sort(key=lambda cid: -_id_realness(cid))
        method = str(endpoint.get("method") or "GET").upper()
        for cid in candidates[:max_extra_per_resource]:
            new_segments = list(segments)
            new_segments[id_index] = cid
            new_path = "/" + "/".join(new_segments)
            key = (method, new_path)
            if key in existing_keys or key in added_keys:
                continue
            variant = dict(endpoint)
            variant["url"] = _rebuild_url(str(endpoint.get("url") or endpoint.get("path") or ""), new_path)
            variant["source"] = "resource_id_propagation"
            result.append(variant)
            added_keys.add(key)
            added += 1
            if added >= max_total:
                break
    return result
