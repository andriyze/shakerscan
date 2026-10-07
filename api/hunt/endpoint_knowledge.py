"""Retain admitted crawl and content-discovery hits in the existing target endpoint inventory.

The inventory is shared target knowledge and an informational worklist, never authority. A
content-discovery hit enters it only when it differs from what the same run measured for paths
that cannot exist.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import asm_inventory

try:
    from scan.negative_control import (
        indistinguishable_from_absent,
        is_negative_control_url,
    )
    from scan.surface_manifest import wildcard_redirect_urls
except ModuleNotFoundError:  # package import in host-side tests
    from ..scan.negative_control import (
        indistinguishable_from_absent,
        is_negative_control_url,
    )
    from ..scan.surface_manifest import wildcard_redirect_urls

ENDPOINT_CAPABILITIES = frozenset({"web.crawl", "web.browser_crawl", "web.content_discover"})


def _identity(value: str):
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        raise ValueError("invalid service URL")
    return url.scheme, url.hostname, url.port or (443 if url.scheme == "https" else 80)


def _same_service_path(value: Any, admitted: tuple) -> str | None:
    try:
        text = str(value or "")
        if len(text) > 8000 or any(c.isspace() for c in text) or "\\" in text or _identity(text) != admitted:
            return None
        parsed = urlsplit(text)
    except ValueError:
        return None
    return (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")


def crawl_worklist(records: list[Mapping], *, origin: str) -> list[str]:
    admitted = _identity(origin)
    found = set()
    for record in records[:5000]:
        if record.get("kind") != "discovered_route":
            continue
        path = _same_service_path(record.get("url"), admitted)
        if path is None:
            continue
        method = str(record.get("method") or "GET").upper()
        if method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            found.add(f"{method} {path}")
    return sorted(found)


def content_discovery_worklist(records: list[Mapping], *, origin: str) -> list[str]:
    """GET hits that differ from a measured absent path and from a blanket origin redirect.

    A hit's only evidence is its status, so it is compared with the run's negative-control probes
    (paths that cannot exist) by status AND size, using the ASM inventory's soft-404 rule: an SPA
    catch-all 200 or a blanket 401/403 matches the controls and is not an endpoint. A run without
    a measured control cannot tell a hit from a catch-all, so it records nothing. The control
    probes themselves and an origin-wide rewrite are measurements, not endpoints.
    """
    admitted = _identity(origin)
    rows = [item for item in records[:5000] if isinstance(item, Mapping)
            and item.get("kind") == "content_discovery"]
    absent = [
        (item.get("status"), item.get("length"))
        for item in rows if is_negative_control_url(item.get("url"))
    ]
    if not absent:
        return []
    excluded = indistinguishable_from_absent(rows) | wildcard_redirect_urls(rows)
    found = set()
    for record in rows:
        url = str(record.get("url") or "")
        if is_negative_control_url(url) or url in excluded:
            continue
        verdict = asm_inventory.measured_not_found_verdict(
            record.get("status"), record.get("length"), absent,
        )
        if verdict != "reachable":
            continue
        path = _same_service_path(url, admitted)
        if path is not None:
            found.add(f"GET {path}")
    return sorted(found)


async def enrich_crawl_endpoints(conn: Any, *, target: Any, origin: str,
                                 capability: str, input: dict, records: list) -> int:
    # The legacy endpoint inventory identifies paths within a web service. Avoid
    # collapsing different network-service ports into one path-only inventory.
    if target.target_kind not in {"web", "api"} or capability not in ENDPOINT_CAPABILITIES:
        return 0
    worklist = (
        content_discovery_worklist(records, origin=origin)
        if capability == "web.content_discover"
        else crawl_worklist(records, origin=origin)
    )
    return await asm_inventory.upsert_endpoints(conn, target.target_id, worklist,
        source="hunt_discovery", auth_state=str(input.get("as_principal") or "anonymous"))

