"""Retain admitted crawl candidates in the existing target endpoint inventory."""
from __future__ import annotations
from typing import Any, Mapping
from urllib.parse import urlsplit
import asm_inventory


def crawl_worklist(records: list[Mapping], *, origin: str) -> list[str]:
    def identity(value: str):
        url = urlsplit(value)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
            raise ValueError("invalid service URL")
        return url.scheme, url.hostname, url.port or (443 if url.scheme == "https" else 80)
    admitted = identity(origin)
    found = set()
    for record in records[:5000]:
        if record.get("kind") != "discovered_route":
            continue
        try:
            value = str(record.get("url") or "")
            if len(value) > 8000 or any(c.isspace() for c in value) or "\\" in value or identity(value) != admitted:
                continue
            parsed = urlsplit(value)
        except ValueError:
            continue
        method = str(record.get("method") or "GET").upper()
        if method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            found.add(f"{method} {parsed.path or '/'}" + ("?" + parsed.query if parsed.query else ""))
    return sorted(found)


async def enrich_crawl_endpoints(conn: Any, *, target: Any, origin: str,
                                 capability: str, input: dict, records: list) -> int:
    # The legacy endpoint inventory identifies paths within a web service. Avoid
    # collapsing different network-service ports into one path-only inventory.
    if target.target_kind not in {"web", "api"} or capability not in {"web.crawl", "web.browser_crawl"}:
        return 0
    worklist = crawl_worklist(records, origin=origin)
    return await asm_inventory.upsert_endpoints(conn, target.target_id, worklist,
        source="hunt_discovery", auth_state=str(input.get("as_principal") or "anonymous"))
