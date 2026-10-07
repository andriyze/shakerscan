"""Record a Scan's own subdomain discovery the way the Targets page records its discovery.

The Scan option "Discover subdomains" ran the bounded ``subdomains.discover`` capability and its
names reached only the endpoint manifest, where they were out of the scan's origin scope: the
action reported success while no report section, discovery run or target named a single host.
The finalizer now lists the names in ``report.discovery.subdomains``; this module turns that list
into the same durable state the Targets-page discovery produces -- a ``discovery_runs`` row and
DNS-checked targets -- and writes the outcome back into the report section.

It never widens a Scan: the names become targets for their own, separately authorized scans.
"""

from __future__ import annotations

import json
from typing import Any, Mapping
import uuid

try:  # Preserve one module identity under api.scan.* host imports.
    from .. import target_resolution
except (ImportError, ModuleNotFoundError):  # top-level scan.* worker imports
    import target_resolution


DISCOVERY_SOURCE = "subfinder"


async def record_scan_subdomain_discovery(
    pool: Any,
    report: Mapping[str, Any],
    *,
    scan_id: str,
    plan_targets: Any = None,
) -> dict[str, Any] | None:
    """Store the report's discovered subdomains as a discovery run and targets.

    Idempotent per Scan: a redelivered job finds its own run and reports it again instead of
    recording a second one. Returns the outcome it wrote into the report section, or None when
    the report lists no subdomains.
    """
    discovery = report.get("discovery") if isinstance(report, Mapping) else None
    section = discovery.get("subdomains") if isinstance(discovery, Mapping) else None
    if not isinstance(section, dict) or not section.get("hosts"):
        return None
    hosts = [str(host) for host in section.get("hosts") or () if str(host or "").strip()]
    root_domain = str(section.get("root_domain") or "").strip().lower()
    if not root_domain:
        outcome = {"status": "not_recorded", "reason": "ambiguous_root_domain"}
        section["targets"] = outcome
        return outcome
    planner = plan_targets or target_resolution.plan_discovered_targets
    try:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow(
                """SELECT id, sources_used FROM discovery_runs
                    WHERE sources_used->>'scan_id' = $1
                    ORDER BY created_at LIMIT 1""",
                str(scan_id),
            )
        if existing is not None:
            sources = existing["sources_used"]
            if isinstance(sources, str):
                sources = json.loads(sources)
            resolution = dict((sources or {}).get("dns_resolution") or {})
            discovery_id = str(existing["id"])
        else:
            # DNS before a connection is taken, as the Targets-page job does, so a slow resolver
            # never holds one. Only names with an address record become targets.
            plan = await planner(hosts)
            discovery_id = str(uuid.uuid4())
            # No transaction: store_discovered_targets tolerates one refused row, which an
            # enclosing transaction would turn into an aborted run.
            async with pool.acquire() as conn:
                resolution = await target_resolution.store_discovered_targets(
                    conn, plan, root_domain, source=DISCOVERY_SOURCE,
                )
                await conn.execute(
                    """INSERT INTO discovery_runs
                           (id, root_domain, status, subdomains_found, new_subdomains,
                            result, sources_used, started_at, completed_at)
                       VALUES ($1, $2, 'completed', $3, $4, $5::jsonb, $6::jsonb, NOW(), NOW())""",
                    uuid.UUID(discovery_id), root_domain, len(hosts),
                    int(resolution.get("added") or 0), json.dumps(hosts),
                    json.dumps({
                        DISCOVERY_SOURCE: len(hosts),
                        "scan_id": str(scan_id),
                        "dns_resolution": resolution,
                    }),
                )
    except Exception as exc:  # noqa: BLE001 -- recording must not fail the finished scan
        outcome = {"status": "failed", "error": type(exc).__name__}
        section["targets"] = outcome
        return outcome
    outcome = {
        "status": "recorded",
        "discovery_id": discovery_id,
        "added": int(resolution.get("added") or 0),
        "scannable": int(resolution.get("scannable") or 0),
        "unresolved_count": int(resolution.get("unresolved_count") or 0),
    }
    section["targets"] = outcome
    return outcome


__all__ = ["record_scan_subdomain_discovery"]
