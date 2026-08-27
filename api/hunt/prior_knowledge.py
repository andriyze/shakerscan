"""Summarise what a Hunt already knows about its target before it probes anything.

A Hunt's context pack described the target, the policy and the budget, but said nothing about
the durable knowledge the deployment had already accumulated for that same target: the endpoint
inventory built by prior DAST/ASM scans, the findings those scans produced, and which of those
findings are already deterministically verified. All of it was reachable through
``POST /hunts/{id}/query``, but an agent planning from the context pack had no way to know it was
there, so it re-derived the attack surface from scratch and could re-hunt a bug the deployment
had already proven.

This module produces a compact, secret-free census of that knowledge, embedded in the context
pack as ``prior_knowledge``. It is a signpost, not a data dump: counts and the query needed to
read the rows, so the agent can decide to spend a query instead of a crawl. ``untested`` marks
the frontier worth spending budget on; ``already_verified`` marks work that is finished.
"""

from __future__ import annotations

from typing import Any, Mapping


SCHEMA_VERSION = "hunt-prior-knowledge/v1"

# A Hunt that re-derives a surface the deployment already inventoried spends its budget twice.
_GUIDANCE = (
    "Prior scans already populated this target's knowledge base. Query it with "
    "POST /hunts/{hunt_id}/query before spending crawl or discovery budget: kind='endpoints' "
    "returns the inventoried surface ranked by priority_score with param_shape, auth_state and "
    "test_status; kind='findings' returns what earlier runs already reported, including which "
    "are deterministically verified. Endpoints marked untested are the unexplored frontier; "
    "findings whose last_verification_verdict is 'exploited' are already proven and need no "
    "further hunting. Narrow either with the filter object: endpoints accept test_status, "
    "auth_state, method and path_contains; findings accept status, severity and verified_only."
)


def _counts(rows: Any, key: str) -> dict[str, int]:
    """Fold asyncpg count-by rows into a plain label -> count mapping."""
    out: dict[str, int] = {}
    for row in rows or []:
        label = str(dict(row).get(key) or "unknown")
        out[label] = int(dict(row).get("count") or 0)
    return out


def unavailable(reason: str) -> dict[str, Any]:
    """Return a census that states it could not be built.

    The census is advisory: a Hunt must still launch when the knowledge base cannot be read. It
    must not, however, silently look like an empty one -- an agent told there are zero endpoints
    would skip the query entirely and crawl from scratch, which is the exact waste this block
    exists to prevent. ``available`` separates "nothing known yet" from "could not ask".
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "available": False,
        "reason": reason,
        "guidance": (
            "This census could not be built, which does not mean the knowledge base is empty. "
            "Query it directly with POST /hunts/{hunt_id}/query before assuming the target is "
            "unexplored."
        ),
    }


async def web_prior_knowledge(conn: Any, target_id: Any) -> dict[str, Any]:
    """Census the durable knowledge held for one web/API/network target."""
    endpoints_by_state = await conn.fetch(
        "SELECT auth_state, count(*) AS count FROM target_endpoints "
        "WHERE target_id=$1 GROUP BY auth_state",
        target_id,
    )
    endpoints_by_status = await conn.fetch(
        "SELECT test_status, count(*) AS count FROM target_endpoints "
        "WHERE target_id=$1 GROUP BY test_status",
        target_id,
    )
    findings_by_severity = await conn.fetch(
        "SELECT severity, count(*) AS count FROM findings "
        "WHERE target_id=$1 AND status='active' GROUP BY severity",
        target_id,
    )
    verified = await conn.fetchval(
        "SELECT count(*) FROM findings WHERE target_id=$1 AND status='active' "
        "AND last_verification_verdict='exploited'",
        target_id,
    )
    last_scan = await conn.fetchrow(
        "SELECT id, completed_at FROM scans WHERE target_id=$1 AND status='completed' "
        "ORDER BY completed_at DESC NULLS LAST LIMIT 1",
        target_id,
    )
    candidates_open = await conn.fetchval(
        "SELECT count(*) FROM investigation_candidates WHERE target_id=$1 "
        "AND COALESCE(status,'') NOT IN ('verified', 'refuted', 'withdrawn')",
        target_id,
    )
    by_status = _counts(endpoints_by_status, "test_status")
    by_severity = _counts(findings_by_severity, "severity")
    return _pack(
        endpoint_total=sum(_counts(endpoints_by_state, "auth_state").values()),
        endpoints_by_auth_state=_counts(endpoints_by_state, "auth_state"),
        endpoints_by_test_status=by_status,
        untested=by_status.get("untested", 0),
        findings_by_severity=by_severity,
        findings_active=sum(by_severity.values()),
        already_verified=int(verified or 0),
        open_candidates=int(candidates_open or 0),
        last_scan=last_scan,
    )


async def device_prior_knowledge(conn: Any, device_target_id: Any) -> dict[str, Any]:
    """Census the durable knowledge held for one connected-device target."""
    services = await conn.fetchval(
        "SELECT count(*) FROM device_services WHERE device_target_id=$1 AND state='open'",
        device_target_id,
    )
    findings_by_severity = await conn.fetch(
        "SELECT severity, count(*) AS count FROM findings "
        "WHERE device_target_id=$1 AND status='active' GROUP BY severity",
        device_target_id,
    )
    verified = await conn.fetchval(
        "SELECT count(*) FROM findings WHERE device_target_id=$1 AND status='active' "
        "AND last_verification_verdict='exploited'",
        device_target_id,
    )
    last_scan = await conn.fetchrow(
        "SELECT id, completed_at FROM scans WHERE device_target_id=$1 AND status='completed' "
        "ORDER BY completed_at DESC NULLS LAST LIMIT 1",
        device_target_id,
    )
    by_severity = _counts(findings_by_severity, "severity")
    pack = _pack(
        endpoint_total=0,
        endpoints_by_auth_state={},
        endpoints_by_test_status={},
        untested=0,
        findings_by_severity=by_severity,
        findings_active=sum(by_severity.values()),
        already_verified=int(verified or 0),
        open_candidates=0,
        last_scan=last_scan,
    )
    pack.pop("endpoints", None)
    pack["open_services"] = int(services or 0)
    return pack


def _pack(
    *,
    endpoint_total: int,
    endpoints_by_auth_state: Mapping[str, int],
    endpoints_by_test_status: Mapping[str, int],
    untested: int,
    findings_by_severity: Mapping[str, int],
    findings_active: int,
    already_verified: int,
    open_candidates: int,
    last_scan: Any,
) -> dict[str, Any]:
    """Shape one census. Counts only -- never rows, URLs, payloads or secret material."""
    completed_at = None
    scan_id = None
    if last_scan is not None:
        row = dict(last_scan)
        scan_id = str(row.get("id")) if row.get("id") else None
        completed_at = row.get("completed_at")
        completed_at = completed_at.isoformat() if hasattr(completed_at, "isoformat") else None
    return {
        "schema_version": SCHEMA_VERSION,
        "available": True,
        "guidance": _GUIDANCE,
        "endpoints": {
            "total": endpoint_total,
            "untested": untested,
            "by_auth_state": dict(endpoints_by_auth_state),
            "by_test_status": dict(endpoints_by_test_status),
        },
        "findings": {
            "active": findings_active,
            "already_verified": already_verified,
            "by_severity": dict(findings_by_severity),
        },
        "open_candidates": open_candidates,
        "last_completed_scan": {"id": scan_id, "completed_at": completed_at},
        "query_kinds": [
            "endpoints", "findings", "candidates", "principals", "notes", "receipts",
            "hypotheses", "graph_nodes", "graph_edges",
        ],
    }


async def safe_prior_knowledge(conn: Any, target_id: Any, *, device: bool = False) -> dict[str, Any]:
    """Build a census, degrading to an explicit ``unavailable`` block rather than failing a Hunt."""
    builder = device_prior_knowledge if device else web_prior_knowledge
    try:
        return await builder(conn, target_id)
    except Exception as exc:  # noqa: BLE001 - advisory context must never block a Hunt launch
        # The type, not the message: this lands in a planner-visible context pack.
        return unavailable(type(exc).__name__)


__all__ = [
    "SCHEMA_VERSION",
    "device_prior_knowledge",
    "safe_prior_knowledge",
    "unavailable",
    "web_prior_knowledge",
]
