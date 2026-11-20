"""Authorization boundaries of the application graph that no Hunt has examined yet.

The application graph records auth-boundary edges: a route that produces an object for one
principal and a route another principal could reach it through. The coverage ledger records the
angles Hunts examined, by family and route. Until now nothing related the two, so "which
boundaries are still untested" had to be worked out by the planner.

This is that relation, computed when read: each boundary's consumer route is matched to the
latest authorization coverage on the same route across the target's Hunts. It is a worklist, not
a result: an untested boundary is not a vulnerability, and a boundary with coverage is only as
settled as the angle says. Nothing here grants authority or is proof.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Mapping

from .knowledge_dependencies import asset_scope, normalize_route

MAX_EDGES = 500
MAX_ANGLES = 5000
MAX_ROWS = 200
FILTERS = ("coverage", "path_contains")
#: Coverage families that examine who may reach an object or function.
AUTHZ_FAMILIES = frozenset({
    "bola", "idor", "bfla", "authz", "authorization", "access_control", "broken_access_control",
    "privilege_escalation", "mass_assignment",
})
#: The latest word on an angle: what it says about the boundary.
EXAMINED = frozenset({"negative", "candidate", "partial"})
IN_PROGRESS = frozenset({"planned", "testing", "blocked"})
STATES = ("untested", "in_progress", "examined")
HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class CoverageGapQueryError(ValueError):
    """A filter this report does not take, or a value outside its bounds."""


def _json(value: Any) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, Mapping) else {}


def route_of(node_key: Any) -> tuple[str | None, str | None]:
    """``(METHOD, route template)`` of a graph route key (``route:GET /api/orders/7``)."""
    label = str(node_key or "")
    if not label.startswith("route:"):
        return None, None
    method, _, path = label[len("route:"):].strip().partition(" ")
    if not path:
        method, path = "", method
    path = path.strip()
    if path.startswith(("http://", "https://")):
        path = "/" + path.split("://", 1)[1].partition("/")[2]
    route = normalize_route(path)
    if route is None:
        return None, None
    return (method.upper() if method.upper() in HTTP_METHODS else None), route[:512]


def _key(route: str) -> str:
    return route.strip().lower().rstrip("/") or "/"


def boundary_coverage(edges: list[Mapping[str, Any]], angles: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Each auth-boundary edge with the state of the authorization coverage on its consumer route. Pure.

    ``angles`` are the latest event of each coverage angle on the target. An angle covers a
    boundary when its family examines authorization and its route is the consumer route (and its
    method, when both name one). ``examined`` wins over ``in_progress``.
    """
    by_route: dict[str, list[Mapping[str, Any]]] = {}
    for angle in angles:
        if str(angle.get("family") or "").strip().lower() not in AUTHZ_FAMILIES:
            continue
        locus = _json(angle.get("locus_json"))
        route = normalize_route(str(locus.get("route") or locus.get("path") or ""))
        if route is not None:
            by_route.setdefault(_key(route), []).append({**angle, "_method": str(locus.get("method") or "").upper()})
    rows = []
    for edge in edges:
        method, route = route_of(edge.get("dst_key"))
        if route is None:
            continue
        _, producer = route_of(edge.get("src_key"))
        attributes = _json(edge.get("attributes"))
        matching = [angle for angle in by_route.get(_key(route), ())
                    if not method or not angle["_method"] or angle["_method"] == method]
        statuses = {str(angle.get("status") or "") for angle in matching}
        state = "examined" if statuses & EXAMINED else "in_progress" if statuses & IN_PROGRESS else "untested"
        rows.append({
            "edge_id": str(edge["id"]) if edge.get("id") else None,
            "coverage": state, "method": method, "route": route, "producer_route": producer,
            "object_key": str(attributes.get("object_id_key") or "")[:200] or None,
            "source_principal": str(attributes.get("source_principal") or "")[:120] or None,
            "excluded_principal": str(attributes.get("excluded_principal") or "")[:120] or None,
            "angle_statuses": sorted(statuses - {""}),
            "hunts_with_coverage": len({str(angle.get("hunt_run_id")) for angle in matching}),
            "last_seen_at": edge["last_seen_at"].isoformat() if edge.get("last_seen_at") else None,
        })
    order = {state: index for index, state in enumerate(STATES)}
    rows.sort(key=lambda row: (order[row["coverage"]], row["route"], row["method"] or ""))
    return rows


async def target_coverage_gaps(conn: Any, target_id: Any, *, filters: Mapping[str, Any] | None = None,
                               limit: int = 100) -> dict[str, Any]:
    """The target's auth boundaries by coverage state, untested first, as one bounded report."""
    supplied = dict(filters or {})
    unknown = set(supplied) - set(FILTERS)
    if unknown:
        raise CoverageGapQueryError("Unsupported coverage_gaps filters: " + ", ".join(sorted(unknown)))
    wanted = supplied.get("coverage", "untested")
    if wanted not in (*STATES, "all"):
        raise CoverageGapQueryError("coverage is one of " + ", ".join((*STATES, "all")))
    contains = supplied.get("path_contains")
    if contains is not None and (not isinstance(contains, str) or not contains.strip() or len(contains) > 200):
        raise CoverageGapQueryError("path_contains is a non-empty string of at most 200 characters")
    target = uuid.UUID(str(target_id))
    edges = await conn.fetch(
        f"""SELECT id, src_key, dst_key, attributes, last_seen_at FROM application_graph_edges
            WHERE {asset_scope('target_id')} AND edge_type='auth_boundary'
            ORDER BY last_seen_at DESC NULLS LAST, id LIMIT {MAX_EDGES + 1}""", target)
    angles = await conn.fetch(
        f"""SELECT DISTINCT ON (e.fingerprint) e.family, e.locus_json, e.status, e.hunt_run_id
            FROM hunt_coverage_angle_events e JOIN hunt_runs r ON r.id = e.hunt_run_id
            WHERE ({asset_scope('r.target_id')} OR {asset_scope('r.device_target_id')})
              AND NOT (COALESCE(r.notes,'[]'::jsonb) @> '[{{"kind":"entries_retracted"}}]'::jsonb)
            ORDER BY e.fingerprint, e.event_seq DESC LIMIT {MAX_ANGLES}""", target)
    rows = boundary_coverage([dict(edge) for edge in edges[:MAX_EDGES]], [dict(angle) for angle in angles])
    summary = {state: sum(row["coverage"] == state for row in rows) for state in STATES}
    if contains is not None:
        needle = contains.strip().lower()
        rows = [row for row in rows if needle in row["route"].lower()]
    if wanted != "all":
        rows = [row for row in rows if row["coverage"] == wanted]
    bound = max(1, min(int(limit), MAX_ROWS))
    return {"kind": "coverage_gaps", "supported": True, "rows": rows[:bound], "count": len(rows[:bound]),
            "has_more": len(rows) > bound, "next_cursor": None, "boundaries": sum(summary.values()),
            "by_coverage": summary, "edges_truncated": len(edges) > MAX_EDGES, "is_proof": False,
            "note": ("A worklist from the application graph and the coverage ledger. An untested boundary is "
                     "not a finding; examined means an authorization angle on that route reached a settled "
                     "state, which the angle itself qualifies.")}


__all__ = ["AUTHZ_FAMILIES", "CoverageGapQueryError", "boundary_coverage", "route_of", "target_coverage_gaps"]
