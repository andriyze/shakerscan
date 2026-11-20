"""Search the HTTP calls already archived for a target, across its Scans and Hunts.

A Hunt's own archive export (``GET /hunts/{id}/http-transactions``) shows that Hunt's calls. This
is the target-wide read a planner uses before sending anything: which routes were already called,
by which run, with which method, principal slot and status, so an answer that already exists is
cited instead of fetched again.

It returns references and call metadata only. The URL is the masked origin and path the archive
search matches on (``search_url``: no userinfo, query or fragment); headers and bodies never
travel here. Calls archived before that column existed have no URL and are left out of a path
search. Calls of a Hunt whose entries an operator retracted are left out, like the rest of what
that Hunt wrote. Nothing here grants authority or is proof.
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping

from .knowledge_dependencies import asset_scope

try:
    from runtime.http_archive_search import search_pattern
except ModuleNotFoundError:  # package import layout
    from ..runtime.http_archive_search import search_pattern

MAX_ROWS = 200
FILTERS = ("path_contains", "method", "status_code", "status_class", "capability", "plane", "principal_slot", "by")
STATUS_CLASSES = ("1xx", "2xx", "3xx", "4xx", "5xx")
PLANES = ("scan", "hunt")


class TrafficQueryError(ValueError):
    """A filter this search does not take, or a value outside its bounds."""


def _text(filters: Mapping[str, Any], key: str, maximum: int = 200) -> str | None:
    value = filters.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise TrafficQueryError(f"{key} is a non-empty string of at most {maximum} characters")
    return value.strip()


async def target_traffic(conn: Any, target_id: Any, *, filters: Mapping[str, Any] | None = None,
                         limit: int = 100, current_hunt_id: Any = None) -> dict[str, Any]:
    """Archived calls to this target's asset, newest first, as one bounded page."""
    supplied = dict(filters or {})
    unknown = set(supplied) - set(FILTERS)
    if unknown:
        raise TrafficQueryError("Unsupported traffic filters: " + ", ".join(sorted(unknown)))
    target = uuid.UUID(str(target_id))
    params: list[Any] = [target]
    where = [f"({asset_scope('t.target_id')} OR {asset_scope('t.device_target_id')})",
             "t.plane IN ('scan','hunt')",
             """NOT EXISTS (SELECT 1 FROM hunt_runs r WHERE r.id = t.hunt_run_id
                           AND COALESCE(r.notes,'[]'::jsonb) @> '[{"kind":"entries_retracted"}]'::jsonb)"""]

    def bind(value: Any) -> str:
        params.append(value)
        return f"${len(params)}"

    path = _text(supplied, "path_contains")
    if path is not None:
        where.append(f"t.search_url ILIKE {bind(search_pattern(path))} ESCAPE '\\'")
    method = _text(supplied, "method", 16)
    if method is not None:
        where.append(f"upper(t.method) = {bind(method.upper())}")
    capability = _text(supplied, "capability", 80)
    if capability is not None:
        where.append(f"t.capability_name = {bind(capability)}")
    slot = _text(supplied, "principal_slot", 40)
    if slot is not None:
        where.append(f"t.principal_slot = {bind(slot)}")
    plane = _text(supplied, "plane", 8)
    if plane is not None:
        if plane not in PLANES:
            raise TrafficQueryError("plane is one of " + ", ".join(PLANES))
        where.append(f"t.plane = {bind(plane)}")
    status = supplied.get("status_code")
    if status is not None:
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise TrafficQueryError("status_code is an integer from 100 to 599")
        where.append(f"t.status_code = {bind(status)}")
    status_class = _text(supplied, "status_class", 3)
    if status_class is not None:
        if status_class not in STATUS_CLASSES:
            raise TrafficQueryError("status_class is one of " + ", ".join(STATUS_CLASSES))
        low = int(status_class[0]) * 100
        where.append(f"t.status_code >= {bind(low)} AND t.status_code < {bind(low + 100)}")
    by = _text(supplied, "by", 16)
    if by is not None:
        if by not in {"this_hunt", "other_runs"} or current_hunt_id is None:
            raise TrafficQueryError("by is this_hunt or other_runs")
        mine = bind(uuid.UUID(str(current_hunt_id)))
        where.append(f"t.hunt_run_id = {mine}" if by == "this_hunt"
                     else f"t.hunt_run_id IS DISTINCT FROM {mine}")
    bound = max(1, min(int(limit), MAX_ROWS))
    rows = await conn.fetch(
        f"""SELECT t.id, t.plane, t.scan_id, t.hunt_run_id, t.hunt_action_id, t.capability_name,
                   t.principal_slot, t.method, t.search_url, t.status_code, t.response_body_bytes,
                   t.elapsed_ms, t.error IS NOT NULL AS errored, t.truncated,
                   COALESCE(t.started_at, t.created_at) AS at
            FROM http_transactions t
            WHERE {' AND '.join(where)}
            ORDER BY COALESCE(t.started_at, t.created_at) DESC, t.id DESC
            LIMIT {bound + 1}""", *params)
    mine_id = str(current_hunt_id) if current_hunt_id is not None else None
    page = [{
        "transaction_id": str(row["id"]), "plane": row["plane"],
        "scan_id": str(row["scan_id"]) if row["scan_id"] else None,
        "hunt_id": str(row["hunt_run_id"]) if row["hunt_run_id"] else None,
        "action_id": str(row["hunt_action_id"]) if row["hunt_action_id"] else None,
        "by_this_hunt": bool(mine_id and row["hunt_run_id"] and str(row["hunt_run_id"]) == mine_id),
        "capability": row["capability_name"], "principal_slot": row["principal_slot"],
        "method": row["method"], "url": row["search_url"], "status_code": row["status_code"],
        "response_body_bytes": row["response_body_bytes"], "elapsed_ms": row["elapsed_ms"],
        "errored": row["errored"], "truncated": row["truncated"],
        "at": row["at"].isoformat() if row["at"] else None,
    } for row in rows[:bound]]
    return {"kind": "traffic", "supported": True, "rows": page, "count": len(page),
            "has_more": len(rows) > bound, "next_cursor": None, "is_proof": False,
            "note": ("Call metadata only: the URL is the masked origin and path. A run's own archive "
                     "export holds the redacted exchange; narrow the filters to see older calls.")}


__all__ = ["FILTERS", "MAX_ROWS", "TrafficQueryError", "target_traffic"]
