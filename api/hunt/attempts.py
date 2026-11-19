"""What has already been tried on this target, read from the Hunt action ledger.

Interpretations and negative results say what a planner *concluded*. This index says what was
*run*: every settled testing action any Hunt sent to the target's asset, grouped by capability,
method, route template and principal, with how each attempt ended. A planner reads it before
spending traffic, and two planners on one target see each other's attempts while both are running.

It is a projection of ``hunt_actions`` and nothing else: no text a planner wrote is returned (routes
are the normalized templates of requests the server sent, never titles or notes), it grants nothing
and is not proof. Actions of a Hunt whose entries an operator retracted are left out, like the rest
of what that Hunt wrote.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Mapping

from .condition_receipts import testing_capability
from .knowledge_dependencies import PRINCIPAL_SQL, asset_scope, normalize_route

#: Settled states an attempt can end in. Reserved and running actions have not been tried yet.
SETTLED_STATES = ("completed", "partial", "failed", "blocked", "cancelled")
#: Newest settled actions read per report. Bounds one read; ``truncated`` says when it was reached.
MAX_ACTIONS = 3000
MAX_GROUPS = 100
FILTERS = ("path_contains", "method", "capability", "by")


class AttemptQueryError(ValueError):
    """A filter this report does not take, or a value outside its bounds."""


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return value or {}


def _request(row: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The method and route template an action addressed, when its input names a path."""
    summary = _json(row.get("input_summary"))
    values = summary.get("input") if isinstance(summary, Mapping) else None
    if not isinstance(values, Mapping) or not isinstance(values.get("path"), str):
        return None, None
    path = values["path"].split("?", 1)[0]
    return str(values.get("method") or "GET").upper()[:16], (normalize_route(path) or path)[:512]


def _filters(filters: Mapping[str, Any] | None) -> dict[str, str]:
    supplied = dict(filters or {})
    unknown = set(supplied) - set(FILTERS)
    if unknown:
        raise AttemptQueryError("Unsupported attempts filters: " + ", ".join(sorted(unknown)))
    clean: dict[str, str] = {}
    for key, value in supplied.items():
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            raise AttemptQueryError(f"{key} must be a non-empty string of at most 200 characters")
        clean[key] = value.strip()
    if clean.get("by") not in (None, "this_hunt", "other_hunts"):
        raise AttemptQueryError("by is this_hunt or other_hunts")
    return clean


def group_attempts(rows: list[Mapping[str, Any]], *, current_hunt_id: Any = None,
                   filters: Mapping[str, str] | None = None, limit: int = MAX_GROUPS) -> dict[str, Any]:
    """Group settled testing actions (newest first) into attempts. Pure: no I/O."""
    wanted = dict(filters or {})
    current = str(current_hunt_id) if current_hunt_id else None
    groups: dict[tuple[str, str | None, str | None, str | None], dict[str, Any]] = {}
    for row in rows:
        capability = str(row["capability_name"])
        if not testing_capability(capability):
            continue
        method, route = _request(row)
        mine = current is not None and str(row["hunt_run_id"]) == current
        if wanted.get("capability") and wanted["capability"] != capability:
            continue
        if wanted.get("method") and wanted["method"].upper() != (method or ""):
            continue
        if wanted.get("path_contains") and wanted["path_contains"].lower() not in (route or "").lower():
            continue
        if (wanted.get("by") == "this_hunt" and not mine) or (wanted.get("by") == "other_hunts" and mine):
            continue
        key = (capability, method, route, row.get("principal"))
        group = groups.get(key)
        if group is None:
            # Rows arrive newest first, so the first one seen is the group's latest attempt.
            group = groups[key] = {
                "capability": capability, "method": method, "route": route, "principal": row.get("principal"),
                "attempts": 0, "this_hunt_attempts": 0, "outcomes": {}, "_hunts": set(),
                "last_status": row["status"], "last_action_id": str(row["id"]),
                "last_by_this_hunt": mine, "last_at": row.get("completed_at") or row.get("started_at"),
                "first_at": row.get("started_at")}
        group["attempts"] += 1
        group["this_hunt_attempts"] += 1 if mine else 0
        group["outcomes"][row["status"]] = group["outcomes"].get(row["status"], 0) + 1
        group["_hunts"].add(str(row["hunt_run_id"]))
        group["first_at"] = row.get("started_at") or group["first_at"]
    ordered = list(groups.values())
    for group in ordered:
        group["hunts"] = len(group.pop("_hunts"))
        for field in ("last_at", "first_at"):
            if hasattr(group[field], "isoformat"):
                group[field] = group[field].isoformat()
    return {"rows": ordered[:limit], "count": min(len(ordered), limit), "groups_total": len(ordered),
            "has_more": len(ordered) > limit}


async def target_attempts(conn: Any, target_id: Any, *, filters: Mapping[str, Any] | None = None,
                          limit: int = MAX_GROUPS, current_hunt_id: Any = None) -> dict[str, Any]:
    """Attempts on this target's asset by any Hunt, newest first, as one bounded report."""
    wanted = _filters(filters)
    target = uuid.UUID(str(target_id))
    scope = f"({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})"
    rows = list(await conn.fetch(f"""SELECT a.id, a.hunt_run_id, a.capability_name, a.input_summary, a.status,
            a.started_at, a.completed_at, {PRINCIPAL_SQL}
        FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
        LEFT JOIN auth_sessions s ON s.id::text = a.input_summary->'input'->>'session_ref'
        LEFT JOIN credential_profiles cp ON cp.id = s.profile_id
        WHERE {scope} AND a.status = ANY($2::text[])
          AND NOT (COALESCE(h.notes,'[]'::jsonb) @> '[{{"kind":"entries_retracted"}}]'::jsonb)
        ORDER BY a.started_at DESC, a.id DESC LIMIT {MAX_ACTIONS + 1}""", target, list(SETTLED_STATES)))
    truncated = len(rows) > MAX_ACTIONS
    report = group_attempts(rows[:MAX_ACTIONS], current_hunt_id=current_hunt_id, filters=wanted,
                            limit=max(1, min(int(limit), MAX_GROUPS)))
    return {"kind": "attempts", "supported": True, **report, "next_cursor": None,
            "actions_read": min(len(rows), MAX_ACTIONS), "truncated": truncated,
            "is_proof": False,
            "note": ("Attempts are what was run, not what it showed. Read an action's evidence, or "
                     "knowledge.check_experiment, before treating an attempt as a negative result.")}
