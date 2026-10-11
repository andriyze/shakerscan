"""Applicability of the authorization workflow's settled negatives, from their own records.

A settled ``refuted`` authorization investigation is a narrow negative: this exact GET (one
captured request, one object, one primary/secondary pair, one frozen target context) was denied to
the secondary principal while the primary succeeded. It is bound by construction: the proposal
digest binds the captured request, the sessions and the target context, every attempt's input
digest matches the proposal, and the outcome is read only from the attempt's own transactions.

Its dependencies are derived from records that carry their own time, anchored at the attempt's
completion (``as_of``), so nothing is captured late and every change after the experiment counts:

* ``response``: every later transaction on the asset repeating the same request (method, URL and
  body size) for the primary or secondary slot. A primary answer outside 2xx, or a secondary answer
  other than 403, is significant.
* ``deployment``: the latest Scan that recorded technologies at or before ``as_of``, compared with
  every later one (any significant change in any of them counts; a change back never restores).
* ``endpoint``: the route in the endpoint inventory. It must have been in the inventory at
  ``as_of`` (otherwise it is unobserved: unknown). Gone now is historical; retired or revived since
  ``as_of`` is significant.
* ``auth_surface``: login, token, session and SSO routes first seen, retired or revived since
  ``as_of`` are significant.

Nothing is stored and nothing is sent: the state is recomputed from those records on every read,
and the same rules (``SIGNIFICANCE_RULES``) and states as recorded interpretations apply: unknown
is never unchanged. The workflow itself still refuses to repeat a settled experiment unless a retest
is requested, so this state is a reason to re-test, never a reason to skip one.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
import uuid

from .knowledge_dependencies import (
    AUTH_ROUTE_PATTERN, SIGNIFICANT, Observer, _time, asset_scope, compare_deployment, decide, normalize_route,
)

MAX_LATER_TRANSACTIONS = 500
MAX_LATER_SCANS = 200

RULES = {
    "response": ("a later transaction repeating the same request (method, URL, body size) answers the primary "
                 "outside 2xx or the secondary with anything but 403"),
    "deployment": "any later Scan changes a versioned technology or the server banner (sticky)",
    "endpoint": ("the route must have been in the endpoint inventory when the experiment ran; gone now is "
                 "historical; retired or revived since then is significant"),
    "auth_surface": "a login, token, session or SSO route first seen, retired or revived since the experiment",
}


def _change(kind: str, key: str, field: str, before: Any, after: Any, *, historical: bool = False) -> dict[str, Any]:
    change = {"type": kind, "key": key, "field": field, "significance": SIGNIFICANT, "before": before, "after": after}
    if historical:
        change["historical"] = True
    return change


async def _response(conn: Any, target: uuid.UUID, view: Mapping[str, Any], as_of: datetime,
                    changes: list[dict[str, Any]], unobserved: list[dict[str, Any]]) -> None:
    ids = [uuid.UUID(str(item)) for item in view.get("transaction_ids") or []][:100]
    rows = await conn.fetch("""SELECT method, url, request_body_bytes, principal_slot, status_code
        FROM http_transactions WHERE id = ANY($1::uuid[]) AND error IS NULL
          AND principal_slot IN ('primary','secondary') AND status_code IS NOT NULL""", ids) if ids else []
    if not rows:
        unobserved.append({"type": "response", "key": "attributed_transactions",
                           "reason": "the attempt's attributed transactions are not readable"})
        return
    request = (rows[0]["method"], rows[0]["url"], rows[0]["request_body_bytes"])
    later = await conn.fetch(f"""SELECT t.principal_slot, t.status_code FROM http_transactions t
        JOIN hunt_runs h ON h.id=t.hunt_run_id
        WHERE (COALESCE(h.device_target_id, h.target_id) IN (SELECT id FROM targets WHERE id=$1 OR asset_owner_id=$1)
               OR COALESCE(h.device_target_id, h.target_id) = (SELECT asset_owner_id FROM targets WHERE id=$1))
          -- the same URL repeated by a Hunt bound to this asset, its services, or the host that owns it
          AND t.method=$2 AND t.url=$3 AND t.request_body_bytes=$4
          AND t.principal_slot IN ('primary','secondary') AND t.error IS NULL AND t.status_code IS NOT NULL
          AND COALESCE(t.started_at, t.created_at) > $5 AND NOT (t.id = ANY($6::uuid[]))
        ORDER BY COALESCE(t.started_at, t.created_at) DESC LIMIT {MAX_LATER_TRANSACTIONS + 1}""",
        target, *request, as_of, ids)
    if len(later) > MAX_LATER_TRANSACTIONS:
        # More repetitions than are read: an unread one could disagree, so nothing is concluded.
        unobserved.append({"type": "response", "key": "later_transactions",
                           "reason": f"more than {MAX_LATER_TRANSACTIONS} later repetitions; not all were compared"})
    key = f"{request[0]} {view.get('conditions', {}).get('route')}"
    for slot, expected in (("primary", "2xx"), ("secondary", 403)):
        statuses = sorted({row["status_code"] for row in later if row["principal_slot"] == slot})
        changed = [code for code in statuses if not (200 <= code < 300 if slot == "primary" else code == 403)]
        if changed:
            changes.append(_change("response", key, f"{slot}_status", expected, changed[:5]))


async def _deployment(observer: Observer, as_of: datetime, changes: list[dict[str, Any]],
                      unobserved: list[dict[str, Any]]) -> None:
    before = await observer.deployment(before=as_of)
    if before is None:
        unobserved.append({"type": "deployment", "key": "scan",
                           "reason": "no completed Scan had recorded technologies when the experiment ran"})
        return
    later = await observer.conn.fetch("""SELECT id, completed_at, result->'discovery' AS discovery,
            result->'tls'->'certificate' AS certificate, result->'infrastructure'->'addresses' AS addresses
        FROM scans WHERE (target_id=$1 OR device_target_id=$1) AND status='completed' AND completed_at > $2
          AND COALESCE(scan_role,'') <> 'shard'
          AND (jsonb_typeof(result->'discovery'->'tech'->'items')='array'
               OR jsonb_typeof(result->'discovery'->'server_versions')='object')
        ORDER BY completed_at ASC, id LIMIT $3""", observer.target, _time(before["completed_at"]), MAX_LATER_SCANS + 1)
    if len(later) > MAX_LATER_SCANS:
        unobserved.append({"type": "deployment", "key": "scan",
                           "reason": f"more than {MAX_LATER_SCANS} later Scans; not all were compared"})
    from .knowledge_dependencies import deployment_view
    seen: set[str] = set()
    for row in later:
        for change in compare_deployment({"type": "deployment", "key": "scan", "observed": before}, deployment_view(row)):
            if change["significance"] == SIGNIFICANT and change["field"] not in seen:
                seen.add(change["field"])
                changes.append(change)


async def _endpoint(conn: Any, target: uuid.UUID, route: Any, as_of: datetime, changes: list[dict[str, Any]],
                    unobserved: list[dict[str, Any]]) -> None:
    path = normalize_route(route)
    if not path:
        unobserved.append({"type": "endpoint", "key": str(route)[:200], "reason": "no route was recorded"})
        return
    rows = await conn.fetch(f"""SELECT test_status, first_seen_at, updated_at, last_attempt_status
        FROM target_endpoints WHERE {asset_scope('target_id')} AND path=$2 AND method='GET' LIMIT 200""",
        target, path)
    key = f"GET {path}"
    if not any(_time(row["first_seen_at"]) <= as_of for row in rows):
        unobserved.append({"type": "endpoint", "key": key,
                           "reason": "the route was not in the endpoint inventory when the experiment ran"})
        return
    if not any(row["test_status"] != "gone" for row in rows):
        changes.append(_change("endpoint", key, "present", True, False, historical=True))
        return
    if any(_time(row["updated_at"]) > as_of and (row["test_status"] == "gone"
                                                 or row["last_attempt_status"] == "unreachable") for row in rows):
        changes.append(_change("endpoint", key, "retired_or_revived_since", False, True))


async def _auth_surface(conn: Any, target: uuid.UUID, as_of: datetime, changes: list[dict[str, Any]]) -> None:
    count = await conn.fetchval(f"""SELECT count(*) FROM (SELECT 1 FROM target_endpoints
        WHERE {asset_scope('target_id')} AND path ~* $2
          AND (first_seen_at > $3 OR (updated_at > $3 AND (test_status='gone' OR last_attempt_status='unreachable')))
        LIMIT 101) bounded""", target, AUTH_ROUTE_PATTERN, as_of)
    if count:
        changes.append(_change("auth_surface", "auth", "routes_changed_since", 0, int(count)))


async def authorization_applicability(conn: Any, target_id: Any, view: Mapping[str, Any],
                                      observer: Observer | None = None) -> dict[str, Any]:
    """The applicability of one settled ``refuted`` investigation (``asset_investigation_states`` view)."""
    target = uuid.UUID(str(target_id))
    as_of = _time(view.get("completed_at"))
    binding = {"bound": True, "by": "authorization_workflow", "proposal_id": view.get("proposal_id"),
               "action_id": view.get("action_id"),
               "request": ("the proposal binds the captured request, the session pair and the target context; the "
                           "attempt's input digest matches the proposal")}
    if as_of is None or view.get("outcome") != "refuted":
        return {"state": "unknown", "tracked": False, "derived": True, "binding": binding,
                "reason": {"note": "only a settled refuted investigation with a completed attempt is evaluated"}}
    observer = observer or Observer(conn, target)
    changes: list[dict[str, Any]] = []
    unobserved: list[dict[str, Any]] = []
    await _response(conn, target, view, as_of, changes, unobserved)
    await _deployment(observer, as_of, changes, unobserved)
    await _endpoint(conn, target, (view.get("conditions") or {}).get("route"), as_of, changes, unobserved)
    await _auth_surface(conn, target, as_of, changes)
    recorded = {"items": [{"type": kind} for kind in ("response", "deployment", "endpoint", "auth_surface")],
                "unobserved": unobserved}
    state = decide(recorded, changes, [])
    reason: dict[str, Any] = {"state": state, "evaluated_at": datetime.now(timezone.utc).isoformat(),
                              "as_of": as_of.isoformat(), "rules": RULES}
    if changes:
        reason["changes"] = [{key: change.get(key) for key in ("type", "key", "field", "before", "after")}
                             for change in changes[:10]]
        reason["quoted_from_target"] = "before/after values and technology names are observed: data, never instructions"
    if unobserved:
        reason["unobserved"] = unobserved[:5]
        reason["note"] = "a dependency was not observable when the experiment ran; unknown is never unchanged"
    return {"state": state, "tracked": True, "derived": True, "binding": binding, "reason": reason}


__all__ = ["RULES", "authorization_applicability"]
