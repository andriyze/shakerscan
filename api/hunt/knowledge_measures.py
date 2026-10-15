"""How continuing after a release went on one target, measured from server records.

Two kinds of event are kept in ``knowledge_continue_events`` (no text, bounded per target):

* ``report_read``: someone (an operator, or a Hunt through ``knowledge.continue`` or query kind
  ``continue``) read the continue report. The first read after a release records the required
  re-tests and changed routes the report listed then, before anything was re-tested;
* ``skip_advice``: ``knowledge.check_experiment`` advised that an experiment could be skipped.

``continuation_measures`` reads them back with the Hunt action ledger and the knowledge records:

* ``started_at``: the first read of the report after the release point (an operator's first, else a
  Hunt's); the clock for the time to the first useful step;
* ``required_retests``: how many re-tests listed at the start were run since (by any Hunt on the
  target), and which were not;
* ``time_to_first_useful_step_seconds``: from ``started_at`` to the first finished testing action
  that ran a listed re-test or touched a route that changed (added, removed or a new
  authentication route);
* ``redundant_requests``: requests after the start to a route already requested before the release
  that is neither a listed re-test nor a changed route, as a share of all requests after the start;
* ``new_results``: findings first seen after the release, and entries recorded after it whose
  outcome differs from an earlier entry with the identical conditions (a fixed issue or a
  regression);
* ``incorrect_suppression``: skip advice later contradicted (the advised entry's dependencies
  changed after the advice, or a later entry with identical conditions recorded another outcome).
  It is expected to be zero.

Everything is read from existing records: nothing here sends traffic, decides or grants anything.
``continue_usage`` counts reads per ISO week across the installation (operators and Hunts).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Iterable, Mapping
import uuid

from .condition_receipts import route_matches
from .knowledge_dependencies import PRINCIPAL_SQL, asset_scope, canonical_origin, normalize_route, operation_route

MAX_REQUIRED = 300
MAX_ROUTES = 100
MAX_EVENTS_PER_TARGET = 1000
MAX_HUNTS = 50
MAX_ACTIONS = 5000
MAX_LISTED = 25
TESTING_STATES = ("completed", "partial")


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


# --- recording ------------------------------------------------------------------------------------

def _required_item(item: Mapping[str, Any]) -> dict[str, Any]:
    values = item.get("input") if isinstance(item.get("input"), Mapping) else {}
    route = item.get("route") if isinstance(item.get("route"), Mapping) else {}
    conditions = item.get("conditions") if isinstance(item.get("conditions"), Mapping) else {}
    method, path = values.get("method"), values.get("path")
    if not path:
        method, path = route.get("method") or method, route.get("path")
    if not path and conditions:
        method, path = operation_route(conditions)
    basis = item.get("basis") if isinstance(item.get("basis"), Mapping) else {}
    return {"rule": item.get("rule"), "basis": {"type": basis.get("type"), "id": basis.get("id")},
            "capability": item.get("capability"), "method": (str(method).upper() if method else None),
            "path": str(path)[:2048] if path else None, "origin": values.get("origin") or conditions.get("origin"),
            "principal": item.get("principal")}


def snapshot_of(ranked: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The required re-tests and changed routes a report lists (identities only, no text)."""
    required, routes = [], []
    for item in ranked:
        if item.get("required_retest") and len(required) < MAX_REQUIRED:
            required.append(_required_item(item))
        if item.get("rule") in {"new_auth_surface", "new_surface", "removed_surface"} and len(routes) < MAX_ROUTES:
            found = _required_item(item)
            routes.append({"method": found["method"], "path": found["path"], "rule": item.get("rule")})
    return required, routes


async def _trim(conn: Any, target: uuid.UUID) -> None:
    await conn.execute(f"""DELETE FROM knowledge_continue_events WHERE id IN (
        SELECT id FROM knowledge_continue_events WHERE target_id=$1
        ORDER BY first_at DESC, id DESC OFFSET {MAX_EVENTS_PER_TARGET})""", target)


async def record_report_read(conn: Any, target_id: Any, *, reader: str, hunt_run_id: Any, since_at: Any,
                             set_digest: str | None, ranked: Iterable[Mapping[str, Any]]) -> None:
    """One read of the continue report: repeated reads of the same report by the same reader count up."""
    target = uuid.UUID(str(target_id))
    hunt = uuid.UUID(str(hunt_run_id)) if hunt_run_id else None
    since = since_at if isinstance(since_at, datetime) or since_at is None else datetime.fromisoformat(str(since_at))
    updated = await conn.fetchval("""UPDATE knowledge_continue_events SET reads = reads + 1, last_at = NOW()
        WHERE target_id=$1 AND kind='report_read' AND reader=$2 AND hunt_run_id IS NOT DISTINCT FROM $3
          AND since_at IS NOT DISTINCT FROM $4 AND set_digest IS NOT DISTINCT FROM $5 RETURNING id""",
        target, reader[:200], hunt, since, set_digest)
    if updated is not None:
        return
    required, routes = snapshot_of(ranked)
    await conn.execute("""INSERT INTO knowledge_continue_events
        (target_id, kind, reader, hunt_run_id, since_at, set_digest, required, routes)
        VALUES ($1,'report_read',$2,$3,$4,$5,$6::jsonb,$7::jsonb)""",
        target, reader[:200], hunt, since, set_digest, json.dumps(required), json.dumps(routes))
    await _trim(conn, target)


async def record_skip_advice(conn: Any, target_id: Any, entry_ids: Iterable[Any], *, hunt_run_id: Any) -> None:
    """Skip advice for these entries (``knowledge.check_experiment``), once per Hunt and entry."""
    target = uuid.UUID(str(target_id))
    hunt = uuid.UUID(str(hunt_run_id)) if hunt_run_id else None
    reader = f"hunt:{hunt}" if hunt else "operator:check-experiment"
    for entry in entry_ids:
        identifier = uuid.UUID(str(entry))
        dependencies = _json(await conn.fetchval("SELECT dependencies FROM target_interpretations WHERE id=$1",
                                                 identifier), {}) or {}
        binding = dependencies.get("binding") if isinstance(dependencies, Mapping) else None
        request = ({key: binding.get(key) for key in ("method", "path", "origin", "principal")}
                   if isinstance(binding, Mapping) else None)
        exists = await conn.fetchval("""UPDATE knowledge_continue_events SET reads = reads + 1, last_at = NOW()
            WHERE target_id=$1 AND kind='skip_advice' AND entry_id=$2 AND hunt_run_id IS NOT DISTINCT FROM $3
            RETURNING id""", target, identifier, hunt)
        if exists is None:
            await conn.execute("""INSERT INTO knowledge_continue_events
                (target_id, kind, reader, hunt_run_id, entry_id, request) VALUES ($1,'skip_advice',$2,$3,$4,$5::jsonb)""",
                target, reader, hunt, identifier, json.dumps(request) if request else None)
    await _trim(conn, target)


# --- measuring ------------------------------------------------------------------------------------

def _request_of(row: Mapping[str, Any]) -> dict[str, Any] | None:
    summary = _json(row.get("input_summary"), {}) or {}
    values = summary.get("input") if isinstance(summary, Mapping) else None
    if not isinstance(values, Mapping) or not isinstance(values.get("path"), str):
        return None
    return {"method": str(values.get("method") or "GET").upper(), "path": values["path"].split("?", 1)[0],
            "origin": canonical_origin(values.get("origin") or row.get("default_origin")),
            "principal": row.get("principal")}


def _matches(item: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    """Whether a finished action ran this listed re-test (or touched this route)."""
    capability = item.get("capability")
    if capability and capability != row["capability_name"]:
        return False
    if row["capability_name"] != "http.request":
        # authz.verify and other capabilities: the capability is what can be compared.
        return bool(capability) and capability == row["capability_name"]
    request = _request_of(row)
    if request is None or not item.get("path"):
        return False
    if item.get("method") and str(item["method"]).upper() != request["method"]:
        return False
    if item.get("origin") and canonical_origin(item["origin"]) not in {None, request["origin"]}:
        return False
    if item.get("principal") and request["principal"] and item["principal"] != request["principal"]:
        return False
    return route_matches(str(item["path"]), request["path"])


def _route_key(method: Any, path: Any) -> tuple[str, str]:
    text = str(path or "").split("?", 1)[0]
    return str(method or "GET").upper(), normalize_route(text) or text


async def _actions(conn: Any, target: uuid.UUID, *, after: Any = None, before: Any = None) -> list[Any]:
    scope = f"({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})"
    return list(await conn.fetch(f"""SELECT a.id, a.hunt_run_id, a.capability_name, a.input_summary, a.status,
            a.started_at, a.completed_at, t.url AS default_origin, {PRINCIPAL_SQL}
        FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
        LEFT JOIN targets t ON t.id = COALESCE(h.target_id, h.device_target_id)
        LEFT JOIN auth_sessions s ON s.id::text = a.input_summary->'input'->>'session_ref'
        LEFT JOIN credential_profiles cp ON cp.id = s.profile_id
        WHERE {scope} AND a.status = ANY($2::text[])
          AND ($3::timestamptz IS NULL OR a.started_at > $3) AND ($4::timestamptz IS NULL OR a.started_at <= $4)
        ORDER BY a.started_at, a.id LIMIT {MAX_ACTIONS + 1}""", target, list(TESTING_STATES), after, before))


def _testing(name: Any) -> bool:
    from .interpretations import _testing_capability
    return _testing_capability(name)


async def _incorrect_suppression(conn: Any, target: uuid.UUID, since: Any) -> dict[str, Any]:
    rows = await conn.fetch("""SELECT e.entry_id, e.first_at, e.hunt_run_id, i.applicability, i.applicability_changed_at,
            i.conditions_sha256, i.negative_state, i.kind
        FROM knowledge_continue_events e LEFT JOIN target_interpretations i ON i.id=e.entry_id
        WHERE e.target_id=$1 AND e.kind='skip_advice' AND ($2::timestamptz IS NULL OR e.first_at > $2)
        ORDER BY e.first_at LIMIT 1000""", target, since)
    contradicted = []
    for row in rows:
        reason = None
        if row["applicability"] in {"needs_revalidation", "historical"} and row["applicability_changed_at"] \
                and row["applicability_changed_at"] > row["first_at"]:
            reason = f"its dependencies changed after the advice ({row['applicability']})"
        elif row["conditions_sha256"] and await conn.fetchval("""SELECT 1 FROM target_interpretations
                WHERE target_id=$1 AND conditions_sha256=$2 AND created_at > $3 AND status <> 'retracted'
                  AND (kind <> $4 OR negative_state IS DISTINCT FROM $5) LIMIT 1""",
                target, row["conditions_sha256"], row["first_at"], row["kind"], row["negative_state"]):
            reason = "a later entry with identical conditions recorded another outcome"
        if reason:
            contradicted.append({"entry_id": str(row["entry_id"]), "advised_at": _iso(row["first_at"]),
                                 "hunt_id": str(row["hunt_run_id"]) if row["hunt_run_id"] else None, "why": reason})
    return {"skip_advice": len(rows), "contradicted": len(contradicted), "items": contradicted[:MAX_LISTED],
            "expected": 0,
            "rule": ("Skip advice later contradicted: the advised entry's dependencies changed after the advice, "
                     "or a later entry with identical conditions recorded another outcome.")}


async def _new_results(conn: Any, target: uuid.UUID, since: Any) -> dict[str, Any]:
    findings = await conn.fetch(f"""SELECT severity, count(*) AS n FROM findings WHERE {asset_scope('target_id')}
        AND first_seen_at > $2 GROUP BY severity""", target, since)
    changed = await conn.fetch(f"""SELECT n.id, n.kind, n.negative_state, n.hunt_run_id, n.created_at, o.id AS earlier_id,
            o.kind AS earlier_kind, o.negative_state AS earlier_state
        FROM target_interpretations n JOIN LATERAL (
            SELECT id, kind, negative_state FROM target_interpretations o
            WHERE o.target_id=n.target_id AND o.conditions_sha256=n.conditions_sha256 AND o.created_at < n.created_at
              AND o.status <> 'retracted' AND (o.kind <> n.kind OR o.negative_state IS DISTINCT FROM n.negative_state)
            ORDER BY o.created_at DESC LIMIT 1) o ON true
        WHERE {asset_scope('n.target_id')} AND n.created_at > $2 AND n.status <> 'retracted'
          AND n.conditions <> '{{}}'::jsonb
        ORDER BY n.created_at LIMIT {MAX_LISTED + 1}""", target, since)
    return {"findings_first_seen": {str(row["severity"]): int(row["n"]) for row in findings},
            "findings_first_seen_total": sum(int(row["n"]) for row in findings),
            "changed_outcomes": [{"id": str(row["id"]), "outcome": row["negative_state"] or row["kind"],
                                  "earlier_id": str(row["earlier_id"]),
                                  "earlier_outcome": row["earlier_state"] or row["earlier_kind"],
                                  "hunt_id": str(row["hunt_run_id"]) if row["hunt_run_id"] else None,
                                  "at": _iso(row["created_at"])} for row in changed[:MAX_LISTED]],
            "changed_outcomes_truncated": len(changed) > MAX_LISTED,
            "rule": ("A changed outcome is an entry recorded after the release whose outcome differs from an earlier "
                     "entry with identical conditions: a regression or a fix found by re-testing.")}


async def continuation_measures(conn: Any, target_id: Any, *, since: str = "release") -> dict[str, Any]:
    """The continuation measures for one target since a point (default: the latest release)."""
    from .knowledge_changes import resolve_since
    target = uuid.UUID(str(target_id))
    resolved = await resolve_since(conn, target, since, device=True)
    anchor = resolved.get("at") if resolved.get("resolved") else None
    result: dict[str, Any] = {
        "ok": True, "kind": "continue_measures", "target_id": str(target),
        "built_at": datetime.now(timezone.utc).isoformat(), "since": {**resolved, "at": _iso(anchor)},
        "sends_traffic": False, "is_proof": False,
    }
    if anchor is None:
        result["note"] = "No release point: declare one with shakerscan knowledge release, or give since."
        return result
    reads = await conn.fetch("""SELECT reader, hunt_run_id, first_at, last_at, reads, required, routes, set_digest
        FROM knowledge_continue_events WHERE target_id=$1 AND kind='report_read' AND first_at > $2
        ORDER BY first_at, id LIMIT 1000""", target, anchor)
    operators = [row for row in reads if str(row["reader"]).startswith("operator:")]
    start = (operators or list(reads) or [None])[0]
    result["reads"] = {"total": sum(int(row["reads"]) for row in reads),
                       "operators": len({row["reader"] for row in operators}),
                       "hunts": len({row["hunt_run_id"] for row in reads if row["hunt_run_id"]})}
    if start is None:
        result["note"] = "Nobody read the continue report since the release point; nothing to measure yet."
        result["incorrect_suppression"] = await _incorrect_suppression(conn, target, anchor)
        result["new_results"] = await _new_results(conn, target, anchor)
        return result
    started_at = start["first_at"]
    required = _json(start["required"], []) or []
    routes = _json(start["routes"], []) or []
    result["started_at"] = _iso(started_at)
    result["started_by"] = "operator" if str(start["reader"]).startswith("operator:") else "hunt"
    actions = [row for row in await _actions(conn, target, after=started_at) if _testing(row["capability_name"])]
    truncated = len(actions) > MAX_ACTIONS
    actions = actions[:MAX_ACTIONS]
    covered: dict[int, Any] = {}
    first_useful = None
    for row in actions:
        hit = False
        for position, item in enumerate(required):
            if _matches(item, row):
                covered.setdefault(position, row)
                hit = True
        if not hit:
            hit = any(_matches({"method": route.get("method") if route.get("rule") != "removed_surface" else None,
                                "path": route.get("path"), "capability": "http.request"}, row)
                      for route in routes if route.get("path"))
        if hit and first_useful is None:
            first_useful = row
    missing = [item for position, item in enumerate(required) if position not in covered]
    result["required_retests"] = {
        "listed_at_start": len(required), "run": len(covered), "not_run": len(missing),
        "not_run_items": [{k: item.get(k) for k in ("rule", "basis", "capability", "method", "path")}
                          for item in missing[:MAX_LISTED]],
        "rule": "A listed re-test counts as run when a finished action after the start repeated it (capability, "
                "method, route, origin and principal where the report named them)."}
    useful_at = (first_useful["completed_at"] or first_useful["started_at"]) if first_useful is not None else None
    result["first_useful_step"] = {
        "at": _iso(useful_at), "action_id": str(first_useful["id"]) if first_useful is not None else None,
        "seconds": round((useful_at - started_at).total_seconds(), 1) if useful_at is not None else None,
        "rule": "From the first read of the report after the release to the first finished testing action that ran "
                "a listed re-test or touched a changed route."}
    before = await _actions(conn, target, before=anchor)
    earlier = set()
    for row in before:
        request = _request_of(row) if row["capability_name"] == "http.request" else None
        if request is not None:
            earlier.add(_route_key(request["method"], request["path"]))
    requests = [row for row in actions if row["capability_name"] == "http.request" and _request_of(row)]
    redundant = 0
    for row in requests:
        request = _request_of(row)
        if _route_key(request["method"], request["path"]) not in earlier:
            continue
        if any(_matches(item, row) for item in required):
            continue
        if any(_matches({"path": route.get("path"), "capability": "http.request"}, row)
               for route in routes if route.get("path")):
            continue
        redundant += 1
    result["redundant_requests"] = {
        "requests_after_start": len(requests), "redundant": redundant,
        "share": round(redundant / len(requests), 3) if requests else None,
        "rule": "A request after the start to a route already requested before the release, that is neither a listed "
                "re-test nor a changed route.",
        **({"at_least": True, "note": f"the first {MAX_ACTIONS} actions after the start were read"} if truncated else {})}
    result["new_results"] = await _new_results(conn, target, anchor)
    result["incorrect_suppression"] = await _incorrect_suppression(conn, target, anchor)
    hunts = await conn.fetch(f"""SELECT id, status, created_at FROM hunt_runs
        WHERE ({asset_scope('target_id')} OR {asset_scope('device_target_id')}) AND created_at > $2
        ORDER BY created_at LIMIT {MAX_HUNTS}""", target, anchor)
    result["hunts_since_release"] = [{"id": str(row["id"]), "status": row["status"], "created_at": _iso(row["created_at"])}
                                     for row in hunts]
    return result


async def continue_usage(conn: Any, *, weeks: int = 8) -> dict[str, Any]:
    """Continue-report reads per ISO week across the installation: readers, targets and reads."""
    weeks = max(1, min(int(weeks), 52))
    since = datetime.now(timezone.utc) - timedelta(weeks=weeks)
    rows = await conn.fetch("""SELECT to_char(date_trunc('week', first_at), 'IYYY-"W"IW') AS week,
            count(DISTINCT reader) FILTER (WHERE reader LIKE 'operator:%') AS operators,
            count(DISTINCT hunt_run_id) AS hunts, count(DISTINCT target_id) AS targets, sum(reads) AS reads
        FROM knowledge_continue_events WHERE kind='report_read' AND first_at > $1
        GROUP BY 1 ORDER BY 1""", since)
    return {"ok": True, "kind": "continue_usage", "weeks": weeks,
            "items": [{"week": row["week"], "operators": int(row["operators"]), "hunts": int(row["hunts"]),
                       "targets": int(row["targets"]), "reads": int(row["reads"] or 0)} for row in rows],
            "rule": "Distinct readers of the continue report per ISO week (operators by their server-recorded identity)."}


__all__ = ["continuation_measures", "continue_usage", "record_report_read", "record_skip_advice", "snapshot_of"]
