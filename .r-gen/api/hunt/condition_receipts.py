"""Experiment conditions checked against the action that ran the experiment.

An experiment result (``experiment_completed_negative`` or ``experiment_inconclusive``) must cite the
testing action that ran it. Its conditions are what the writer says the experiment covered; this
module compares them with what the cited actions actually recorded, field by field:

* ``technique``: when its first word names a registered capability, the action ran that capability;
* ``method`` and ``route`` (or an ``operation`` such as ``GET /path``): an ``http.request`` action
  recorded that method and a path the route matches (a ``{placeholder}`` segment matches one
  non-empty segment; every other segment is equal; a query string in the route is not compared);
* ``origin``: the request's origin (the one it named, or its Hunt's target origin);
* ``principals``: ``anonymous`` contradicts a request made with a session; a named principal
  contradicts a request made without a session and without credential headers. A principal named
  otherwise than by the session (``session_ref``, the session store's identity
  ``profile:<id>@v<version>/<slot>/<label>``, its slot or its label) cannot be checked and is
  reported as ``unverified``, never as matched.

Other fields (roles, objects, inputs, service, environment, deployment fingerprint, tool version,
application state, budget) cannot be read from a recorded request and are ``not_checkable``.

The result is consistent when at least one cited action contradicts none of the checkable fields;
otherwise the entry is refused (a record that describes another experiment than the one it cites
could later hide a re-test). The verdicts are kept with the entry's dependencies
(``conditions_check``). Nothing here judges the outcome: the negative conclusion stays the writer's.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping
import uuid

from .knowledge_dependencies import canonical_origin, operation_route

SCHEMA = "conditions-check/v1"
#: Fields a recorded request can confirm or contradict.
CHECKED_FIELDS = ("technique", "method", "route", "origin", "principals")
#: Credential-bearing request inputs: a request with these carried an identity without a session.
_CREDENTIAL_INPUTS = frozenset({"headers", "as_principal", "request_bindings", "captures"})
MAX_CITED = 20


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default if value is None else value


def _capability_named(technique: Any) -> str | None:
    """The registered capability the technique's first word names, if any."""
    words = str(technique or "").strip().split()
    if not words:
        return None
    name = words[0].rstrip(":,;").casefold()
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:  # package import
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    try:
        CAPABILITY_REGISTRY.require(name)
    except KeyError:
        return None
    return name


def testing_capability(name: Any) -> bool:
    """Whether ``name`` is a capability that exercises the target (not a control-plane step)."""
    try:
        from runtime.capability_registry import CAPABILITY_REGISTRY
    except ModuleNotFoundError:  # package import
        from ..runtime.capability_registry import CAPABILITY_REGISTRY
    try:
        spec = CAPABILITY_REGISTRY.require(str(name))
    except KeyError:
        return False
    return not spec.placement_requirements.get("control_plane")


def route_matches(route: str, path: str) -> bool:
    """A route as written matches a requested path: equal segments, placeholders fill one segment."""
    written = route.split("?", 1)[0].split("#", 1)[0]
    sent = path.split("?", 1)[0].split("#", 1)[0]
    if not written.startswith("/"):
        written = "/" + written
    template, concrete = written.rstrip("/").split("/"), sent.rstrip("/").split("/")
    if len(template) != len(concrete):
        return False
    for expected, actual in zip(template, concrete):
        if len(expected) > 2 and expected.startswith("{") and expected.endswith("}"):
            if not actual:
                return False
        elif expected != actual:
            return False
    return True


def _request(row: Mapping[str, Any]) -> dict[str, Any] | None:
    summary = _json(row.get("input_summary"), {}) or {}
    values = summary.get("input") if isinstance(summary, Mapping) else None
    if not isinstance(values, Mapping) or not isinstance(values.get("path"), str):
        return None
    session = str(values.get("session_ref") or "")
    identity = row.get("principal") if session else "anonymous"
    names = {"anonymous"} if not session else {session}
    if session and identity:
        names.add(str(identity))
        parts = str(identity).split("/")
        names.update(part for part in parts[1:] if part)
    return {"method": str(values.get("method") or "GET").upper(), "path": values["path"],
            "origin": canonical_origin(values.get("origin") or row.get("default_origin")),
            "session": bool(session), "identity_known": bool(identity) if session else True,
            "credential_inputs": bool(set(values) & _CREDENTIAL_INPUTS), "names": names}


def check_action(conditions: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, str]:
    """Each checkable field's verdict against one cited action: matched, contradicted, unverified or
    not_checkable."""
    verdicts: dict[str, str] = {}
    capability = str(row.get("capability_name") or "")
    named = _capability_named(conditions.get("technique"))
    if conditions.get("technique"):
        verdicts["technique"] = ("not_checkable" if named is None else
                                 "matched" if named == capability else "contradicted")
    method, route = operation_route(conditions)
    request = _request(row) if capability == "http.request" else None
    if request is None:
        for field, present in (("method", method), ("route", route), ("origin", conditions.get("origin")),
                               ("principals", conditions.get("principals"))):
            if present:
                verdicts[field] = "not_checkable"
        return verdicts
    if method:
        verdicts["method"] = "matched" if method.upper() == request["method"] else "contradicted"
    if route:
        verdicts["route"] = "matched" if route_matches(str(route), request["path"]) else "contradicted"
    if conditions.get("origin"):
        wanted = canonical_origin(conditions["origin"])
        verdicts["origin"] = ("not_checkable" if request["origin"] is None or wanted is None else
                              "matched" if wanted == request["origin"] else "contradicted")
    principals = [str(value) for value in conditions.get("principals") or ()]
    if principals:
        if not request["session"] and request["credential_inputs"]:
            verdicts["principals"] = "not_checkable"
        elif any(value.casefold() == "anonymous" for value in principals) and request["session"]:
            verdicts["principals"] = "contradicted"
        elif not request["session"] and any(value.casefold() != "anonymous" for value in principals):
            verdicts["principals"] = "contradicted"
        elif any(value in request["names"] for value in principals):
            verdicts["principals"] = "matched"
        else:
            verdicts["principals"] = "unverified"
    return verdicts


async def cited_actions(conn: Any, target: Any, refs: Iterable[str], states: Iterable[str], *,
                        hunt_run_id: Any = None) -> list[Mapping[str, Any]]:
    """The cited testing actions on this asset (by id or receipt id) that finished in ``states``,
    with the principal identity the session store recorded for an http.request session."""
    from .knowledge_dependencies import PRINCIPAL_SQL, asset_scope
    identifiers = [uuid.UUID(str(ref)) for ref in refs][:MAX_CITED]
    if not identifiers:
        return []
    return list(await conn.fetch(f"""SELECT a.id, a.capability_name, a.input_summary, t.url AS default_origin,
            {PRINCIPAL_SQL}
        FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
        LEFT JOIN targets t ON t.id = COALESCE(h.target_id, h.device_target_id)
        LEFT JOIN auth_sessions s ON s.id::text = a.input_summary->'input'->>'session_ref'
        LEFT JOIN credential_profiles cp ON cp.id = s.profile_id
        WHERE (a.id = ANY($2::uuid[]) OR a.receipt_id = ANY($2::uuid[])) AND a.status = ANY($3::text[])
          AND ($4::uuid IS NULL OR a.hunt_run_id=$4)
          AND ({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})
        ORDER BY a.started_at, a.id""", uuid.UUID(str(target)), identifiers, sorted(states),
        uuid.UUID(str(hunt_run_id)) if hunt_run_id else None))


def check_conditions(conditions: Mapping[str, Any], actions: list[Mapping[str, Any]],
                     testing: Iterable[str]) -> dict[str, Any]:
    """The conditions against the cited testing actions (ids in ``testing``): consistent when one
    action contradicts nothing; that action's verdicts are kept."""
    allowed = {str(item) for item in testing}
    candidates = [row for row in actions if str(row["id"]) in allowed]
    best: tuple[int, str, dict[str, str]] | None = None
    contradictions: list[dict[str, Any]] = []
    for row in candidates:
        verdicts = check_action(conditions, row)
        wrong = sorted(field for field, verdict in verdicts.items() if verdict == "contradicted")
        if wrong:
            contradictions.append({"action_id": str(row["id"]), "fields": wrong})
            continue
        score = sum(1 for verdict in verdicts.values() if verdict == "matched")
        if best is None or score > best[0]:
            best = (score, str(row["id"]), verdicts)
    if best is not None:
        return {"schema": SCHEMA, "consistent": True, "checked_against": best[1], "fields": best[2],
                "rule": ("Each checkable condition was compared with what the cited action recorded; unverified "
                         "and not_checkable fields are the writer's statement.")}
    return {"schema": SCHEMA, "consistent": not candidates, "checked_against": None, "fields": {},
            "contradictions": contradictions[:5]}


__all__ = ["CHECKED_FIELDS", "SCHEMA", "check_action", "check_conditions", "cited_actions", "route_matches"]
