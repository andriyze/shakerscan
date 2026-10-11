"""What an interpretation depends on, captured when it is written, and how a dependency changed.

An entry is learned under conditions. This module records which observable records those
conditions rest on (the dependencies), reads their current state from existing records, and
compares the two. It never sends traffic: every value comes from records other flows already keep.

Dependency types and where their state is read:

* ``endpoint``: the route in the endpoint inventory (``target_endpoints``), by method and
  normalized path;
* ``response``: the latest ``http.request`` action of a Hunt on the asset with the same method,
  path and session reference (the action's own response summary: status, media type, JSON key
  set and the body digest, which is read from the action and never copied here);
* ``deployment``: technologies, versions and server banners from the latest completed Scan that
  recorded them (``scans.result.discovery``);
* ``auth_surface``: the login, token and session routes in the endpoint inventory;
* ``service``: one device service (``device_services``) by transport and port;
* ``finding``: what an operator's dismissal was decided about (severity, URL, tool, verification);
* ``subject``: the record an entry is about still exists.

Significance is explicit (``SIGNIFICANCE_RULES``) and only a significant change moves an entry
out of ``applicable``. Age is never a dependency. A dependency that could not be observed when
the entry was written, or cannot be compared now, leaves the entry ``unknown``; unknown is never
treated as unchanged.

Body digests changed format between releases (a plain SHA-256, then installation-keyed digests).
Digests are compared only when both have the same format; otherwise the body comparison is
``incomparable`` and settles nothing.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable, Mapping
import uuid

SCHEMA = "knowledge-dependencies/v1"
MAX_ITEMS = 24
MAX_RESPONSE_DEPENDENCIES = 5
MAX_TECHNOLOGIES = 40
MAX_ENDPOINT_ROWS = 200
MAX_AUTH_ROUTES = 500
#: Recent http.request actions of an asset read per evaluation (newest first).
RESPONSE_WINDOW = 2000

SIGNIFICANT = "significant"
MINOR = "minor"
INCOMPARABLE = "incomparable"

#: The rules, published with every change report and applicability reason.
SIGNIFICANCE_RULES: dict[str, str] = {
    "endpoint": ("significant when every inventory row of the route is retired as gone (or the route is "
                 "deleted from the inventory); a route first appearing in the inventory, a new auth state "
                 "or a new parameter shape is minor (the inventory learned more)"),
    "response": ("compared with every later http.request of the same plain request (method, origin, path "
                 "without query, session; no headers, body or bindings) among the asset's latest "
                 f"{2000}: a different status code, media type or JSON key set in any of them is significant; "
                 "a different body digest alone is minor; digests of different formats are incomparable"),
    "deployment": ("compared with the latest later Scan of the same target that recorded technologies (a side "
                   "without technologies or banners compares nothing): a version change of a "
                   "technology seen in both, a versioned technology appearing or disappearing, or a changed "
                   "server banner is significant; an unversioned technology appearing or disappearing is minor; "
                   "a certificate renewal or address change is reported but changes no interpretation"),
    "auth_surface": ("significant when a login, token, session, sign-up, password or SSO route appears in or "
                     "disappears from the inventory"),
    "service": ("significant when the service is no longer observed open, or its product or version "
                "changed"),
    "finding": ("significant when the finding's severity or URL changed, or a verification recorded a new "
                "verdict (a verdict cleared when the scanner re-records evidence is not a change); a different "
                "tool name is minor; the finding being observed again, a new Scan or a release alone is not"),
    "subject": "the record an entry is about no longer exists (or its route is gone): the entry is historical",
    "age": "never: how old an entry is changes nothing",
}

#: Routes that make up the authentication surface (paths, case-insensitive).
AUTH_ROUTE_PATTERN = (r"(^|/)(login|logout|signin|sign-in|signout|signup|sign-up|register|auth|oauth2?|"
                      r"openid|oidc|sso|saml|token|tokens|session|sessions|password|passwd|reset|mfa|2fa|otp)"
                      r"(/|$|\.|-|_)")
_AUTH_ROUTE = re.compile(AUTH_ROUTE_PATTERN, re.I)
_OPERATION = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S*)$", re.I)
_SERVICE = re.compile(r"^(?:(tcp|udp)\s*/\s*(\d{1,5})|(\d{1,5})\s*/\s*(tcp|udp))$", re.I)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _json(value: Any, default: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value if value is not None else default


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def normalize_route(path: Any) -> str | None:
    """The inventory's path form: no query or fragment, volatile id segments templated."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048:
        return None
    path = path.split("?", 1)[0].split("#", 1)[0]
    try:
        from asm_inventory import normalize_path
    except ModuleNotFoundError:  # package import
        from ..asm_inventory import normalize_path
    return normalize_path(path)


def auth_route(path: Any) -> bool:
    return isinstance(path, str) and bool(_AUTH_ROUTE.search(path))


def digest_format(value: Any) -> str | None:
    """The scheme a body digest was made with, so digests of different schemes are never compared."""
    if not isinstance(value, str) or not value:
        return None
    if _HEX64.fullmatch(value):
        return "sha256"
    for prefix in ("scrypt-", "hmac-"):
        if value.startswith(prefix):
            return value.split(":", 1)[0][:64]
    return "unrecognized"


def media_type(value: Any) -> str | None:
    text = str(value or "").split(";", 1)[0].strip().lower()
    return text[:100] or None


def operation_route(conditions: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """(method, normalized path) named by the conditions, from route/method or an operation like
    ``GET /api/orders/{id}``."""
    method = conditions.get("method")
    route = conditions.get("route")
    if not route and isinstance(conditions.get("operation"), str):
        match = _OPERATION.match(conditions["operation"].strip())
        if match:
            method, route = match.group(1), match.group(2)
    normalized = normalize_route(route)
    return (str(method).upper() if method else None), normalized


def service_key(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, str):
        return None
    match = _SERVICE.match(value.strip())
    if not match:
        return None
    transport = (match.group(1) or match.group(4)).lower()
    port = int(match.group(2) or match.group(3))
    return (transport, port) if 1 <= port <= 65535 else None


# --- pure comparisons ---------------------------------------------------------------------------

def _change(item: Mapping[str, Any], field: str, significance: str, before: Any, after: Any,
            **extra: Any) -> dict[str, Any]:
    return {"type": item["type"], "key": item["key"], "field": field, "significance": significance,
            "before": before, "after": after, "rule": SIGNIFICANCE_RULES[item["type"]], **extra}


def compare_endpoint(item: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    before, changes = item["observed"], []
    if before.get("present") and not current.get("present"):
        changes.append(_change(item, "present", SIGNIFICANT, True, False,
                               historical=bool(item.get("is_subject"))))
    elif not before.get("present") and current.get("present"):
        changes.append(_change(item, "present", MINOR, False, True))
    if before.get("present") and current.get("present"):
        if sorted(before.get("auth_states") or []) != sorted(current.get("auth_states") or []):
            changes.append(_change(item, "auth_states", MINOR, before.get("auth_states"), current.get("auth_states")))
        if before.get("param_shapes_sha256") != current.get("param_shapes_sha256"):
            changes.append(_change(item, "param_shapes", MINOR, before.get("param_shapes_sha256"),
                                   current.get("param_shapes_sha256")))
    return changes


def compare_response(item: Mapping[str, Any], newer: Mapping[str, Any] | None, *,
                     recorded_body: Any = None, newer_body: Any = None) -> list[dict[str, Any]]:
    """``newer`` is the latest later observation of the same request, or None (nothing newer)."""
    if not newer:
        return []
    before, changes = item["observed"], []
    for field in ("status", "media_type", "json_keys_sha256"):
        if before.get(field) != newer.get(field):
            changes.append(_change(item, field, SIGNIFICANT, before.get(field), newer.get(field),
                                   observed_by=newer.get("action_id"), observed_at=newer.get("completed_at")))
    old_format, new_format = digest_format(recorded_body), digest_format(newer_body)
    if old_format and new_format:
        if old_format != new_format:
            changes.append(_change(item, "body_digest", INCOMPARABLE, old_format, new_format,
                                   note="digests of different formats are never compared"))
        elif recorded_body != newer_body:
            changes.append(_change(item, "body_digest", MINOR, "earlier digest", "different digest"))
    return changes


def compare_deployment(item: Mapping[str, Any], newer: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not newer:
        return []
    before, changes = item["observed"], []
    old = dict(before.get("technologies") or {})
    new = dict(newer.get("technologies") or {})
    # A side that recorded no technologies (or no banners) observed nothing to compare; absence of
    # data is not a change.
    names = sorted(set(old) | set(new)) if old and new else []
    for name in names:
        if name in old and name in new:
            if old[name] and new[name] and old[name] != new[name]:
                changes.append(_change(item, f"technology:{name}", SIGNIFICANT, old[name], new[name],
                                       observed_by=newer.get("scan_id")))
            elif bool(old[name]) != bool(new[name]):
                changes.append(_change(item, f"technology:{name}", MINOR, old[name], new[name],
                                       observed_by=newer.get("scan_id")))
        else:
            versioned = bool(old.get(name) or new.get(name))
            changes.append(_change(item, f"technology:{name}", SIGNIFICANT if versioned else MINOR,
                                   old.get(name, "absent") if name in old else "absent",
                                   new.get(name, "absent") if name in new else "absent",
                                   observed_by=newer.get("scan_id")))
    if before.get("server_banners") and newer.get("server_banners") \
            and before.get("server_banners_sha256") != newer.get("server_banners_sha256"):
        changes.append(_change(item, "server_banners", SIGNIFICANT, before.get("server_banners"),
                               newer.get("server_banners"), observed_by=newer.get("scan_id")))
    return changes


def compare_auth_surface(item: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    before = item["observed"]
    if before.get("routes_sha256") == current.get("routes_sha256"):
        return []
    return [_change(item, "routes", SIGNIFICANT, before.get("count"), current.get("count"))]


def compare_service(item: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    before, changes = item["observed"], []
    was_open = before.get("present") and str(before.get("state")) != "not_observed"
    is_open = current.get("present") and str(current.get("state")) != "not_observed"
    if was_open != is_open:
        changes.append(_change(item, "state", SIGNIFICANT, before.get("state"), current.get("state")))
    for field in ("product", "version"):
        if before.get("present") and current.get("present") and before.get(field) != current.get(field):
            changes.append(_change(item, field, SIGNIFICANT, before.get(field), current.get(field)))
    return changes


def compare_finding(item: Mapping[str, Any], current: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    before = item["observed"]
    if current is None:
        return [_change(item, "exists", SIGNIFICANT, True, False, historical=True)]
    changes = []
    for field in ("severity", "url"):
        if before.get(field) != current.get(field):
            changes.append(_change(item, field, SIGNIFICANT, before.get(field), current.get(field)))
    # The scanner clears the verdict when it re-records evidence; only a new verdict is a change.
    verdict = current.get("last_verification_verdict")
    if verdict is not None and verdict != before.get("last_verification_verdict"):
        changes.append(_change(item, "last_verification_verdict", SIGNIFICANT,
                               before.get("last_verification_verdict"), verdict))
    if before.get("tool") != current.get("tool"):
        changes.append(_change(item, "tool", MINOR, before.get("tool"), current.get("tool")))
    return changes


def compare_subject(item: Mapping[str, Any], exists: bool) -> list[dict[str, Any]]:
    if item["observed"].get("exists") and not exists:
        return [_change(item, "exists", SIGNIFICANT, True, False, historical=True)]
    return []


def decide(recorded: Mapping[str, Any], changes: list[dict[str, Any]], incomparable: list[dict[str, Any]]) -> str:
    """The applicability an evaluation supports (needs_revalidation and historical are sticky; the
    caller never moves an entry back from them)."""
    if any(change.get("historical") for change in changes):
        return "historical"
    if any(change["significance"] == SIGNIFICANT for change in changes):
        return "needs_revalidation"
    if not recorded.get("items") or recorded.get("unobserved") or incomparable:
        return "unknown"
    return "applicable"


# --- observation from existing records ----------------------------------------------------------

def asset_scope(column: str, placeholder: str = "$1") -> str:
    """The rows of one asset: the target itself and, for a host asset, its service members."""
    return f"{column} IN (SELECT id FROM targets WHERE id={placeholder} OR asset_owner_id={placeholder})"


def _response_view(row: Mapping[str, Any]) -> dict[str, Any] | None:
    result = _json(row.get("result_summary"), {}) or {}
    observations = result.get("observations") if isinstance(result, Mapping) else None
    response = None
    for item in observations or ():
        if isinstance(item, Mapping) and item.get("kind") == "http_observation" \
                and isinstance(item.get("response"), Mapping):
            response = item["response"]
            break
    if response is None:
        return None
    status = response.get("status")
    keys = response.get("json_keys")
    return {"action_id": str(row["id"]), "completed_at": _iso(row.get("completed_at")),
            "status": status if isinstance(status, int) else None,
            "media_type": media_type(response.get("content_type")),
            "json_keys_sha256": _sha(sorted(str(key) for key in keys)) if isinstance(keys, list) else None,
            "body_digest_format": digest_format(response.get("body_sha256")),
            "_body": response.get("body_sha256")}


#: Request options that change what was sent beyond method, origin, path and session. A request
#: carrying any of them (or a query string) is never the same request as a plain one.
_REQUEST_OPTIONS = ("headers", "body", "json_body", "form", "request_bindings", "capture", "collection_id",
                    "request_collection_id", "request_collection_ref", "query", "params")


def _request_view(row: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
    """(method, origin and path, session) of a plain recorded request: no query string and no
    headers, body or bindings. Anything else is not comparable and returns None."""
    summary = _json(row.get("input_summary"), {}) or {}
    values = summary.get("input") if isinstance(summary, Mapping) else None
    if not isinstance(values, Mapping) or not isinstance(values.get("path"), str):
        return None
    path = values["path"][:2048]
    if not path.startswith("/") or "?" in path or "#" in path or any(values.get(key) for key in _REQUEST_OPTIONS):
        return None
    origin = str(values.get("origin") or "")[:300]
    return (str(values.get("method") or "GET").upper()[:10], path, str(values.get("session_ref") or "")[:64],
            origin)


class Observer:
    """Reads the current state of dependencies for one asset, each value once per evaluation."""

    def __init__(self, conn: Any, target_id: Any):
        self.conn = conn
        self.target = uuid.UUID(str(target_id))
        self._memo: dict[Any, Any] = {}

    async def _cached(self, key: Any, reader: Any) -> Any:
        if key not in self._memo:
            self._memo[key] = await reader()
        return self._memo[key]

    async def endpoint(self, method: str | None, path: str) -> dict[str, Any]:
        async def read() -> dict[str, Any]:
            rows = await self.conn.fetch(f"""SELECT method, auth_state, param_shape, test_status FROM target_endpoints
                WHERE {asset_scope('target_id')} AND path=$2 AND ($3::text IS NULL OR method=$3)
                ORDER BY id LIMIT {MAX_ENDPOINT_ROWS}""", self.target, path, method)
            live = [row for row in rows if row["test_status"] != "gone"]
            return {"present": bool(live), "rows": len(live),
                    "auth_states": sorted({str(row["auth_state"]) for row in live}),
                    "param_shapes_sha256": _sha(sorted({f"{row['method']} {row['param_shape']}" for row in live}))}
        return await self._cached(("endpoint", method, path), read)

    async def _requests(self) -> dict[tuple[str, str, str, str], list[dict[str, Any]]]:
        """The asset's most recent plain http.request responses, grouped by request identity, newest
        first: one bounded read per evaluation instead of one query per dependency."""
        async def read() -> dict[tuple[str, str, str, str], list[dict[str, Any]]]:
            rows = await self.conn.fetch(f"""SELECT a.id, a.completed_at, a.input_summary, a.result_summary
                FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
                WHERE {asset_scope('COALESCE(h.device_target_id, h.target_id)')}
                  AND a.capability_name='http.request' AND a.status IN ('completed','partial')
                  AND a.completed_at IS NOT NULL
                ORDER BY a.completed_at DESC, a.id DESC LIMIT {RESPONSE_WINDOW}""", self.target)
            grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
            for row in rows:
                request, view = _request_view(row), _response_view(row)
                if request is not None and view is not None:
                    grouped.setdefault(request, []).append({**view, "_at": _time(row["completed_at"])})
            return grouped
        return await self._cached(("requests",), read)

    async def responses_after(self, identity: tuple[str, str, str, str], after: Any, *,
                              exclude: Any = None) -> list[dict[str, Any]]:
        """Every later observation of the same plain request (newest first, at most 50)."""
        moment = _time(after)
        rows = (await self._requests()).get(identity, [])
        return [row for row in rows if moment is not None and row["_at"] > moment
                and row["action_id"] != str(exclude)][:50]

    async def response(self, identity: tuple[str, str, str, str], *, after: Any = None,
                       before: Any = None) -> dict[str, Any] | None:
        """The latest observation of the same plain request after (or at or before) a time."""
        rows = (await self._requests()).get(identity, [])
        for row in rows:
            if (after is None or row["_at"] > _time(after)) and (before is None or row["_at"] <= _time(before)):
                return row
        return None

    async def action_body(self, action_id: Any) -> Any:
        async def read() -> Any:
            row = await self.conn.fetchrow("SELECT id, completed_at, result_summary FROM hunt_actions WHERE id=$1",
                                           uuid.UUID(str(action_id)))
            view = _response_view(row) if row else None
            return view.get("_body") if view else None
        return await self._cached(("body", str(action_id)), read)

    async def deployment(self, *, after: Any = None, before: Any = None) -> dict[str, Any] | None:
        """The latest completed Scan of this target (not its host's other services) that recorded
        technologies or server banners."""
        async def read() -> dict[str, Any] | None:
            row = await self.conn.fetchrow("""SELECT id, completed_at, result->'discovery' AS discovery,
                    result->'tls'->'certificate' AS certificate, result->'infrastructure'->'addresses' AS addresses
                FROM scans
                WHERE (target_id=$1 OR device_target_id=$1)
                  AND status='completed' AND completed_at IS NOT NULL
                  AND COALESCE(scan_role,'') <> 'shard'
                  AND (jsonb_typeof(result->'discovery'->'tech'->'items')='array'
                       OR jsonb_typeof(result->'discovery'->'server_versions')='object')
                  AND ($2::timestamptz IS NULL OR completed_at > $2)
                  AND ($3::timestamptz IS NULL OR completed_at <= $3)
                ORDER BY completed_at DESC, id DESC LIMIT 1""", self.target, _time(after), _time(before))
            return deployment_view(row) if row else None
        return await self._cached(("deployment", str(after), str(before)), read)

    async def auth_surface(self) -> dict[str, Any]:
        async def read() -> dict[str, Any]:
            rows = await self.conn.fetch(f"""SELECT DISTINCT method, path FROM target_endpoints
                WHERE {asset_scope('target_id')} AND test_status <> 'gone' AND path ~* $2
                ORDER BY method, path LIMIT {MAX_AUTH_ROUTES + 1}""", self.target, AUTH_ROUTE_PATTERN)
            routes = sorted(f"{row['method']} {row['path']}" for row in rows[:MAX_AUTH_ROUTES])
            return {"routes_sha256": _sha(routes), "count": len(routes), "at_least": len(rows) > MAX_AUTH_ROUTES}
        return await self._cached(("auth",), read)

    async def service(self, transport: str, port: int) -> dict[str, Any]:
        async def read() -> dict[str, Any]:
            row = await self.conn.fetchrow("""SELECT state, product, version FROM device_services
                WHERE device_target_id IN (SELECT id FROM targets WHERE id=$1
                                           OR id=(SELECT asset_owner_id FROM targets WHERE id=$1))
                  AND transport=$2 AND port=$3 ORDER BY last_seen_at DESC LIMIT 1""", self.target, transport, port)
            if row is None:
                return {"present": False}
            return {"present": True, "state": row["state"], "product": row["product"], "version": row["version"]}
        return await self._cached(("service", transport, port), read)

    async def finding(self, finding_id: Any) -> dict[str, Any] | None:
        async def read() -> dict[str, Any] | None:
            row = await self.conn.fetchrow(f"""SELECT severity, url, tool, last_verification_verdict FROM findings
                WHERE id=$2 AND {asset_scope('target_id')}""", self.target, uuid.UUID(str(finding_id)))
            return finding_view(row) if row else None
        return await self._cached(("finding", str(finding_id)), read)

    async def subject(self, subject_type: str, subject_id: Any) -> bool:
        tables = {"finding": "findings", "hypothesis": "hypotheses", "candidate": "investigation_candidates",
                  "authorization_investigation": "application_graph_nodes", "endpoint": "target_endpoints"}
        table = tables.get(subject_type)
        if table is None:
            return True  # interpretations are never deleted; their own status covers them

        async def read() -> bool:
            gone = " AND test_status <> 'gone'" if subject_type == "endpoint" else ""
            return bool(await self.conn.fetchval(
                f"SELECT 1 FROM {table} WHERE id=$2 AND {asset_scope('target_id')}{gone}",
                self.target, uuid.UUID(str(subject_id))))
        return await self._cached(("subject", subject_type, str(subject_id)), read)


def deployment_view(row: Mapping[str, Any]) -> dict[str, Any]:
    discovery = _json(row.get("discovery"), {}) or {}
    technologies: dict[str, Any] = {}
    tech = discovery.get("tech") if isinstance(discovery, Mapping) else None
    seen: dict[str, Any] = {}
    for item in (tech.get("items") if isinstance(tech, Mapping) else None) or ():
        name = str(item.get("name") if isinstance(item, Mapping) else item or "").strip()[:80]
        if not name or name in seen:
            continue
        version = item.get("version") if isinstance(item, Mapping) else None
        seen[name] = str(version)[:40] if version not in (None, "") else None
    # Sorted before the cap, so the order a Scan listed them in never makes names come and go.
    for name in sorted(seen)[:MAX_TECHNOLOGIES]:
        technologies[name] = seen[name]
    banners = discovery.get("server_versions") if isinstance(discovery, Mapping) else None
    banner_values = sorted({str(value)[:120] for value in (banners or {}).values()}) if isinstance(banners, Mapping) else []
    certificate = _json(row.get("certificate"), None)
    fingerprints = certificate.get("fingerprints") if isinstance(certificate, Mapping) else None
    addresses = _json(row.get("addresses"), None)
    return {"scan_id": str(row["id"]), "completed_at": _iso(row.get("completed_at")),
            "technologies": dict(sorted(technologies.items())),
            "server_banners": banner_values[:10], "server_banners_sha256": _sha(banner_values),
            "certificate_sha256": (fingerprints or {}).get("sha256") if isinstance(fingerprints, Mapping) else None,
            "certificate_not_after": certificate.get("not_after") if isinstance(certificate, Mapping) else None,
            "addresses_sha256": _sha(sorted(str(a) for a in addresses)) if isinstance(addresses, list) else None}


def finding_view(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: (str(row[key]) if row[key] is not None else None)
            for key in ("severity", "url", "tool", "last_verification_verdict")}


# --- binding of an experiment's conditions to what ran -------------------------------------------

def _placeholder(segment: str) -> bool:
    return len(segment) > 2 and segment.startswith("{") and segment.endswith("}")


def _route_matches(route: str, path: str) -> bool:
    """A condition route matches the path an action requested: segment by segment equal, with a
    ``{name}`` placeholder allowed only where the inventory's own normalization templates the
    requested segment (a number, UUID or long hex id). ``/{a}/{b}`` never matches ``/api/orders``."""
    template = route.split("/")
    concrete = path.split("/")
    normalized = (normalize_route(path) or path).split("/")
    if not (len(template) == len(concrete) == len(normalized)):
        return False
    return all(t == c or (_placeholder(t) and _placeholder(n)) for t, c, n in zip(template, concrete, normalized))


def _object_named(value: str, path: str) -> bool:
    """An object is bound when its identifier (``invoice:17`` -> ``17``) is a segment of the path."""
    identifier = value.rsplit(":", 1)[-1].strip()
    return bool(identifier) and identifier in path.split("/")


#: The only condition fields a recorded request can confirm. Any other field (roles, inputs, service,
#: environment, deployment fingerprint, tool version, application state, budget) cannot be checked
#: against what was sent, so its presence leaves the experiment unbound.
BINDABLE_FIELDS = frozenset({"method", "route", "operation", "principals", "objects", "technique"})


def bind_experiment(conditions: Mapping[str, Any], cited: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Whether the experiment's conditions are what one cited testing action actually requested.

    Bound only when one cited ``http.request`` of the writing Hunt recorded a plain request (no
    query string, headers, body or bindings) and:

    * the conditions name only method, route or operation, principals, objects and technique;
    * the method is the conditions' method (default GET);
    * the path is the conditions' route as written: segments equal, a ``{name}`` placeholder only
      where the path holds an identifier, and then every placeholder covered by a named object;
    * every named object's identifier (``invoice:17`` -> ``17``) is a segment of the path;
    * exactly one principal is named and it is the request's ``session_ref`` (``anonymous``
      without a session);
    * the technique's first word is ``http.request``.

    Anything else is unbound: the entry is kept as a record, but never lets an experiment be
    skipped. The binding does not judge the response; the negative conclusion stays the writer's.
    """
    if set(conditions) - BINDABLE_FIELDS:
        return {"bound": False, "reasons": ["conditions name fields a recorded request cannot confirm: "
                                            + ", ".join(sorted(set(conditions) - BINDABLE_FIELDS))]}
    method = str(conditions.get("method") or "").upper() or None
    route = conditions.get("route")
    if not route and isinstance(conditions.get("operation"), str):
        match = _OPERATION.match(conditions["operation"].strip())
        if match:
            method, route = match.group(1).upper(), match.group(2)
    if not isinstance(route, str) or not route.startswith("/"):
        return {"bound": False, "reasons": ["the conditions name no route (method and route, or an operation such as "
                                            "GET /path) to compare with the request"]}
    principals = list(conditions.get("principals") or [])
    objects = [str(value) for value in conditions.get("objects") or []]
    technique = str(conditions.get("technique") or "").strip().split()
    reasons: list[str] = []
    for row in cited:
        request = _request_view(row)
        if request is None:
            reasons.append(f"action {row['id']}: not a plain request (a query string, headers, body or bindings), "
                           "or no request was recorded")
            continue
        req_method, path, session, _origin = request
        mismatch = []
        if (method or "GET") != req_method:
            mismatch.append("method")
        if not _route_matches(route, path):
            mismatch.append("route")
        if any(not _object_named(value, path) for value in objects) or \
                (any(_placeholder(part) for part in route.split("/")) and not objects):
            mismatch.append("objects")
        if len(principals) != 1 or principals[0] != (session or "anonymous"):
            mismatch.append("principals")
        if not technique or technique[0].rstrip(":,;").casefold() != "http.request":
            mismatch.append("technique")
        if not mismatch:
            return {"bound": True, "action_id": str(row["id"]), "method": req_method, "path": path,
                    "session_ref": session or None}
        reasons.append(f"action {row['id']}: " + ", ".join(mismatch) + " differ from the recorded request")
    if not cited:
        reasons.append("no cited http.request of this Hunt recorded the request (other capabilities are not bound)")
    return {"bound": False, "reasons": reasons[:5]}


# --- capture ------------------------------------------------------------------------------------

async def _cited_requests(conn: Any, target: uuid.UUID, refs: Iterable[str], *,
                          hunt_run_id: Any = None) -> list[Mapping[str, Any]]:
    """Cited http.request actions on this asset; for a Hunt writer, only its own."""
    identifiers = [uuid.UUID(ref) for ref in refs]
    if not identifiers:
        return []
    return list(await conn.fetch(f"""SELECT a.id, a.completed_at, a.input_summary, a.result_summary
        FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
        WHERE (a.id = ANY($2::uuid[]) OR a.receipt_id = ANY($2::uuid[]))
          AND a.capability_name='http.request' AND a.status IN ('completed','partial')
          AND ($3::uuid IS NULL OR a.hunt_run_id=$3)
          AND {asset_scope('COALESCE(h.device_target_id, h.target_id)')}
        ORDER BY a.completed_at DESC NULLS LAST LIMIT {MAX_RESPONSE_DEPENDENCIES}""", target, identifiers,
        uuid.UUID(str(hunt_run_id)) if hunt_run_id else None))


async def capture(conn: Any, target_id: Any, *, kind: str, negative_state: str | None,
                  conditions: Mapping[str, Any], subject: Mapping[str, Any] | None = None,
                  evidence_refs: Iterable[str] = (), finding: Mapping[str, Any] | None = None,
                  hunt_run_id: Any = None) -> dict[str, Any]:
    """The dependencies of one entry, observed now. Never raises for a missing record: what cannot
    be observed is listed in ``unobserved`` and keeps the entry ``unknown``."""
    target = uuid.UUID(str(target_id))
    observer = Observer(conn, target)
    items: list[dict[str, Any]] = []
    unobserved: list[dict[str, Any]] = []
    keys: set[tuple[str, str]] = set()

    def add(item: dict[str, Any]) -> None:
        if (item["type"], item["key"]) not in keys and len(items) < MAX_ITEMS:
            keys.add((item["type"], item["key"]))
            items.append(item)

    specific = False
    if subject and subject.get("type") and subject.get("id"):
        exists = await observer.subject(str(subject["type"]), subject["id"])
        add({"type": "subject", "key": f"{subject['type']}:{subject['id']}", "observed": {"exists": exists}})
        if subject["type"] == "endpoint" and exists:
            row = await conn.fetchrow("SELECT method, path FROM target_endpoints WHERE id=$1", uuid.UUID(str(subject["id"])))
            if row is not None:
                add({"type": "endpoint", "key": f"{row['method']} {row['path']}", "method": row["method"],
                     "path": row["path"], "is_subject": True,
                     "observed": await observer.endpoint(row["method"], row["path"])})
                specific = True

    method, route = operation_route(conditions)
    if route:
        add({"type": "endpoint", "key": f"{method or '*'} {route}", "method": method, "path": route,
             "observed": await observer.endpoint(method, route)})
        specific = True

    cited = await _cited_requests(conn, target, evidence_refs, hunt_run_id=hunt_run_id)
    binding = (bind_experiment(conditions, cited) if negative_state == "experiment_completed_negative" else None)
    for row in cited:
        request = _request_view(row)
        view = _response_view(row)
        if request is None or view is None:
            unobserved.append({"type": "response", "key": str(row["id"]),
                               "reason": "the cited request is not a plain request (query string, headers, body or "
                                         "bindings) or recorded no response summary"})
            continue
        req_method, path, session, origin = request
        observed = {key: value for key, value in view.items() if not key.startswith("_")}
        add({"type": "response", "key": f"{req_method} {origin}{path} session:{session or 'none'}",
             "method": req_method, "path": path, "session_ref": session, "origin": origin, "observed": observed})
        normalized = normalize_route(path)
        if normalized:
            add({"type": "endpoint", "key": f"{req_method} {normalized}", "method": req_method, "path": normalized,
                 "observed": await observer.endpoint(req_method, normalized)})
        specific = True

    located = service_key(conditions.get("service"))
    if located:
        add({"type": "service", "key": f"{located[0]}/{located[1]}", "transport": located[0], "port": located[1],
             "observed": await observer.service(*located)})
        specific = True

    if finding is not None:
        # A dismissal depends on what it was decided about, only: Scans, banners and inventory
        # changes are reported by knowledge.changes but never reopen a person's decision.
        add({"type": "finding", "key": str(finding["id"]), "observed": finding_view(finding)})
        return {"schema": SCHEMA, "captured_at": _now().isoformat(), "items": items, "unobserved": unobserved,
                "for": negative_state or kind}

    if conditions.get("principals") or conditions.get("roles") or (route and auth_route(route)):
        add({"type": "auth_surface", "key": "auth", "observed": await observer.auth_surface()})

    # Deployment-wide versions matter to what was observed of the application's behaviour, not
    # to a plan or a free note.
    if specific or kind in {"observation", "explanation", "negative_result"}:
        deployment = await observer.deployment()
        if deployment is None:
            unobserved.append({"type": "deployment", "key": "scan",
                               "reason": "no completed Scan of this asset has recorded technologies yet"})
        else:
            add({"type": "deployment", "key": "scan", "observed": deployment})

    if not items and not unobserved and binding is None:
        return {}
    result = {"schema": SCHEMA, "captured_at": _now().isoformat(), "items": items, "unobserved": unobserved,
              "for": negative_state or kind}
    if binding is not None:
        result["binding"] = binding
    return result


async def evaluate(observer: Observer, recorded: Mapping[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """(state, changes, incomparable) for one entry's recorded dependencies, read from ``observer``."""
    if not isinstance(recorded, Mapping) or recorded.get("schema") != SCHEMA:
        return "unknown", [], []
    changes: list[dict[str, Any]] = []
    for item in recorded.get("items") or ():
        kind = item.get("type")
        if kind == "endpoint":
            changes += compare_endpoint(item, await observer.endpoint(item.get("method"), item["path"]))
        elif kind == "response":
            observed = item["observed"]
            identity = (item["method"], item["path"], item.get("session_ref") or "", item.get("origin") or "")
            later = await observer.responses_after(identity, observed.get("completed_at"),
                                                   exclude=observed.get("action_id"))
            recorded_body = await observer.action_body(observed["action_id"]) if later else None
            # Every later observation counts: a later one that looks unchanged never hides one that did not.
            seen: set[str] = set()
            for index, newer in enumerate(later):
                for change in compare_response(item, newer, recorded_body=recorded_body if index == 0 else None,
                                               newer_body=newer.get("_body") if index == 0 else None):
                    if change["field"] not in seen:
                        seen.add(change["field"])
                        changes.append(change)
        elif kind == "deployment":
            changes += compare_deployment(item, await observer.deployment(after=item["observed"].get("completed_at")))
        elif kind == "auth_surface":
            changes += compare_auth_surface(item, await observer.auth_surface())
        elif kind == "service":
            changes += compare_service(item, await observer.service(item["transport"], int(item["port"])))
        elif kind == "finding":
            changes += compare_finding(item, await observer.finding(item["key"]))
        elif kind == "subject":
            subject_type, _, subject_id = str(item["key"]).partition(":")
            changes += compare_subject(item, await observer.subject(subject_type, subject_id))
    incomparable = [change for change in changes if change["significance"] == INCOMPARABLE]
    return decide(recorded, changes, incomparable), changes, incomparable


def public_dependencies(recorded: Any) -> dict[str, Any]:
    """What a reader sees: types, keys and when they were observed; no digests of bodies."""
    recorded = _json(recorded, {}) or {}
    if not isinstance(recorded, Mapping) or not recorded:
        return {"tracked": False}
    return {"tracked": True, "captured_at": recorded.get("captured_at"),
            **({"binding": recorded["binding"]} if isinstance(recorded.get("binding"), Mapping) else {}),
            "items": [{"type": item.get("type"), "key": item.get("key"),
                       "observed_at": (item.get("observed") or {}).get("completed_at")}
                      for item in recorded.get("items") or ()],
            "unobserved": list(recorded.get("unobserved") or [])}


__all__ = [
    "AUTH_ROUTE_PATTERN", "INCOMPARABLE", "MINOR", "Observer", "SCHEMA", "SIGNIFICANCE_RULES", "SIGNIFICANT",
    "asset_scope", "auth_route", "bind_experiment", "capture", "compare_auth_surface", "compare_deployment", "compare_endpoint",
    "compare_finding", "compare_response", "compare_service", "compare_subject", "decide", "deployment_view",
    "digest_format", "evaluate", "media_type", "normalize_route", "operation_route", "public_dependencies",
    "service_key",
]
