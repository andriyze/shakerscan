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
from urllib.parse import urlsplit
import uuid

SCHEMA = "knowledge-dependencies/v1"
MAX_ITEMS = 24
MAX_RESPONSE_DEPENDENCIES = 5
MAX_TECHNOLOGIES = 40
MAX_ENDPOINT_ROWS = 200
MAX_AUTH_ROUTES = 500

SIGNIFICANT = "significant"
MINOR = "minor"
INCOMPARABLE = "incomparable"

#: The rules, published with every change report and applicability reason.
SIGNIFICANCE_RULES: dict[str, str] = {
    "endpoint": ("significant when every inventory row of the route is retired as gone (or the route is "
                 "deleted from the inventory); a route first appearing in the inventory, a new auth state "
                 "or a new parameter shape is minor (the inventory learned more)"),
    "reuse": ("applicable is not safe to skip: a skip needs the same plain request (method, path, origin, "
              "session) repeated by a Hunt after the asking Hunt started, every response unchanged, body digest "
              "included; Scans and the inventory never authorise a skip"),
    "response": ("compared with every later http.request of the same plain request (method, origin, path "
                 "without query, session; nothing else in the request): a different status code, media type or "
                 "JSON key set in any of them is significant; a different body digest is significant for a "
                 "negative result and minor otherwise; digests of different formats are incomparable"),
    "deployment": ("compared with the latest later Scan of the same target that recorded technologies (a side "
                   "without technologies or banners compares nothing): a version change of a "
                   "technology seen in both, a versioned technology appearing or disappearing, or a changed "
                   "server banner is significant; an unversioned technology appearing or disappearing is minor; "
                   "a certificate renewal or address change is reported but changes no interpretation"),
    "auth_surface": ("significant when a login, token, session, sign-up, password or SSO route appears in or "
                     "disappears from the inventory"),
    "service": ("significant when the service is no longer observed open, or its product or version "
                "changed"),
    "finding": ("significant when the finding's severity rose, its URL changed, it was resolved and detected "
                "again (resurfaced), or a verifier proved it exploited while it is dismissed as a false positive "
                "or duplicate; a verdict agreeing with the dismissal, an error, inconclusive or cleared verdict, a "
                "lower severity, a tool name, new scanner evidence for the same issue, a Scan or a release alone "
                "are not; a dismissal of a finding merged into another follows the surviving finding"),
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
                     recorded_body: Any = None, newer_body: Any = None,
                     body_significant: bool = False) -> list[dict[str, Any]]:
    """``newer`` is a later observation of the same request, or None (nothing newer).

    For a negative result (``body_significant``) a different body is significant: the same status
    and keys can carry another tenant's data."""
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
            changes.append(_change(item, "body_digest", SIGNIFICANT if body_significant else MINOR,
                                   "earlier digest", "different digest"))
    elif body_significant and (old_format or new_format):
        changes.append(_change(item, "body_digest", INCOMPARABLE, old_format, new_format,
                               note="one side recorded no body digest"))
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


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
#: Verdicts that contradict a dismissal as a false positive or a duplicate.
CONTRADICTING_VERDICTS = frozenset({"exploited"})


def compare_finding(item: Mapping[str, Any], current: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """A dismissal is re-decided when the finding got worse or came back, never on noise."""
    before = item["observed"]
    if current is None:
        return [_change(item, "exists", SIGNIFICANT, True, False, historical=True)]
    changes = []
    old_rank = _SEVERITY_ORDER.get(str(before.get("severity") or "").lower(), -1)
    new_rank = _SEVERITY_ORDER.get(str(current.get("severity") or "").lower(), -1)
    if new_rank > old_rank:
        changes.append(_change(item, "severity", SIGNIFICANT, before.get("severity"), current.get("severity")))
    elif new_rank != old_rank:
        changes.append(_change(item, "severity", MINOR, before.get("severity"), current.get("severity")))
    if before.get("url") != current.get("url"):
        changes.append(_change(item, "url", SIGNIFICANT, before.get("url"), current.get("url")))
    # Only a verifier proving the issue contradicts a false-positive or duplicate dismissal; a
    # verdict agreeing with it, an error, inconclusive or a cleared verdict is not a change.
    verdict = current.get("last_verification_verdict")
    if verdict != before.get("last_verification_verdict") and verdict is not None:
        contradicts = verdict in CONTRADICTING_VERDICTS and item.get("dismissal_reason") in {"false_positive",
                                                                                          "duplicate"}
        changes.append(_change(item, "last_verification_verdict", SIGNIFICANT if contradicts else MINOR,
                               before.get("last_verification_verdict"), verdict))
    # The finding was resolved and then detected again: a regression.
    if int(current.get("resurfaced_count") or 0) > int(before.get("resurfaced_count") or 0):
        changes.append(_change(item, "resurfaced", SIGNIFICANT, before.get("resurfaced_count"),
                               current.get("resurfaced_count")))
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
    return {"action_id": str(row["id"]) if row.get("id") else None, "completed_at": _iso(row.get("completed_at")),
            "status": status if isinstance(status, int) else None,
            "media_type": media_type(response.get("content_type")),
            "json_keys_sha256": _sha(sorted(str(key) for key in keys)) if isinstance(keys, list) else None,
            "body_digest_format": digest_format(response.get("body_sha256")),
            "_body": response.get("body_sha256")}


#: The only keys a recorded http.request input may hold to count as a plain request: method, path
#: (no query string), origin and session. Anything else (a body, which the ledger records as
#: ``body_kind``; ``as_principal``; ``via_address``; ``follow_redirects``; headers, query, captures,
#: bindings) makes it a different request, never comparable with a plain one.
PLAIN_REQUEST_KEYS = frozenset({"method", "path", "origin", "session_ref"})


def canonical_origin(value: Any) -> str | None:
    """``scheme://host[:port]`` lower-cased, the default port dropped; None for anything else
    (user info, a path, a query or a fragment, a scheme other than http or https)."""
    if not isinstance(value, str) or not value or len(value) > 300:
        return None
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    # A trailing dot is refused, not folded: "host." and "host" are compared as written elsewhere.
    if scheme not in {"http", "https"} or not host or host.endswith(".") or parts.username is not None \
            or parts.password is not None or parts.path not in {"", "/"} or parts.query or parts.fragment:
        return None
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    if port is None or (scheme, port) in {("https", 443), ("http", 80)}:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _request_view(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """The identity of a plain recorded request, or None when the request was not plain.

    The effective origin is the recorded one, or the Hunt's target origin when none was given."""
    summary = _json(row.get("input_summary"), {}) or {}
    values = summary.get("input") if isinstance(summary, Mapping) else None
    if not isinstance(values, Mapping) or not isinstance(values.get("path"), str):
        return None
    if set(values) - PLAIN_REQUEST_KEYS:
        return None
    path = values["path"]
    if len(path) > 2048 or not path.startswith("/") or "?" in path or "#" in path:
        return None
    origin = canonical_origin(values.get("origin") or row.get("default_origin"))
    if origin is None:
        return None
    return {"method": str(values.get("method") or "GET").upper()[:10], "path": path,
            "session_ref": str(values.get("session_ref") or "")[:64], "origin": origin}


def request_identity(view: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return view["method"], view["path"], view["session_ref"], view["origin"]


#: Joined to every read of http.request actions: the Hunt's target origin, the default for a
#: request that names none.
_ACTIONS_FROM = """FROM hunt_actions a JOIN hunt_runs h ON h.id=a.hunt_run_id
                LEFT JOIN targets t ON t.id = CASE WHEN h.target_id IS NOT NULL THEN h.target_id
                                                   ELSE h.device_target_id END"""
#: Distinct later responses of one request read at most; more is reported as a change.
MAX_DISTINCT_RESPONSES = 1000


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
            rows = await self.conn.fetch(f"""SELECT method, auth_state, param_shape, test_status, last_seen_at
                FROM target_endpoints
                WHERE {asset_scope('target_id')} AND path=$2 AND ($3::text IS NULL OR method=$3)
                ORDER BY id LIMIT {MAX_ENDPOINT_ROWS}""", self.target, path, method)
            live = [row for row in rows if row["test_status"] != "gone"]
            seen = [row["last_seen_at"] for row in live if row["last_seen_at"] is not None]
            return {"present": bool(live), "rows": len(live),
                    "auth_states": sorted({str(row["auth_state"]) for row in live}),
                    "param_shapes_sha256": _sha(sorted({f"{row['method']} {row['param_shape']}" for row in live})),
                    "_last_seen_at": max(seen) if seen else None}
        return await self._cached(("endpoint", method, path), read)

    async def _same_path(self, path: str, *, after: Any = None, before: Any = None, exclude: Any = None,
                         distinct: bool) -> list[Mapping[str, Any]]:
        """http.request actions on this asset to exactly ``path`` (an indexed lookup, no window)."""
        scope = f"({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})"
        if distinct:
            # Every distinct (request, response) pair after the point: a later change is never
            # hidden behind later unchanged requests, however many there are.
            sql = f"""SELECT DISTINCT jsonb_build_object('input', a.input_summary->'input') AS input_summary,
                    t.url AS default_origin,
                    jsonb_build_object('observations', jsonb_path_query_array(
                        a.result_summary, '$.observations[*] ? (@.kind == "http_observation")')) AS result_summary,
                    NULL::uuid AS id, NULL::timestamptz AS completed_at
                {_ACTIONS_FROM}
                WHERE a.capability_name='http.request' AND (a.input_summary->'input'->>'path')=$2
                  AND a.status IN ('completed','partial') AND a.completed_at IS NOT NULL AND {scope}
                  AND ($3::timestamptz IS NULL OR a.completed_at > $3)
                  AND ($4::timestamptz IS NULL OR a.completed_at <= $4)
                  AND ($5::uuid IS NULL OR a.id <> $5)
                LIMIT {MAX_DISTINCT_RESPONSES + 1}"""
        else:
            sql = f"""SELECT a.id, a.completed_at, a.input_summary, a.result_summary, t.url AS default_origin
                {_ACTIONS_FROM}
                WHERE a.capability_name='http.request' AND (a.input_summary->'input'->>'path')=$2
                  AND a.status IN ('completed','partial') AND a.completed_at IS NOT NULL AND {scope}
                  AND ($3::timestamptz IS NULL OR a.completed_at > $3)
                  AND ($4::timestamptz IS NULL OR a.completed_at <= $4)
                  AND ($5::uuid IS NULL OR a.id <> $5)
                ORDER BY a.completed_at DESC, a.id DESC LIMIT 200"""
        return list(await self.conn.fetch(sql, self.target, path, _time(after), _time(before),
                                          uuid.UUID(str(exclude)) if exclude else None))

    async def responses_after(self, identity: tuple[str, str, str, str], after: Any, *,
                              exclude: Any = None) -> tuple[list[dict[str, Any]], bool]:
        """Every distinct later response of the same plain request, and whether there were too many
        distinct ones to list (which callers treat as a change)."""
        async def read() -> tuple[list[dict[str, Any]], bool]:
            rows = await self._same_path(identity[1], after=after, exclude=exclude, distinct=True)
            views = []
            for row in rows[:MAX_DISTINCT_RESPONSES]:
                request, view = _request_view(row), _response_view(row)
                if request is not None and view is not None and request_identity(request) == tuple(identity):
                    views.append(view)
            return views, len(rows) > MAX_DISTINCT_RESPONSES
        return await self._cached(("after", tuple(identity), str(after), str(exclude)), read)

    async def response(self, identity: tuple[str, str, str, str], *, after: Any = None,
                       before: Any = None) -> dict[str, Any] | None:
        """The latest observation of the same plain request after (or at or before) a time, among
        the latest 200 requests to that path."""
        async def read() -> dict[str, Any] | None:
            for row in await self._same_path(identity[1], after=after, before=before, distinct=False):
                request, view = _request_view(row), _response_view(row)
                if request is not None and view is not None and request_identity(request) == tuple(identity):
                    return view
            return None
        return await self._cached(("latest", tuple(identity), str(after), str(before)), read)

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
            row = await self.conn.fetchrow(f"""SELECT severity, url, tool, last_verification_verdict,
                    resurfaced_count FROM findings
                WHERE id=$2 AND {asset_scope('target_id')}""", self.target, uuid.UUID(str(finding_id)))
            return finding_view(dict(row)) if row else None
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
    view: dict[str, Any] = {key: (str(row[key]) if row.get(key) is not None else None)
                            for key in ("severity", "url", "tool", "last_verification_verdict")}
    view["resurfaced_count"] = int(row.get("resurfaced_count") or 0)
    return view


# --- binding of an experiment's conditions to what ran -------------------------------------------

def _placeholder(segment: str) -> bool:
    return len(segment) > 2 and segment.startswith("{") and segment.endswith("}")


def _object_id(value: str) -> str:
    """``invoice:17`` -> ``17``; a bare value is its own id."""
    return value.rsplit(":", 1)[-1].strip()


def _route_binding(route: str, path: str, objects: list[str]) -> str | None:
    """None when the route as written is exactly the requested path with each placeholder filled by
    one named object; otherwise what differs.

    Segments are equal except placeholders. Each placeholder's segment in the path must be an
    identifier the inventory would template (number, UUID, long hex) and the id of exactly one named
    object; every named object fills exactly one placeholder; no named id may stand in a literal
    segment. ``/api/users/{uid}/invoices/{id}`` with only ``invoice:17`` is therefore unbound: user
    5 was part of the request and was not named.
    """
    template, concrete = route.split("/"), path.split("/")
    normalized = (normalize_route(path) or path).split("/")
    if not (len(template) == len(concrete) == len(normalized)):
        return "route"
    ids = [_object_id(value) for value in objects]
    if any(not identifier for identifier in ids) or len(set(ids)) != len(ids):
        return "objects"
    filled: list[str] = []
    for written, sent, templated in zip(template, concrete, normalized):
        if _placeholder(written):
            if not _placeholder(templated):
                return "route"
            if ids.count(sent) != 1:
                return "objects"
            filled.append(sent)
        elif written != sent:
            return "route"
        elif sent in ids:
            return "objects"
    if sorted(filled) != sorted(ids):
        return "objects"
    return None


#: The only condition fields a recorded request can confirm. Any other field (roles, inputs, service,
#: environment, deployment fingerprint, tool version, application state, budget) cannot be checked
#: against what was sent, so its presence leaves the experiment unbound.
BINDABLE_FIELDS = frozenset({"method", "route", "operation", "origin", "principals", "objects", "technique"})


def bind_experiment(conditions: Mapping[str, Any], cited: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Whether the experiment's conditions are what one cited testing action actually requested.

    Bound only when one cited ``http.request`` of the writing Hunt recorded a plain request (its
    recorded input holds only method, path, origin and session) and:

    * the conditions name only origin, method, route or operation, principals, objects, technique;
    * the origin (scheme, host and port) is named and is the request's effective origin;
    * the method is the conditions' method (default GET);
    * the route as written is the requested path, each placeholder filled by exactly one named
      object (see ``_route_binding``);
    * exactly one principal is named and it is the request's ``session_ref`` (``anonymous``
      without a session);
    * the technique's first word is ``http.request``.

    Anything else is unbound: the entry is kept as a record, but never lets an experiment be
    skipped. The binding does not judge the response; the negative conclusion stays the writer's.
    """
    if set(conditions) - BINDABLE_FIELDS:
        return {"bound": False, "reasons": ["conditions name fields a recorded request cannot confirm: "
                                            + ", ".join(sorted(set(conditions) - BINDABLE_FIELDS))]}
    origin = canonical_origin(conditions.get("origin"))
    if origin is None:
        return {"bound": False, "reasons": ["the conditions name no origin (scheme://host[:port]) to compare with "
                                            "the request"]}
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
            reasons.append(f"action {row['id']}: not a plain request (it carried a body, headers, query, "
                           "principal binding, address, redirect or capture option), or none was recorded")
            continue
        mismatch = []
        if request["origin"] != origin:
            mismatch.append("origin")
        if (method or "GET") != request["method"]:
            mismatch.append("method")
        differs = _route_binding(route, request["path"], objects)
        if differs:
            mismatch.append(differs)
        if len(principals) != 1 or principals[0] != (request["session_ref"] or "anonymous"):
            mismatch.append("principals")
        if not technique or technique[0].rstrip(":,;").casefold() != "http.request":
            mismatch.append("technique")
        if not mismatch:
            return {"bound": True, "action_id": str(row["id"]), "method": request["method"],
                    "path": request["path"], "origin": request["origin"],
                    "session_ref": request["session_ref"] or None}
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
    return list(await conn.fetch(f"""SELECT a.id, a.completed_at, a.input_summary, a.result_summary,
            t.url AS default_origin
        {_ACTIONS_FROM}
        WHERE (a.id = ANY($2::uuid[]) OR a.receipt_id = ANY($2::uuid[]))
          AND a.capability_name='http.request' AND a.status IN ('completed','partial')
          AND ($3::uuid IS NULL OR a.hunt_run_id=$3)
          AND ({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})
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
        item["observed"] = {key: value for key, value in dict(item["observed"]).items() if not key.startswith("_")}
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
                               "reason": "the cited request is not a plain request (a body, headers, query, "
                                         "principal binding, address, redirect or capture option) or recorded no "
                                         "response summary"})
            continue
        req_method, path, session, origin = request_identity(request)
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
        add({"type": "finding", "key": str(finding["id"]), "observed": finding_view(finding),
             "dismissal_reason": finding.get("dismissal_reason")})
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


NEGATIVE_FOR = frozenset({"experiment_completed_negative", "experiment_inconclusive", "hypothesis_refuted",
                          "finding_dismissed"})


async def _response_changes(observer: Observer, item: Mapping[str, Any], *, after: Any, exclude: Any,
                            body_significant: bool) -> tuple[list[dict[str, Any]], int]:
    """Changes across every distinct later response of the item's request, and how many there were."""
    observed = item["observed"]
    identity = (item["method"], item["path"], item.get("session_ref") or "", item.get("origin") or "")
    later, overflow = await observer.responses_after(identity, after, exclude=exclude)
    changes: list[dict[str, Any]] = []
    if overflow:
        changes.append(_change(item, "responses", SIGNIFICANT, None, f"more than {MAX_DISTINCT_RESPONSES} different",
                               note="too many different later responses to confirm none changed"))
    recorded_body = await observer.action_body(observed["action_id"]) if later else None
    seen: set[tuple[str, str]] = set()
    # Every later observation counts: a later one that looks unchanged never hides one that did not.
    for newer in later:
        for change in compare_response(item, newer, recorded_body=recorded_body, newer_body=newer.get("_body"),
                                       body_significant=body_significant):
            marker = (change["field"], change["significance"])
            if marker not in seen:
                seen.add(marker)
                changes.append(change)
    return changes, len(later)


async def evaluate(observer: Observer, recorded: Mapping[str, Any], *,
                   finding_id: Any = None) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """(state, changes, incomparable) for one entry's recorded dependencies, read from ``observer``.

    ``finding_id`` is the dismissal's current finding (it follows a finding merge)."""
    if not isinstance(recorded, Mapping) or recorded.get("schema") != SCHEMA:
        return "unknown", [], []
    body_significant = recorded.get("for") in NEGATIVE_FOR
    changes: list[dict[str, Any]] = []
    for item in recorded.get("items") or ():
        kind = item.get("type")
        if kind == "endpoint":
            changes += compare_endpoint(item, await observer.endpoint(item.get("method"), item["path"]))
        elif kind == "response":
            observed = item["observed"]
            found, _count = await _response_changes(observer, item, after=observed.get("completed_at"),
                                                    exclude=observed.get("action_id"),
                                                    body_significant=body_significant)
            changes += found
        elif kind == "deployment":
            changes += compare_deployment(item, await observer.deployment(after=item["observed"].get("completed_at")))
        elif kind == "auth_surface":
            changes += compare_auth_surface(item, await observer.auth_surface())
        elif kind == "service":
            changes += compare_service(item, await observer.service(item["transport"], int(item["port"])))
        elif kind == "finding":
            changes += compare_finding(item, await observer.finding(finding_id or item["key"]))
        elif kind == "subject":
            subject_type, _, subject_id = str(item["key"]).partition(":")
            changes += compare_subject(item, await observer.subject(subject_type, subject_id))
    incomparable = [change for change in changes if change["significance"] == INCOMPARABLE]
    return decide(recorded, changes, incomparable), changes, incomparable


async def reobserved(observer: Observer, recorded: Mapping[str, Any], anchor: Any) -> dict[str, Any]:
    """Whether a negative result's bound request was made again after ``anchor`` (the start of the
    Hunt asking) and answered exactly as recorded. Evidence, not age.

    Only the same plain request identity (method, path, origin, session) repeated by a Hunt counts,
    and every such response must equal the recorded one, body digest included. Scans and the
    endpoint inventory never re-observe the behaviour under test: they feed applicability (and
    needs_revalidation), never a skip.
    """
    moment = _time(anchor)
    if moment is None or not isinstance(recorded, Mapping):
        return {"observed": False, "reason": "no Hunt context to re-observe from"}
    binding = recorded.get("binding") if isinstance(recorded.get("binding"), Mapping) else {}
    for item in recorded.get("items") or ():
        if item.get("type") != "response" or item.get("origin") != binding.get("origin") \
                or item.get("path") != binding.get("path") or item.get("method") != binding.get("method") \
                or (item.get("session_ref") or None) != binding.get("session_ref"):
            continue
        found, count = await _response_changes(observer, item, after=moment, exclude=item["observed"].get("action_id"),
                                               body_significant=True)
        if found:
            return {"observed": False, "reason": "the same request answered differently after this Hunt started"}
        if count:
            return {"observed": True, "by": "the same request after this Hunt started", "responses": count}
    return {"observed": False, "reason": "the bound request was not repeated since this Hunt started: repeat the "
                                         "same plain request (method, path, origin, session) before it can be reused"}


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
    "asset_scope", "auth_route", "bind_experiment", "canonical_origin", "capture", "reobserved", "compare_auth_surface", "compare_deployment", "compare_endpoint",
    "compare_finding", "compare_response", "compare_service", "compare_subject", "decide", "deployment_view",
    "digest_format", "evaluate", "media_type", "normalize_route", "operation_route", "public_dependencies",
    "service_key",
]
