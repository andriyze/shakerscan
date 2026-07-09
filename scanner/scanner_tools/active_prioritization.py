"""Prioritize active-test endpoints under tight scan budgets."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any


# A path *segment* that looks like a concrete or templated object identifier.
# These are the IDOR / BOLA / SQLi-on-path-param goldmines (e.g. crAPI's
# /identity/api/v2/vehicle/{vehicleId}/location or /api/orders/42): the
# vulnerable code path only runs when a real resource id reaches it, yet such
# routes often carry no high-value path *keyword* and would otherwise score low.
_OBJECT_ID_SEGMENT_RE = re.compile(
    r"^(?:"
    r"\d+"                                   # numeric id: 42
    r"|[0-9a-fA-F]{24}"                      # mongo ObjectId
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # uuid
    r"|\{[^/}]+\}"                           # templated: {id}, {vehicleId}
    r"|:[A-Za-z_][\w-]*"                     # express-style: :id
    r")$"
)

STATE_CHANGING_METHODS = frozenset({"PUT", "PATCH", "DELETE"})


def _path_has_object_id_segment(path: str) -> bool:
    """True if any path segment is a concrete or templated object identifier."""
    for segment in str(path or "").split("/"):
        if segment and _OBJECT_ID_SEGMENT_RE.match(segment):
            return True
    return False


DEFAULT_SOURCE_PRIORITY: dict[str, int] = {
    "har_discovery": 1,
    "manual": 2,
    "discovered_lookup": 2,
    "hash_route": 2,
    "openapi": 3,
    "form": 4,
    "common": 5,
    "options": 6,
    "inferred": 7,
}

DEFAULT_SOURCE_PRIORITY_VALUE = 6

SOURCE_BONUS: dict[str, int] = {
    "har_discovery": 14,
    "manual": 14,
    "discovered_lookup": 12,
    "hash_route": 18,
    "openapi": 12,
    "form": 8,
    "common": 2,
    "options": -8,
    "inferred": -6,
}

HIGH_SIGNAL_PARAM_TOKENS = (
    "id", "user", "uid", "account", "token", "file", "path", "url",
    "redirect", "next", "q", "query", "search", "filter", "name",
    "email", "password", "code", "otp", "amount", "quantity",
)

HIGH_VALUE_PATH_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("sqli", 18),
    ("sql", 14),
    ("xss", 14),
    ("search", 18),
    ("query", 12),
    ("redirect", 10),
    ("upload", 10),
    ("xml", 10),
    ("xxe", 10),
    ("template", 10),
    ("render", 8),
    ("ping", 8),
    ("exec", 8),
    ("command", 8),
    ("deserialize", 8),
    ("deserial", 8),
    ("login", 8),
    ("auth", 7),
    ("users", 7),
    ("user", 6),
    ("account", 6),
    ("admin", 6),
    ("profile", 5),
    ("settings", 5),
    ("order", 5),
    ("coupon", 5),
    ("review", 5),
    ("product", 5),
    ("payment", 5),
    ("checkout", 5),
    ("wallet", 5),
    ("transfer", 5),
)

LOW_VALUE_PATH_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("/.well-known/", 28),
    ("security.txt", 26),
    ("csaf", 22),
    ("socket.io", 22),
    ("/assets/", 20),
    ("/static/", 18),
    ("/images/", 16),
    ("/i18n/", 16),
    ("ai-redteam", 30),
    ("ai-gate", 24),
    ("model-intake", 24),
    ("secure-demo", 22),
    ("benchmark", 22),
    ("scenario", 20),
    ("scenarios", 20),
    ("schema", 16),
    ("manifest", 16),
    ("openapi", 16),
    ("swagger", 16),
    ("redoc", 16),
    ("docs", 14),
    ("features", 12),
    ("governance", 12),
    ("threat-model", 12),
    ("course", 10),
    ("health", 8),
    ("status", 8),
    ("metrics", 8),
)


def _coerce_param_names(raw: Any) -> list[str]:
    if isinstance(raw, dict):
        return [str(key) for key in raw.keys() if key]
    if isinstance(raw, (list, tuple, set)):
        return [str(value) for value in raw if value]
    if isinstance(raw, str):
        return [raw] if raw else []
    return []


def _param_score(endpoint: dict[str, Any]) -> int:
    names = [
        str(p).lower()
        for p in (
            _coerce_param_names(endpoint.get("params"))
            + _coerce_param_names(endpoint.get("body_params"))
        )
    ]
    score = 0
    for name in names:
        if any(token == name or token in name for token in HIGH_SIGNAL_PARAM_TOKENS):
            score += 6
    return min(score, 30)


def _path_score(path: str) -> int:
    path_l = path.lower()
    score = sum(weight for token, weight in HIGH_VALUE_PATH_WEIGHTS if token in path_l)
    penalty = sum(weight for token, weight in LOW_VALUE_PATH_WEIGHTS if token in path_l)
    return score - penalty


# Per-family route relevance. When a focused lane knows it is hunting SQLi vs XSS
# vs BOLA, the same endpoint graph should be ordered differently: SQLi wants
# login/search/filter/order/track + injectable params; XSS wants reflected/stored
# sinks (search/comment/review/profile) + SPA/form routes.
_SQLI_ROUTE_TOKENS = (
    "login", "signin", "authenticate", "search", "filter", "sort", "order",
    "track", "lookup", "report", "query", "coupon", "promo", "voucher",
    "review", "product", "validate", "checkout",
)
_XSS_ROUTE_TOKENS = (
    "search", "comment", "review", "feedback", "message", "profile", "post",
    "note", "reply", "chat", "greeting", "subject", "title", "description",
)
_XSS_REFLECTED_PARAM_TOKENS = (
    "q", "query", "search", "keyword", "term", "name", "title", "comment",
    "message", "text", "body", "content", "subject", "description", "greeting",
)


def _family_route_boost(family: str, path_l: str, endpoint: dict[str, Any]) -> int:
    """Family-specific score boost so a focused lane tests its likely routes first."""
    if family == "sqli":
        boost = 12 if any(tok in path_l for tok in _SQLI_ROUTE_TOKENS) else 0
        if endpoint.get("params") or endpoint.get("body_params"):
            boost += 6  # query/body params are the injection surface
        return boost
    if family == "xss":
        boost = 12 if any(tok in path_l for tok in _XSS_ROUTE_TOKENS) else 0
        names = [
            str(n).lower()
            for n in (_coerce_param_names(endpoint.get("params")) + _coerce_param_names(endpoint.get("body_params")))
        ]
        if any(any(tok in n for tok in _XSS_REFLECTED_PARAM_TOKENS) for n in names):
            boost += 8  # reflected-looking params
        if str(endpoint.get("source") or "") in ("hash_route", "form"):
            boost += 6  # SPA DOM-XSS routes + form-backed stored/reflected sinks
        return boost
    return 0


def active_endpoint_score(endpoint: dict[str, Any], *, family: str | None = None) -> int:
    """Return a higher-is-better score for active DAST endpoint selection.

    ``family`` (e.g. ``"sqli"``/``"xss"``) adds a focused-lane relevance boost so a
    single shared endpoint graph is ordered per the family currently hunting it.
    """
    source = str(endpoint.get("source") or "")
    method = str(endpoint.get("method") or "GET").upper()
    path = urllib.parse.urlparse(str(endpoint.get("url") or "")).path or "/"

    score = SOURCE_BONUS.get(source, 0)
    score += _param_score(endpoint)
    score += _path_score(path)
    if family and family != "all":
        score += _family_route_boost(family, path.lower(), endpoint)

    # Object-id-bearing consumer routes (/orders/42, /vehicle/{id}/location) are
    # prime IDOR/BOLA/SQLi-on-path targets even without a high-value keyword.
    if _path_has_object_id_segment(path):
        score += 12
        # A state-changing method on an object route is a BOLA-write / object
        # mutation candidate — the highest-impact access-control bug class.
        if method in STATE_CHANGING_METHODS:
            score += 6

    if method in {"POST", "PUT", "PATCH"}:
        score += 6
    elif endpoint.get("params"):
        score += 2

    # OPTIONS expansion is useful, but generated unsafe methods without a
    # schema/body example should not crowd out real observed or OpenAPI routes.
    if source == "options" and method in {"PUT", "PATCH"}:
        score -= 6

    return score


def active_endpoint_priority_key(
    endpoint: dict[str, Any],
    source_priority: dict[str, int] | None = None,
    *,
    family: str | None = None,
) -> tuple[int, int, str, str]:
    """Stable sort key where lower values should be tested first."""
    source_priority = source_priority or DEFAULT_SOURCE_PRIORITY
    source = str(endpoint.get("source") or "")
    source_rank = source_priority.get(source, DEFAULT_SOURCE_PRIORITY_VALUE)
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint.get("url") or "")
    return (-active_endpoint_score(endpoint, family=family), source_rank, method, url)


def _is_body_endpoint(endpoint: dict[str, Any]) -> bool:
    """True for request-body injection surfaces (POST/PUT/PATCH with params)."""
    method = str(endpoint.get("method") or "GET").upper()
    return method in ("POST", "PUT", "PATCH") and bool(
        endpoint.get("body_params") or endpoint.get("params")
    )


# Fraction of a tight active budget guaranteed to request-body endpoints so they
# are never fully crowded out by higher-source-scored GET routes.
BODY_ENDPOINT_BUDGET_FRACTION = 0.4

# Synthetic "common API" candidates are only a fallback. Keep them small enough
# that observed HAR/browser/OpenAPI endpoints dominate the active budget and the
# later soft-404 reachability gate never has to retire thousands of guessed URLs.
DEFAULT_SYNTHETIC_ACTIVE_BURST_CAP = 24
DEFAULT_SYNTHETIC_ACTIVE_BUDGET_FRACTION = 0.5


def synthetic_active_candidate_cap(max_active: int, *, explicit: bool = False) -> int:
    """Bound common-endpoint synthetic fan-out before reachability filtering.

    ``explicit`` is for operator-requested thorough parameter probing. It allows a
    larger, but still finite, fallback set. The cap is in candidate URLs after
    parameter expansion, not source endpoint templates.
    """
    try:
        budget = max(0, int(max_active or 0))
    except (TypeError, ValueError):
        budget = 0
    if budget <= 0:
        return 0
    multiplier = 1.0 if explicit else DEFAULT_SYNTHETIC_ACTIVE_BUDGET_FRACTION
    hard_cap = DEFAULT_SYNTHETIC_ACTIVE_BURST_CAP * (2 if explicit else 1)
    return max(1, min(hard_cap, int(max(1, budget * multiplier))))


def should_generate_synthetic_active_candidates(
    *,
    api_hint: bool,
    observed_candidate_count: int,
    max_active: int,
    explicit: bool = False,
) -> bool:
    """Gate guessed endpoint generation behind signal that the target has APIs.

    Without any observed API/manual/browser/HAR signal, common endpoint lists turn
    a static site into a large phantom worklist. If real observed candidates have
    already filled the active budget, synthetic fallback is unnecessary.
    """
    try:
        budget = max(0, int(max_active or 0))
    except (TypeError, ValueError):
        budget = 0
    try:
        observed = max(0, int(observed_candidate_count or 0))
    except (TypeError, ValueError):
        observed = 0
    if budget <= 0 or observed >= budget:
        return False
    return bool(api_hint or explicit)


def prioritize_active_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    budget: int | None = None,
    source_priority: dict[str, int] | None = None,
    family: str | None = None,
) -> list[dict[str, Any]]:
    """Sort endpoints for active DAST and optionally apply an endpoint budget.

    The budget cap reserves a share for request-body endpoints (POST/PUT/PATCH).
    Pure top-by-score selection can be 100% GET when observed GET routes outrank
    generated POST routes, which leaves request-body injection (e.g. a JSON login
    SQLi) entirely untested under a tight budget — the cause of shallow API scans.
    ``family`` orders the same graph for the focused lane currently hunting it.
    """
    key = lambda endpoint: active_endpoint_priority_key(endpoint, source_priority=source_priority, family=family)
    ordered = sorted(endpoints, key=key)
    if not (budget and budget > 0):
        return ordered

    selected = ordered[:budget]
    body_all = [e for e in ordered if _is_body_endpoint(e)]
    non_body_all = [e for e in ordered if not _is_body_endpoint(e)]
    if body_all:
        # Keep at least one globally top-ranked non-body route when such routes exist.
        # A one-slot budget should not evict a higher-scored hash/search route just
        # because any POST body route is present.
        max_body_slots = int(budget) if not non_body_all else max(0, int(budget) - 1)
        reserve = min(
            len(body_all),
            max(1, int(budget * BODY_ENDPOINT_BUDGET_FRACTION)),
            max_body_slots,
        )
        if sum(1 for e in selected if _is_body_endpoint(e)) < reserve:
            # Guarantee the top-scoring body endpoints a place, then fill the rest
            # with the top-scoring non-body endpoints, keeping overall score order.
            reserved_body = body_all[:reserve]
            non_body = non_body_all[: budget - reserve]
            selected = sorted(reserved_body + non_body, key=key)[:budget]
    return selected
