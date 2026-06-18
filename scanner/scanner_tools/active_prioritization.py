"""Prioritize active-test endpoints under tight scan budgets."""

from __future__ import annotations

import urllib.parse
from typing import Any


DEFAULT_SOURCE_PRIORITY: dict[str, int] = {
    "har_discovery": 1,
    "manual": 2,
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


def active_endpoint_score(endpoint: dict[str, Any]) -> int:
    """Return a higher-is-better score for active DAST endpoint selection."""
    source = str(endpoint.get("source") or "")
    method = str(endpoint.get("method") or "GET").upper()
    path = urllib.parse.urlparse(str(endpoint.get("url") or "")).path or "/"

    score = SOURCE_BONUS.get(source, 0)
    score += _param_score(endpoint)
    score += _path_score(path)

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
) -> tuple[int, int, str, str]:
    """Stable sort key where lower values should be tested first."""
    source_priority = source_priority or DEFAULT_SOURCE_PRIORITY
    source = str(endpoint.get("source") or "")
    source_rank = source_priority.get(source, DEFAULT_SOURCE_PRIORITY_VALUE)
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint.get("url") or "")
    return (-active_endpoint_score(endpoint), source_rank, method, url)


def _is_body_endpoint(endpoint: dict[str, Any]) -> bool:
    """True for request-body injection surfaces (POST/PUT/PATCH with params)."""
    method = str(endpoint.get("method") or "GET").upper()
    return method in ("POST", "PUT", "PATCH") and bool(
        endpoint.get("body_params") or endpoint.get("params")
    )


# Fraction of a tight active budget guaranteed to request-body endpoints so they
# are never fully crowded out by higher-source-scored GET routes.
BODY_ENDPOINT_BUDGET_FRACTION = 0.4


def prioritize_active_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    budget: int | None = None,
    source_priority: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Sort endpoints for active DAST and optionally apply an endpoint budget.

    The budget cap reserves a share for request-body endpoints (POST/PUT/PATCH).
    Pure top-by-score selection can be 100% GET when observed GET routes outrank
    generated POST routes, which leaves request-body injection (e.g. a JSON login
    SQLi) entirely untested under a tight budget — the cause of shallow API scans.
    """
    key = lambda endpoint: active_endpoint_priority_key(endpoint, source_priority=source_priority)
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
