"""A lockout-safety ceiling on the credential profile's own sign-in endpoint (E1-N6).

This is a lockout-safety ceiling on one endpoint, not a budget cut: budgets stay generous. Every
other endpoint, and every fast, balanced, thorough or deep plan, keeps its full verification
budget; no plan changes. It applies only to the sign-in endpoint (and the form's action) of a
credential profile the Scan carries, the one URL where an active injection verifier's requests
are failed sign-ins against the account the Scan itself signs in with.
One balanced lab Scan sent about 1,460 injection POSTs to honey's Hub login (938 sqlmap, 523
Dalfox) and took 51 minutes instead of 8; an application with account lockout or a per-address
sign-in throttle would have locked the account the Scan was signing in with.

On that endpoint each active injection verifier gets a bounded probe set per parameter instead
of the whole technique ladder, at a lockout-safe pace, and the coverage says so
(``auth_endpoint_probe_limited``):

* pace: at most ``AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE`` (20) requests a minute to the endpoint,
  one every 3 seconds. The reviewed verifier paces are 60 a minute for sqlmap (``--delay 1``,
  one thread) and about 180 for Dalfox (1 s delay, 3 workers); a third of the slower one keeps a
  candidate's traffic below the sign-in throttles applications commonly apply per address;
* probes: sqlmap runs its level-1, risk-1 payloads (``probe_profile=auth_endpoint``) within 60
  requests per parameter, enough for its boolean- and error-based checks of one field, which
  confirm an obvious login injection in well under a hundred requests; Dalfox runs the reviewed
  verification set (four vectors in four encodings) within 32 requests per parameter. Honey's
  two-field login then receives at most 184 injection requests (120 + 64) instead of 1,461.

The numbers bound each parameter's requests across the Scan, its continuation rounds included:
a candidate whose probe set is spent is inconclusive (``auth_endpoint_probe_limited``), never
extended and never called negative.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping
import urllib.parse

AUTH_ENDPOINT_PROBE_LIMITED = "auth_endpoint_probe_limited"
AUTH_ENDPOINT_PROBE_PROFILE = "auth_endpoint"
AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE = 20
AUTH_ENDPOINT_SECONDS_PER_REQUEST = 60 // AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE
#: Requests one parameter of the sign-in endpoint may receive from each verifier, per Scan.
AUTH_ENDPOINT_PROBE_REQUESTS: Mapping[str, int] = {
    "sqli.verify_batch": 60,
    "xss.verify_batch": 32,
}
#: Below this an attempt cannot run even the bounded probe set's baseline and first payloads.
AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS = 8
#: The sign-in actions whose observations name the endpoint and the form's action.
AUTH_ACTION_IDS = ("inputs.auth_primary", "inputs.auth_secondary")
#: Hydrated worker-private options that name a sign-in endpoint.
_ENDPOINT_OPTIONS = ("login_url", "user2_login_url", "oauth_token_url")


def _key(url: str) -> tuple[str, str, int, str] | None:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = str(parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    path = parsed.path.rstrip("/") or "/"
    return scheme, host, port or (443 if scheme == "https" else 80), path


def auth_endpoint_keys(
    options: Mapping[str, Any], observations: Iterable[Mapping[str, Any]], *, base_url: str,
) -> frozenset[tuple[str, str, int, str]]:
    """The sign-in endpoints of the credential profiles this Scan carries, on ``base_url``."""
    keys: set[tuple[str, str, int, str]] = set()
    base = str(base_url or "").rstrip("/") + "/"
    for name in _ENDPOINT_OPTIONS:
        value = str(options.get(name) or "").strip()
        key = _key(urllib.parse.urljoin(base, value)) if value else None
        if key is not None:
            keys.add(key)
    for item in observations:
        if not isinstance(item, Mapping) or item.get("kind") != "credential_session":
            continue
        for field in ("endpoint_path", "form_action_path"):
            path = str(item.get(field) or "")
            if path.startswith("/") and "<redacted" not in path:
                key = _key(urllib.parse.urljoin(base, path.split("?", 1)[0]))
                if key is not None:
                    keys.add(key)
    return frozenset(keys)


def auth_endpoint_of(url: str, keys: frozenset[tuple[str, str, int, str]]) -> str | None:
    """The sign-in endpoint path ``url`` targets, or None for any other endpoint."""
    key = _key(url)
    return key[3] if key is not None and key in keys else None


#: A body candidate tests every field of its form; at most this many count toward its probe set.
AUTH_ENDPOINT_MAX_PARAMETERS = 4


def probe_parameters(body_field_names: Iterable[Any] | None) -> int:
    """How many parameters one candidate's probe set covers: its body fields, else its one."""
    return max(1, min(AUTH_ENDPOINT_MAX_PARAMETERS, len(list(body_field_names or ()))))


def auth_endpoint_hold(
    sub_budget: Mapping[str, int], *, capability_name: str, used: int, concurrency: int = 1,
    parameters: int = 1,
) -> dict[str, int] | None:
    """The attempt's hold on the sign-in endpoint, or None when its probe set is spent.

    Requests are at most what the parameter has left of its probe set, and at most one per
    ``AUTH_ENDPOINT_SECONDS_PER_REQUEST`` of the attempt's wall for every candidate that may run
    at once, so the batch's own pacing (wall / requests) never exceeds the lockout-safe rate.
    """
    allowance = probe_set_requests(capability_name, parameters) - max(0, int(used))
    wall = int(sub_budget.get("tool_wall_seconds") or 0)
    paced = wall // (AUTH_ENDPOINT_SECONDS_PER_REQUEST * max(1, int(concurrency)))
    requests = min(allowance, int(sub_budget.get("http_requests") or 0), paced)
    if requests < AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS:
        return None
    hold = dict(sub_budget)
    hold["http_requests"] = requests
    if "state_changing_requests" in hold:
        hold["state_changing_requests"] = min(int(hold["state_changing_requests"]), requests)
        if hold["state_changing_requests"] < requests:
            hold["http_requests"] = hold["state_changing_requests"]
    return hold


def probe_set_requests(capability_name: str, parameters: int = 1) -> int:
    """The requests a candidate's probe set holds: the per-parameter set times its parameters."""
    return int(AUTH_ENDPOINT_PROBE_REQUESTS.get(capability_name, 0)) * max(1, int(parameters))


def probe_set_spent(capability_name: str, used: int, parameters: int = 1) -> bool:
    """Whether a candidate that has received ``used`` requests can run no further attempt."""
    return (
        probe_set_requests(capability_name, parameters) - int(used)
        < AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS
    )


__all__ = [
    "AUTH_ACTION_IDS", "AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE", "AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS",
    "AUTH_ENDPOINT_PROBE_LIMITED", "AUTH_ENDPOINT_PROBE_PROFILE", "AUTH_ENDPOINT_PROBE_REQUESTS",
    "AUTH_ENDPOINT_MAX_PARAMETERS", "AUTH_ENDPOINT_SECONDS_PER_REQUEST", "auth_endpoint_hold",
    "auth_endpoint_keys", "auth_endpoint_of", "probe_parameters", "probe_set_requests",
    "probe_set_spent",
]
