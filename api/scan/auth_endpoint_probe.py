"""A lockout-safety ceiling on the credential profile's own sign-in endpoint (E1-N6).

This is a lockout-safety ceiling on one endpoint, not a budget cut: budgets stay generous. Every
other endpoint, and every fast, balanced, thorough or deep plan, keeps its full verification
budget; no plan changes. It applies only to the sign-in endpoint of a credential profile the
Scan carries (its login, second-user login or OAuth token request, and the form's action), the
one request where an active injection verifier's probes are failed sign-in attempts from the
scanner's address. One authenticated balanced Scan of a test application sent about 1,460
injection requests to the sign-in form it used (938 sqlmap, 523 Dalfox) and took 51 minutes
instead of 8; an application with a per-address sign-in throttle or lockout would have refused
the scanner for the rest of the Scan.

Which requests are the sign-in endpoint (``sign_in_endpoints``, ``sign_in_endpoint_for``): a
request that carries a body (POST, PUT, PATCH) to the endpoint's origin and path, compared after
normalization (percent-decoding, dot segments, repeated slashes and ``;`` parameters removed,
case folded), and, when the sign-in URL routes by its query (``index.php?route=account/login``),
carrying those routing pairs. A query pair that only says where to go next (``next``,
``ReturnUrl``) or carries a token does not route. A GET to the sign-in page (``/login?next=``)
attempts no sign-in and is not limited; a page whose form posts elsewhere is not the endpoint,
its action is.

On that endpoint the verifiers keep their full payloads: sqlmap its level-2, risk-2 ladder and
Dalfox its own discovery and payloads for the request's body (its custom-payload mode tests the
URL's query, not a body). What changes:

* pace: at most ``AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE`` (20) requests a minute to the endpoint,
  one every 3 seconds, a third of sqlmap's reviewed single-call pace (60 a minute). A slice runs
  one attempt on the endpoint at a time; each attempt holds at most one request per 3 s of its
  wall and is paced no faster (sqlmap one thread, Dalfox one worker, a 3 s delay floor). A Scan
  split across parallel children paces the endpoint by the number of children, so siblings that
  reach it at the same time stay inside the rate together. A slice whose hold cannot pace even
  ``AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS`` leaves the candidate for a later round, exactly like any
  other candidate its holds cannot fund;
* one probe set per endpoint and verifier across the Scan: every candidate on the endpoint (a
  declared request, the crawled form with its hidden fields, a JSON variant), every slice and
  every continuation round draws from it (a parallel child holds its own). Per tested field, at
  most four, sized from measured runs with ``AUTH_ENDPOINT_PROBE_HEADROOM`` (2x) headroom:
  sqlmap 946 requests, twice its level-2 ladder's measured cost to a negative verdict (union 53,
  boolean 87, error 144, time 189: 473, ``sqli_stages.SQLI_TECHNIQUE_NEGATIVE_COST``). A plain
  two-field fixture in the scanner image cost exactly that ladder (946 for both fields), and a
  real sign-in costs more per unit (a JSON sign-in's union unit sent 316 requests on one field
  against the 53 measured), so a set of one ladder would leave the last technique of the last
  field (time-based blind, the one that finds a blind sign-in injection) unfunded after a slight
  overspend anywhere before it. Dalfox gets 64 per field: it reported a verified reflection
  within 18 requests (12 in a later run) on a reflecting two-field sign-in form. The largest set,
  a four-field candidate's, is the most the endpoint receives per Scan part: 3,784 sqlmap and
  256 Dalfox requests (4,040, at the pace above about 3 h 20 min); each parallel child holds its
  own, so a Scan split into N parts may send N times that, at the same combined pace;
* verdicts: Dalfox stops at its first verified finding, and a Dalfox attempt that verified nothing
  is inconclusive, never negative, since it sent a bounded part of its payloads: it sends its whole
  payload set to a body whether or not a field reflects (1,347 requests for a two-field form in
  the scanner image, ten times its probe set), so a sign-in form without a verified XSS leaves the
  XSS family partial. sqlmap concludes as anywhere else inside the probe set, and a candidate
  whose probe set is spent before its verdict is inconclusive. Both are named
  ``auth_endpoint_probe_limited``, and coverage leaves the family partial for that reason.

The probes carry placeholder values, not the profile's account, so they cannot lock out the
account the Scan signs in with; the pace and the probe set bound what a per-address sign-in
throttle sees from the scanner.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import posixpath
from typing import Any, Iterable, Mapping
import urllib.parse

try:
    from scanner_tools.url_redaction import is_sensitive_label, redact_path, token_like_segment
except ModuleNotFoundError:  # package import layout
    from scanner.scanner_tools.url_redaction import (
        is_sensitive_label, redact_path, token_like_segment,
    )

from .sqli_stages import SQLI_TECHNIQUE_NEGATIVE_COST

AUTH_ENDPOINT_PROBE_LIMITED = "auth_endpoint_probe_limited"
#: A candidate on the sign-in endpoint whose hold cannot pace a probe: left for a later round,
#: like any candidate its slice cannot fund, with no verdict.
AUTH_ENDPOINT_PACE_UNFUNDED = "auth_endpoint_pace_unfunded"
AUTH_ENDPOINT_PROBE_PROFILE = "auth_endpoint"
AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE = 20
AUTH_ENDPOINT_SECONDS_PER_REQUEST = 60 // AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE
#: The probe sets hold at least this many times what a verdict was measured to cost.
AUTH_ENDPOINT_PROBE_HEADROOM = 2
#: Requests one tested field of the sign-in endpoint may receive from each verifier, per Scan.
AUTH_ENDPOINT_PROBE_REQUESTS: Mapping[str, int] = {
    "sqli.verify_batch": AUTH_ENDPOINT_PROBE_HEADROOM * sum(SQLI_TECHNIQUE_NEGATIVE_COST.values()),
    "xss.verify_batch": 64,
}
#: Below this an attempt cannot run even a technique's baseline and first payloads.
AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS = 8
#: The sign-in actions whose observations name the endpoint and the form's action.
AUTH_ACTION_IDS = ("inputs.auth_primary", "inputs.auth_secondary")
#: Hydrated worker-private options that name a sign-in endpoint.
_ENDPOINT_OPTIONS = ("login_url", "user2_login_url", "oauth_token_url")
#: A sign-in request carries its credentials in a body.
SIGN_IN_METHODS = frozenset({"POST", "PUT", "PATCH"})
#: A body candidate tests every field of its form; at most this many count toward its probe set.
AUTH_ENDPOINT_MAX_PARAMETERS = 4
#: Query keys that say where to go after the sign-in, or carry client state, never which route.
_NON_ROUTING_KEYS = frozenset({
    "back", "continue", "dest", "destination", "forward", "from", "goto", "hl", "lang",
    "language", "locale", "next", "redir", "redirect", "redirect_to", "redirect_uri",
    "redirect_url", "redirectto", "redirecturl", "ref", "referer", "referrer", "return",
    "return_to", "return_url", "returnto", "returnurl", "service", "success_url", "target",
    "to", "url",
})


def normalize_path(path: str) -> str:
    """One spelling of a request path for comparing it with the sign-in endpoint.

    Each segment loses its ``;`` parameters (``;jsessionid=``) and is percent-decoded; dot
    segments and repeated slashes are removed and the result is case folded. Folding errs toward
    the endpoint on servers that treat ``/Account/Login`` and ``/account/login`` as one.
    """
    segments = [
        urllib.parse.unquote(segment.split(";", 1)[0])
        for segment in str(path or "").split("/")
    ]
    joined = "/" + "/".join(segment for segment in segments if segment)
    normalized = posixpath.normpath(joined) if joined != "/" else "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.replace("//", "/").casefold()


def _pair_digest(key: str, value: str) -> str:
    # Keyed by the installation (HMAC), so a published digest of a query pair the target chose
    # is no offline oracle for its value; it still matches within the installation.
    try:
        from capabilities.secret_material import keyed_short_digest
    except ModuleNotFoundError:  # package import layout
        from ..capabilities.secret_material import keyed_short_digest
    return keyed_short_digest(f"{key}={value}".encode("utf-8", "replace"), 16)


def routing_digests(query: str) -> frozenset[str]:
    """Digests of the query pairs that route a request (``route=account/login``).

    Only installation-keyed digests are recorded, never query values. A key that names a
    credential, a token-like value, and the keys that only say where to go next do not route.
    """
    pairs = urllib.parse.parse_qsl(str(query or ""), keep_blank_values=True)
    return frozenset(
        _pair_digest(key, value) for key, value in pairs
        if key and key.casefold() not in _NON_ROUTING_KEYS and not is_sensitive_label(key)
        and not token_like_segment(value)
    )


@dataclass(frozen=True)
class SignInEndpoint:
    """The sign-in endpoint of a credential profile the Scan carries."""

    scheme: str
    host: str
    port: int
    path: str
    routing: frozenset[str] = frozenset()
    #: The redacted public path, for records.
    label: str = ""

    @property
    def key(self) -> str:
        """A stable id for counting what the endpoint received across the Scan."""
        canonical = json.dumps(
            [self.scheme, self.host, self.port, self.path, sorted(self.routing)],
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _origin(parsed: urllib.parse.SplitResult) -> tuple[str, str, int] | None:
    try:
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = str(parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return None
    return scheme, host, port or (443 if scheme == "https" else 80)


def _endpoint(url: str, *, routing: frozenset[str] | None = None) -> SignInEndpoint | None:
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return None
    origin = _origin(parsed)
    if origin is None:
        return None
    return SignInEndpoint(
        *origin, normalize_path(parsed.path),
        routing_digests(parsed.query) if routing is None else routing,
        redact_path(parsed.path or "/"),
    )


def _recorded(item: Mapping[str, Any], field: str, *, base: str) -> SignInEndpoint | None:
    """The endpoint a sign-in observation recorded in ``field``, or None when it cannot say.

    The record holds the redacted path (``?<redacted-query>`` after it when the request had a
    query) and the query's routing digests beside it. A redacted segment names nothing. The page's
    query of unknown routing names nothing either (the profile's own URL still does); a form
    action's query of unknown routing leaves its path as the endpoint.
    """
    raw = str(item.get(field) or "")
    path, _, query = raw.partition("?")
    if not path.startswith("/") or "<redacted" in path:
        return None
    stem = field.removesuffix("_path")
    digests = item.get(f"{stem}_routing")
    if isinstance(digests, (list, tuple)) and all(isinstance(value, str) for value in digests):
        routing = frozenset(digests)
    elif (query or item.get(f"{stem}_has_query")) and field == "endpoint_path":
        return None
    else:
        routing = frozenset()
    return _endpoint(urllib.parse.urljoin(base, path), routing=routing)


def sign_in_endpoints(
    options: Mapping[str, Any], observations: Iterable[Mapping[str, Any]], *, base_url: str,
) -> tuple[SignInEndpoint, ...]:
    """The sign-in endpoints of the credential profiles this Scan carries, on ``base_url``."""
    base = str(base_url or "").rstrip("/") + "/"
    endpoints: dict[str, SignInEndpoint] = {}
    pages_posting_elsewhere: set[str] = set()
    for item in observations:
        if not isinstance(item, Mapping) or item.get("kind") != "credential_session":
            continue
        page = _recorded(item, "endpoint_path", base=base)
        action = _recorded(item, "form_action_path", base=base)
        if action is not None:
            endpoints.setdefault(action.key, action)
            if page is not None and page.key != action.key:
                # The form posts elsewhere: the page is where it is shown, not where it signs in.
                pages_posting_elsewhere.add(page.key)
        elif page is not None:
            endpoints.setdefault(page.key, page)
    for key in pages_posting_elsewhere:
        endpoints.pop(key, None)
    for name in _ENDPOINT_OPTIONS:
        value = str(options.get(name) or "").strip()
        endpoint = _endpoint(urllib.parse.urljoin(base, value)) if value else None
        if endpoint is not None and endpoint.key not in pages_posting_elsewhere:
            endpoints.setdefault(endpoint.key, endpoint)
    return tuple(endpoints.values())


def sign_in_page_paths(
    options: Mapping[str, Any], observations: Iterable[Mapping[str, Any]], *, base_url: str,
) -> frozenset[str]:
    """Every normalized path of the profiles' sign-in pages and requests, on any origin.

    For leaving them out of a session-carrying crawl's seeds: a GET of a sign-in page may end
    the session the crawl carries.
    """
    base = str(base_url or "").rstrip("/") + "/"
    paths: set[str] = set()
    for name in _ENDPOINT_OPTIONS:
        value = str(options.get(name) or "").strip()
        if value:
            paths.add(normalize_path(urllib.parse.urlsplit(urllib.parse.urljoin(base, value)).path))
    for item in observations:
        if not isinstance(item, Mapping) or item.get("kind") != "credential_session":
            continue
        for field in ("endpoint_path", "form_action_path"):
            path = str(item.get(field) or "").partition("?")[0]
            if path.startswith("/") and "<redacted" not in path:
                paths.add(normalize_path(path))
    return frozenset(paths)


def sign_in_endpoint_for(
    url: str, method: str, endpoints: Iterable[SignInEndpoint],
) -> SignInEndpoint | None:
    """The sign-in endpoint a request attempts, or None for any other request.

    Only a request that carries a body is a sign-in attempt; a GET to the sign-in page is not.
    """
    if str(method or "").upper() not in SIGN_IN_METHODS:
        return None
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return None
    origin = _origin(parsed)
    if origin is None:
        return None
    path = normalize_path(parsed.path)
    digests = frozenset(
        _pair_digest(key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    )
    return next((
        item for item in endpoints
        if (item.scheme, item.host, item.port, item.path) == (*origin, path)
        and item.routing <= digests
    ), None)


def parallel_children(options: Mapping[str, Any]) -> int:
    """How many parallel children of this Scan may reach the endpoint at once (1 when unsplit)."""
    shard = options.get("canonical_shard_authority")
    count = shard.get("shard_count") if isinstance(shard, Mapping) else None
    return int(count) if isinstance(count, int) and not isinstance(count, bool) and count > 1 else 1


def probe_parameters(body_field_names: Iterable[Any] | None) -> int:
    """How many parameters one candidate's probe set covers: its body fields, else its one."""
    return max(1, min(AUTH_ENDPOINT_MAX_PARAMETERS, len(list(body_field_names or ()))))


def probe_set_requests(capability_name: str, parameters: int = 1) -> int:
    """The requests the endpoint's probe set holds for a candidate with ``parameters`` fields."""
    counted = max(1, min(AUTH_ENDPOINT_MAX_PARAMETERS, int(parameters)))
    return int(AUTH_ENDPOINT_PROBE_REQUESTS.get(capability_name, 0)) * counted


def probe_set_left(capability_name: str, received: int, parameters: int = 1) -> int:
    """What the endpoint's probe set has left after the endpoint received ``received``."""
    return max(0, probe_set_requests(capability_name, parameters) - max(0, int(received)))


def probe_set_spent(
    capability_name: str, received: int, parameters: int = 1, *, next_need: int = 0,
) -> bool:
    """Whether the endpoint can fund no further attempt for this candidate.

    ``next_need`` is what the candidate's next unit needs for its verdict (a SQLi technique over
    one field): a probe set with less left than that cannot conclude it either.
    """
    return probe_set_left(capability_name, received, parameters) < max(
        AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS, int(next_need or 0),
    )


def pace_seconds(*, children: int = 1) -> int:
    """The least delay between two of an attempt's requests to the sign-in endpoint."""
    return AUTH_ENDPOINT_SECONDS_PER_REQUEST * max(1, int(children))


def pace_wall_seconds(*, children: int = 1) -> int:
    """The least attempt wall that paces ``AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS``."""
    return AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS * pace_seconds(children=children)


def auth_endpoint_hold(
    sub_budget: Mapping[str, int], *, capability_name: str, received: int, parameters: int = 1,
    children: int = 1,
) -> dict[str, int] | None:
    """The attempt's hold on the sign-in endpoint, or None when its wall cannot pace a probe.

    Requests are at most what the endpoint's probe set has left and at most one per
    ``pace_seconds`` of the attempt's wall, so the attempt's own pacing (wall / requests) never
    exceeds the lockout-safe rate. The caller checks ``probe_set_spent`` first.
    """
    paced = max(0, int(sub_budget.get("tool_wall_seconds") or 0)) // pace_seconds(children=children)
    if paced < AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS:
        return None
    requests = min(
        probe_set_left(capability_name, received, parameters),
        int(sub_budget.get("http_requests") or 0), paced,
    )
    hold = dict(sub_budget)
    hold["http_requests"] = requests
    if "state_changing_requests" in hold:
        hold["state_changing_requests"] = min(int(hold["state_changing_requests"]), requests)
        hold["http_requests"] = hold["state_changing_requests"]
    return hold


__all__ = [
    "AUTH_ACTION_IDS", "AUTH_ENDPOINT_MAX_PARAMETERS", "AUTH_ENDPOINT_MAX_REQUESTS_PER_MINUTE",
    "AUTH_ENDPOINT_MIN_ATTEMPT_REQUESTS", "AUTH_ENDPOINT_PACE_UNFUNDED", "AUTH_ENDPOINT_PROBE_HEADROOM",
    "AUTH_ENDPOINT_PROBE_LIMITED", "AUTH_ENDPOINT_PROBE_PROFILE", "AUTH_ENDPOINT_PROBE_REQUESTS",
    "AUTH_ENDPOINT_SECONDS_PER_REQUEST", "SIGN_IN_METHODS", "SignInEndpoint", "auth_endpoint_hold",
    "normalize_path", "pace_seconds", "pace_wall_seconds", "parallel_children",
    "probe_parameters", "probe_set_left", "probe_set_requests", "probe_set_spent",
    "routing_digests", "sign_in_endpoint_for", "sign_in_endpoints", "sign_in_page_paths",
]
