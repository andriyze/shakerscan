"""Deterministic proof of one vulnerability class on one exact request.

The checks that prove a class from what the target answers, each with a repeat that uses fresh
random values and a control that must stay silent:

* ``open_redirect``: a redirect parameter sends the browser to a random host under a reserved
  ``.invalid`` name, twice with two different hosts; the application's own path in the same
  parameter does not;
* ``crlf_injection``: a CR LF sequence in a parameter starts a response header the application
  never sends (random name and value), twice; the same text with spaces in place of CR LF does not;
* ``host_header_injection``: a random ``.invalid`` host in ``Host`` (or a forwarding header the
  application trusts) is written into the response, twice; the same host in a header no
  application reads is not;
* ``cors``: a random ``.invalid`` origin is granted in Access-Control-Allow-Origin, twice with two
  origins (with Access-Control-Allow-Credentials, the user's data is readable by any site); the
  ``null`` origin, and ``*`` with credentials, are judged the same way;
* ``security_headers``: an HTML page answered twice without a Content-Security-Policy, or framable
  (no X-Frame-Options and no frame-ancestors);
* ``directory_listing``: a server-generated index of the path, twice, and none for a sibling
  directory that does not exist;
* ``graphql``: a validating GraphQL server (``__typename`` answered, an undefined field rejected)
  that answers introspection, suggests field names, or runs 100 aliases, 100 duplicate fields or a
  batch of operations in one request;
* ``file_upload``: an uploaded HTML file is served back from the application's origin as HTML
  with the markup it was uploaded with (a random element that is no part of the file name),
  twice; a file name never uploaded is answered with neither the markup nor that name;
* ``rate_limit``: a sign-in refused for every one of a run of wrong passwords, none of them
  answered with a lockout, a rate-limit status or a Retry-After. An observation, never a
  finding: a dozen attempts for an account name the check cannot tie to a real account show
  neither a per-account lockout nor a threshold above a dozen;
* ``csrf``: a state-changing request sent as a cross-site browser would send it (foreign Origin
  and Referer, no custom headers, every anti-CSRF field left out) is answered exactly like the
  original (status, redirect and page), twice, while the same request without the session is
  answered differently and refused;
* ``ldap_injection``: a sign-in accepted for an LDAP wildcard, twice, and refused for a random
  value and for the escaped wildcard;
* ``jwt``: the principal's bearer token accepted with its signature altered, under ``alg: none``,
  or reproduced with a well-known secret (``jwt_forgery``);
* ``exposure``: an anonymous GET classified by the Scan's exposure classifier
  (``exposure_probe.classify_exposure``) into a class that proves a sensitive exposure (secret
  material, a server autoindex, a metrics endpoint, a debug interface ...), twice, while a sibling
  path that cannot exist is not classified the same;
* ``unauthenticated_api``: a self-hosted product's management route (``product_api``) answered an
  anonymous GET with that product's data, twice, while a sibling route that cannot exist did not.

Command injection, path traversal, template injection, XXE and in-band SSRF are proved by
``injection_verify``; NoSQL operator injection by ``nosqli_verify``. A response body is never
kept: observations hold statuses, keyed digests, header names and the name of what matched.
"""

from __future__ import annotations

from dataclasses import replace
import asyncio
import hashlib
import json
import math
import re
import secrets
import time
from typing import Any, Awaitable, Callable, Mapping, Sequence
import urllib.parse

try:
    from capabilities.secret_material import keyed_body_digest
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import keyed_body_digest

try:
    from capabilities.product_api import product_api_for
except ModuleNotFoundError:
    from .product_api import product_api_for

try:
    from capabilities import graphql_probe, jwt_forgery
    from capabilities.exposure_probe import _LISTING_RE, classify_exposure, directory_listing_links
    from capabilities.sqli_proof import SQLiProofError, _mutate
    from hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from hunt.default_credentials import classify_response
    from runtime.auth_refusal import is_login_location, refusal_error, request_refusal
    from runtime.models import TargetBinding
    from runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
    from scan.posture_findings import header_value_issues
except ModuleNotFoundError:
    from . import graphql_probe, jwt_forgery
    from .exposure_probe import _LISTING_RE, classify_exposure, directory_listing_links
    from .sqli_proof import SQLiProofError, _mutate
    from ..hunt.capability_executor import CapabilityAdapterResult, Cancelled, Heartbeat
    from ..hunt.default_credentials import classify_response
    from ..runtime.auth_refusal import is_login_location, refusal_error, request_refusal
    from ..runtime.models import TargetBinding
    from ..runtime.request_replay_executor import ReplayTransport, ReplayTransportResult
    from ..scan.posture_findings import header_value_issues

try:
    from scanner_tools.request_replay import ReplayRequest
except ModuleNotFoundError:
    from scanner.scanner_tools.request_replay import ReplayRequest


REQUEST_VERIFY_PARSER_VERSION = "request-verify/v1"
# Checks this module proves itself, and what each one needs from the request.
REQUEST_CHECKS = (
    "open_redirect", "crlf_injection", "host_header_injection", "cors", "security_headers",
    "directory_listing", "graphql", "file_upload", "rate_limit", "csrf", "ldap_injection", "jwt",
    "unauthenticated_api", "exposure", "mass_assignment",
)
# Checks that mutate one named input (``parameter``).
FIELD_CHECKS = frozenset({
    "open_redirect", "crlf_injection", "file_upload", "rate_limit", "ldap_injection", "mass_assignment",
})
PROOF_CONTRACTS = {
    "open_redirect": "request_open_redirect_differential/v1",
    "crlf_injection": "request_crlf_header_differential/v1",
    "host_header_injection": "request_host_header_differential/v1",
    "cors_reflected_origin": "request_cors_origin_differential/v1",
    "cors_null_origin": "request_cors_origin_differential/v1",
    "cors_wildcard_credentials": "request_cors_wildcard_repeated/v1",
    "missing_content_security_policy": "request_security_header_repeated/v1",
    "clickjacking": "request_security_header_repeated/v1",
    "weak_security_header": "request_security_header_repeated/v1",
    "directory_listing": "request_directory_listing_differential/v1",
    "graphql_introspection": "graphql_introspection/v1",
    "field_suggestions": "graphql_field_suggestions/v1",
    "alias_limit_absent": "graphql_alias_limit_absent/v1",
    "duplicate_field_limit_absent": "graphql_duplicate_field_limit_absent/v1",
    "batch_limit_absent": "graphql_batch_limit_absent/v1",
    "file_upload": "request_upload_served_differential/v1",
    "csrf": "request_cross_site_differential/v1",
    "ldap_injection": "request_ldap_wildcard_differential/v1",
    "jwt": jwt_forgery.JWT_FORGERY_CONTRACT,
    "unauthenticated_api": "request_anonymous_product_api_repeated/v1",
    "mass_assignment": "request_registration_privilege_readback/v1",
}
# ``exposure`` carries the Scan exposure class's own proof contract (exposure_signature_contract).
# ``rate_limit`` has none: its run of unthrottled refusals is an observation (see ``_rate_limit``).
MINIMUM_REQUESTS = 4
# Reserved (RFC 6761) names: a host under one never resolves, so it can only have come from the
# request, and following it reaches nobody.
_REDIRECT_PROBE_DOMAIN = "shakerscan-redirect-probe.invalid"
_HOST_PROBE_DOMAIN = "shakerscan-host-probe.invalid"
_CORS_PROBE_DOMAIN = "shakerscan-cors-probe.invalid"
_CSRF_PROBE_DOMAIN = "shakerscan-csrf-probe.invalid"
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Headers some frameworks read the public host from. ``X-Forwarded-Host`` and ``Forwarded`` also
# say where a client is, so they are sent only when the Hunt allows identity headers.
_HOST_OVERRIDE_HEADERS = ("X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "X-Original-Host")
_HOST_IDENTITY_HEADERS = ("X-Forwarded-Host", "Forwarded")
_HOST_CONTROL_HEADER = "X-Shakerscan-Control"
# A run of wrong passwords this long, none of them throttled, is what the rate-limit check states.
RATE_LIMIT_ATTEMPTS = 12
RATE_LIMIT_PACE_SECONDS = 0.2
_LDAP_WILDCARDS = ("*", "*)(|(objectClass=*")
_SIMPLE_CONTENT_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
# Request headers a browser adds on its own or that a cross-site form can carry.
_CROSS_SITE_KEPT_HEADERS = frozenset({"cookie", "content-type", "accept", "accept-language", "user-agent"})
_HTML_TYPES = ("text/html", "application/xhtml+xml")
# Anti-CSRF field names, compared with everything but letters and digits removed
# (``__RequestVerificationToken``, ``_csrf``, ``X-XSRF-TOKEN``, ``authenticity_token``,
# ``csrfmiddlewaretoken``): a name that contains one of the parts, is one of the whole names
# (Laravel ``_token``, Drupal ``form_token``, Magento ``form_key``, Moodle ``sesskey``), or ends in
# ``nonce`` (WordPress ``_wpnonce``). A forged request cannot carry any of them, so the check
# leaves them out itself instead of trusting the planner to name the one that matters.
_ANTI_CSRF_PARTS = ("csrf", "xsrf", "antiforgery", "requestverificationtoken", "authenticitytoken")
_ANTI_CSRF_NAMES = frozenset({"token", "formtoken", "formkey", "sesskey", "securitytoken"})
_NOT_ALNUM_RE = re.compile(r"[^a-z0-9]")
_PART_NAME_RE = re.compile(rb'name="([^"\r\n]{1,100})"')
_SAME_SITE_RE = re.compile(r"(?i);\s*samesite\s*=\s*(lax|strict|none)")
# A word of the page: letters only, as prose and JSON keys are. Counters, dates, ids and fresh
# tokens (anything with a digit or mixed case inside) change between two answers and are left out.
_RUN_RE = re.compile(rb"[A-Za-z0-9_+/=-]+")
_PROSE_WORD_RE = re.compile(rb"[A-Za-z][a-z]{1,19}")
_META_CSP_RE = re.compile(rb"(?i)<meta[^>]{0,200}http-equiv\s*=\s*[\"']?content-security-policy")


class RequestVerifyError(ValueError):
    """A request verification does not fit what the check needs."""


def _marker(seed: str, label: str) -> str:
    return "sk" + hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()[:12]


def _header(headers: Mapping[str, Any] | None, name: str) -> str | None:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value)
    return None


def _content_type(result: ReplayTransportResult) -> str:
    return str(_header(result.response_headers, "content-type") or "").split(";", 1)[0].strip().lower()


def _request_content_type(request: ReplayRequest) -> str:
    for name, value in request.headers:
        if str(name).lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def _with_header(request: ReplayRequest, name: str, value: str | None) -> ReplayRequest:
    """``request`` with header ``name`` replaced (or removed when ``value`` is None)."""
    kept = tuple(item for item in request.headers if str(item[0]).lower() != name.lower())
    return replace(request, headers=kept + (((name, value),) if value is not None else ()))


def _contains(result: ReplayTransportResult, needle: str) -> bool:
    return needle.encode("utf-8") in result.response_body[:2_000_000]


def _reflected(result: ReplayTransportResult, needle: str) -> bool:
    """``needle`` appears in the response body or any response header value."""
    if _contains(result, needle):
        return True
    return any(needle.lower() in str(value).lower() for value in result.response_headers.values())


_TOKEN_RE = re.compile(rb"[A-Za-z0-9_]{3,64}")


def _same_page(probe: ReplayTransportResult, baseline: ReplayTransportResult,
               probe_text: str, baseline_text: str) -> bool:
    """The probe got the page the unchanged request got, apart from the two values named.

    A host header that reaches another virtual host (a catch-all "unknown host" page that prints
    the name it was given) is not the application trusting it: the status must match and at
    least 80% of the words must be shared.
    """
    if probe.status_code != baseline.status_code:
        return False
    first = set(_TOKEN_RE.findall(probe.response_body[:500_000].replace(probe_text.encode(), b" ")))
    second = set(_TOKEN_RE.findall(baseline.response_body[:500_000].replace(baseline_text.encode(), b" ")))
    if not first and not second:
        return True
    return len(first & second) / max(1, len(first | second)) >= 0.8


_ABSOLUTE_HREF = re.compile(r'(?i)href\s*=\s*["\'](/[^"\'#?]+)["\']')


def _own_directory_links(text: str, directory: str) -> tuple[str, ...]:
    """Root-relative links to files inside the listed directory itself (some index middleware
    writes ``/dir/file`` where others write ``file``)."""
    base = directory if directory.endswith("/") else directory + "/"
    return tuple(dict.fromkeys(
        href for href in _ABSOLUTE_HREF.findall(text)
        if href.startswith(base) and len(href) > len(base) and not href.endswith("/")))[:20]


def _pair(control: ReplayTransportResult, payload: ReplayTransportResult) -> dict[str, Any]:
    return {
        "control_status": control.status_code,
        "payload_status": payload.status_code,
        "control_response_sha256": keyed_body_digest(control.response_body),
        "payload_response_sha256": keyed_body_digest(payload.response_body),
    }


def _accepted(result: ReplayTransportResult) -> bool:
    """A 2xx answer, or a redirect that does not send the browser to sign in."""
    status = result.status_code
    if not isinstance(status, int) or result.error_code:
        return False
    if 200 <= status < 300:
        return True
    return status in _REDIRECT_STATUSES and not is_login_location(_header(result.response_headers, "location"))


def _location_host(result: ReplayTransportResult) -> str:
    if result.status_code not in _REDIRECT_STATUSES:
        return ""
    value = str(_header(result.response_headers, "location") or "").strip().replace("\\", "/")
    if value.startswith("//"):
        value = "https:" + value
    try:
        return str(urllib.parse.urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _verdict(result: ReplayTransportResult, login_path: str) -> str:
    try:
        cookie_names = sorted({
            part.split("=", 1)[0].strip()
            for name, value in result.response_headers.items() if str(name).lower() == "set-cookie"
            for part in [str(value)] if "=" in part
        })
        return classify_response(
            status=result.status_code, headers=result.response_headers, cookie_names=cookie_names,
            body=result.response_body, location=_header(result.response_headers, "location"),
            login_path=login_path,
        )
    except Exception:  # noqa: BLE001 - target content never fails the check
        return "unclear"


def _multipart(fields: Sequence[tuple[str, str]], file_field: str, filename: str,
               content: bytes, content_type: str, boundary: str) -> bytes:
    parts: list[bytes] = []
    for name, value in fields:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    parts.append(
        (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
         f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n').encode() + content + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def _anti_csrf_name(name: Any) -> bool:
    key = _NOT_ALNUM_RE.sub("", str(name or "").lower())
    return (any(part in key for part in _ANTI_CSRF_PARTS) or key in _ANTI_CSRF_NAMES
            or key.endswith("nonce"))


def _without_anti_csrf_fields(request: ReplayRequest) -> tuple[ReplayRequest, list[str], bool]:
    """``(request without its anti-CSRF fields, their names, whether all could be removed)``.

    Query parameters, form fields and JSON keys (at any depth) are removed. A body that cannot be
    rewritten (multipart, XML) is only looked at: when it names such a field the third value is
    False and the caller proves nothing, since the forged request would still carry the token.
    """
    removed: list[str] = []
    parsed = urllib.parse.urlsplit(request.url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(_anti_csrf_name(name) for name, _value in pairs):
        removed += [name for name, _value in pairs if _anti_csrf_name(name)]
        kept = [(name, value) for name, value in pairs if not _anti_csrf_name(name)]
        request = replace(request, url=urllib.parse.urlunsplit((*parsed[:3], urllib.parse.urlencode(kept), "")))
    body = bytes(request.body or b"")
    if not body:
        return request, removed, True
    content_type = _request_content_type(request)
    text = body.decode("utf-8", "replace")
    if content_type == "application/x-www-form-urlencoded":
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
        if any(_anti_csrf_name(name) for name, _value in pairs):
            removed += [name for name, _value in pairs if _anti_csrf_name(name)]
            kept = [(name, value) for name, value in pairs if not _anti_csrf_name(name)]
            request = replace(request, body=urllib.parse.urlencode(kept).encode())
        return request, removed, True
    if "json" in content_type or text.lstrip()[:1] in {"{", "["}:
        try:
            document = json.loads(text)
        except ValueError:
            document = None
        if document is not None:
            found: list[str] = []

            def strip(node: Any, depth: int = 0) -> Any:
                if depth > 8:
                    return node
                if isinstance(node, dict):
                    found.extend(str(name) for name in node if _anti_csrf_name(name))
                    return {name: strip(child, depth + 1) for name, child in node.items()
                            if not _anti_csrf_name(name)}
                if isinstance(node, list):
                    return [strip(child, depth + 1) for child in node]
                return node

            stripped = strip(document)
            if found:
                removed += found
                request = replace(request, body=json.dumps(stripped, separators=(",", ":"),
                                                           ensure_ascii=False).encode())
            return request, removed, True
    named = [name.decode("utf-8", "replace") for name in _PART_NAME_RE.findall(body[:500_000])]
    unremovable = [name for name in named if _anti_csrf_name(name)]
    return request, removed + unremovable, not unremovable


def _same_site_restricted_cookie(request: ReplayRequest, results: Sequence[ReplayTransportResult]) -> tuple[str | None, str]:
    """``(a cookie of the request the application set SameSite=Lax or Strict, what was seen)``.

    The session's cookies reach this check as a ``Cookie`` header, without the attributes they were
    set with, so the only evidence is a ``Set-Cookie`` of the same name in an answer of this check
    (a session refresh). ``what was seen`` is ``lax``/``strict``/``none`` (the attribute),
    ``unspecified`` (re-set without the attribute: a Chromium browser treats that as Lax) or
    ``not_observed`` (no answer re-set a cookie of the request: nothing is known).
    """
    sent = {part.split("=", 1)[0].strip() for item in request.headers if str(item[0]).lower() == "cookie"
            for part in str(item[1]).split(";") if "=" in part}
    seen = "not_observed"
    for result in results:
        for name, value in (result.response_headers or {}).items():
            if str(name).lower() != "set-cookie":
                continue
            for line in str(value).split("\n"):
                cookie = line.split("=", 1)[0].strip()
                if cookie not in sent:
                    continue
                match = _SAME_SITE_RE.search(line)
                attribute = match.group(1).lower() if match else "unspecified"
                if attribute in {"lax", "strict"}:
                    return cookie, attribute
                seen = attribute if seen in {"not_observed", "unspecified"} else seen
    return None, seen


def _prose_words(result: ReplayTransportResult) -> frozenset[bytes]:
    return frozenset(run for run in _RUN_RE.findall(result.response_body[:500_000])
                     if _PROSE_WORD_RE.fullmatch(run))


def _same_answer(first: ReplayTransportResult, second: ReplayTransportResult) -> bool:
    """Two answers that say the same thing: the status, where a redirect goes, and the words of
    the body. A 200 page that says the token is invalid, or a redirect somewhere else, is another
    answer although its status matches; a counter, a date or a fresh token in the page is not."""
    if first.error_code or second.error_code or first.status_code != second.status_code:
        return False
    if first.status_code in _REDIRECT_STATUSES and (
            str(_header(first.response_headers, "location") or "").strip()
            != str(_header(second.response_headers, "location") or "").strip()):
        return False
    return _prose_words(first) == _prose_words(second)


Send = Callable[[ReplayRequest], Awaitable[ReplayTransportResult]]


class RequestVerifier:
    """One check over one exact request, inside a request budget the caller sends through."""

    def __init__(
        self, *, check: str, request: ReplayRequest, field: str | None, seed: str,
        send: Send, left: Callable[[], int], options: Mapping[str, Any] | None = None,
    ) -> None:
        if check not in REQUEST_CHECKS:
            raise RequestVerifyError(f"unknown request check: {check}")
        if check in FIELD_CHECKS and not field:
            raise RequestVerifyError(f"{check} needs the input to test (parameter)")
        self.check = check
        self.request = request
        self.field = field or ""
        self.seed = seed
        self.send = send
        self.left = left
        self.options = dict(options or {})
        self.writes = request.method not in {"GET", "HEAD", "OPTIONS"}

    def observation(self, proof_class: str | None = None, **fields: Any) -> dict[str, Any]:
        verified = bool(fields.get("proof_contract"))
        parsed = urllib.parse.urlsplit(self.request.url)
        return {
            "kind": "request_proof",
            "check": self.check,
            "proof_class": proof_class or self.check,
            "origin": self.request.origin(),
            "canonical_path": parsed.path or "/",
            "method": self.request.method,
            "field_path": self.field or None,
            "proof_state": "verified" if verified else "not_proven",
            "finding_verdict": "verified" if verified else "not_proven",
            "proof_contract": None,
            "technique": None,
            "repetitions": 2 if verified else 0,
            "response_pairs": [],
            "secret_values_visible": False,
            **fields,
        }

    def _with(self, value: str, request: ReplayRequest | None = None) -> ReplayRequest:
        try:
            return _mutate(request or self.request, self.field, value)
        except SQLiProofError as exc:
            raise RequestVerifyError(str(exc)) from exc

    async def run(self, baseline: ReplayTransportResult) -> list[dict[str, Any]]:
        handler = getattr(self, "_" + self.check)
        result = await handler(baseline)
        return result if isinstance(result, list) else [result]

    # -- redirects, headers and hosts ------------------------------------------------------

    async def _open_redirect(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        own = self.request.origin()
        own_host = urllib.parse.urlsplit(own).netloc

        def destinations(host: str) -> tuple[tuple[str, str], ...]:
            return (
                ("absolute", f"https://{host}/"),
                ("scheme_relative", f"//{host}/"),
                ("own_host_as_userinfo", f"https://{own_host}@{host}/"),
                ("own_origin_in_query", f"https://{host}/?next={own}/"),
            )

        first = f"{_marker(self.seed, 'redirect:1')}.{_REDIRECT_PROBE_DOMAIN}"
        second = f"{_marker(self.seed, 'redirect:2')}.{_REDIRECT_PROBE_DOMAIN}"
        for (name, value), (_same, repeat_value) in zip(destinations(first), destinations(second)):
            if self.left() < 3:
                break
            probe = await self.send(self._with(value))
            if _location_host(probe) != first:
                continue
            repeat = await self.send(self._with(repeat_value))
            # The application's own path in the same parameter: a route that redirects to the
            # canary whatever it is given would not be following the parameter.
            control = await self.send(self._with("/" + _marker(self.seed, "redirect:control")))
            if _location_host(repeat) == second and _location_host(control) not in {first, second}:
                return self.observation(
                    proof_contract=PROOF_CONTRACTS["open_redirect"],
                    technique=f"location_{name}_repeated",
                    payload_shape=value.replace(first, "<random>." + _REDIRECT_PROBE_DOMAIN),
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        return self.observation()

    async def _crlf_injection(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        for name, separator in (("crlf", "\r\n"), ("lf", "\n")):
            if self.left() < 3:
                break
            header_1, value_1 = "X-Sk-" + _marker(self.seed, f"crlf:{name}:h1"), _marker(self.seed, f"crlf:{name}:v1")
            header_2, value_2 = "X-Sk-" + _marker(self.seed, f"crlf:{name}:h2"), _marker(self.seed, f"crlf:{name}:v2")
            probe = await self.send(self._with(f"en{separator}{header_1}: {value_1}"))
            if _header(probe.response_headers, header_1) != value_1:
                continue
            repeat = await self.send(self._with(f"en{separator}{header_2}: {value_2}"))
            # The same characters with spaces where the line break was.
            control = await self.send(self._with(f"en  {header_1}: {value_1}"))
            if (
                _header(repeat.response_headers, header_2) == value_2
                and _header(control.response_headers, header_1) is None
            ):
                return self.observation(
                    proof_contract=PROOF_CONTRACTS["crlf_injection"],
                    technique=f"response_header_{name}_repeated",
                    payload_shape=f"<value>{separator.encode('unicode_escape').decode()}X-Sk-<random>: <random>",
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        return self.observation()

    def _canonical_redirect(self, result: ReplayTransportResult) -> bool:
        """A redirect to the path that was asked for (with or without a trailing slash)."""
        if result.status_code not in _REDIRECT_STATUSES:
            return False
        try:
            location = urllib.parse.urlsplit(str(_header(result.response_headers, "location") or "").strip())
        except ValueError:
            return False
        own = urllib.parse.urlsplit(self.request.url).path or "/"
        return (location.path or "/").rstrip("/") == own.rstrip("/")

    async def _host_header_injection(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        canonical_redirect = False
        headers = ("Host", *_HOST_OVERRIDE_HEADERS)
        if self.options.get("allow_identity_headers"):
            headers += _HOST_IDENTITY_HEADERS
        for header in headers:
            if self.left() < 3:
                break
            first = f"{_marker(self.seed, 'host:' + header + ':1')}.{_HOST_PROBE_DOMAIN}"
            second = f"{_marker(self.seed, 'host:' + header + ':2')}.{_HOST_PROBE_DOMAIN}"

            def value(host: str) -> str:
                return f"host={host}" if header == "Forwarded" else host

            probe = await self.send(_with_header(self.request, header, value(first)))
            own_host = urllib.parse.urlsplit(self.request.url).netloc
            if probe.error_code or not _reflected(probe, first) or not _same_page(probe, baseline, first, own_host):
                continue
            if header == "Host" and self._canonical_redirect(probe):
                # The web server's own redirect to the same path (a trailing slash, http to
                # https) is built from Host by every server; the application trusted nothing.
                canonical_redirect = True
                continue
            repeat = await self.send(_with_header(self.request, header, value(second)))
            # The same host in a header no application reads: one that echoes every request
            # header (a debugging endpoint) is not trusting the host it names.
            control_host = f"{_marker(self.seed, 'host:control')}.{_HOST_PROBE_DOMAIN}"
            control = await self.send(_with_header(self.request, _HOST_CONTROL_HEADER, control_host))
            if (
                not repeat.error_code and not control.error_code
                and _reflected(repeat, second) and not _reflected(control, control_host)
                and _same_page(repeat, baseline, second, own_host)
            ):
                where = "location" if first in str(_header(probe.response_headers, "location") or "") else (
                    "body" if _contains(probe, first) else "header")
                return self.observation(
                    proof_contract=PROOF_CONTRACTS["host_header_injection"],
                    technique=f"{header.lower()}_reflected_in_{where}_repeated",
                    header_name=header,
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        return self.observation(
            **({"not_proven_reason": "canonical_redirect_built_from_host"} if canonical_redirect else {}))

    async def _cors(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        def granted(result: ReplayTransportResult, origin: str) -> tuple[bool, bool]:
            allowed = str(_header(result.response_headers, "access-control-allow-origin") or "").strip()
            credentials = str(
                _header(result.response_headers, "access-control-allow-credentials") or ""
            ).strip().lower() == "true"
            return allowed.lower() == origin.lower(), credentials

        first = f"https://{_marker(self.seed, 'cors:1')}.{_CORS_PROBE_DOMAIN}"
        second = f"https://{_marker(self.seed, 'cors:2')}.{_CORS_PROBE_DOMAIN}"
        probe = await self.send(_with_header(self.request, "Origin", first))
        hit, credentials = granted(probe, first)
        if hit and self.left() >= 2:
            repeat = await self.send(_with_header(self.request, "Origin", second))
            # No Origin at all: a fixed header naming the probe origin is impossible, so what
            # this rules out is a response that grants whatever was last sent (a shared cache).
            control = await self.send(_with_header(self.request, "Origin", None))
            again, again_credentials = granted(repeat, second)
            if again and not granted(control, second)[0]:
                return self.observation(
                    "cors_reflected_origin",
                    proof_contract=PROOF_CONTRACTS["cors_reflected_origin"],
                    technique="origin_reflected_repeated", credentials=credentials and again_credentials,
                    response_pairs=[_pair(control, probe), _pair(control, repeat)],
                )
        if self.left() >= 3:
            probe = await self.send(_with_header(self.request, "Origin", "null"))
            hit, credentials = granted(probe, "null")
            if hit:
                repeat = await self.send(_with_header(self.request, "Origin", "null"))
                control = await self.send(_with_header(self.request, "Origin", second))
                if granted(repeat, "null")[0] and not granted(control, second)[0]:
                    return self.observation(
                        "cors_null_origin", proof_contract=PROOF_CONTRACTS["cors_null_origin"],
                        technique="null_origin_granted_repeated", credentials=credentials,
                        response_pairs=[_pair(control, probe), _pair(control, repeat)],
                    )
        allowed = str(_header(probe.response_headers, "access-control-allow-origin") or "").strip()
        if allowed == "*" and granted(probe, "*")[1] and self.left() >= 1:
            repeat = await self.send(_with_header(self.request, "Origin", first))
            if str(_header(repeat.response_headers, "access-control-allow-origin") or "").strip() == "*" \
                    and granted(repeat, "*")[1]:
                return self.observation(
                    "cors_wildcard_credentials",
                    proof_contract=PROOF_CONTRACTS["cors_wildcard_credentials"],
                    technique="wildcard_with_credentials_repeated", credentials=True,
                    response_pairs=[_pair(probe, repeat)],
                )
        return self.observation("cors_reflected_origin")

    # -- read-only posture ------------------------------------------------------------------

    async def _security_headers(self, baseline: ReplayTransportResult) -> list[dict[str, Any]]:
        def issues(result: ReplayTransportResult) -> dict[str, Any] | None:
            status = result.status_code
            if result.error_code or not isinstance(status, int) or not 200 <= status < 300:
                return None
            if _content_type(result) not in _HTML_TYPES:
                return None
            csp = str(_header(result.response_headers, "content-security-policy") or "")
            xfo = str(_header(result.response_headers, "x-frame-options") or "")
            found: dict[str, Any] = {}
            if not csp and not _META_CSP_RE.search(result.response_body[:200_000]):
                found["missing_content_security_policy"] = True
            if not xfo and "frame-ancestors" not in csp.lower():
                found["clickjacking"] = True
            weak = header_value_issues(
                {str(k).lower(): v for k, v in result.response_headers.items()}, origin=self.request.origin(),
            )
            if weak:
                found["weak_security_header"] = sorted({
                    f"{name}:{issue[0]}" for name, items in weak.items() for issue in items
                })[:20]
            return found

        first = issues(baseline)
        if not first or self.left() < 1:
            return [self.observation("missing_content_security_policy",
                                     inconclusive_reason="not_an_html_page" if first is None else None)]
        repeat = await self.send(self.request)
        second = issues(repeat) or {}
        observations = []
        for name in ("missing_content_security_policy", "clickjacking", "weak_security_header"):
            if first.get(name) and second.get(name) == first.get(name):
                observations.append(self.observation(
                    name, proof_contract=PROOF_CONTRACTS[name], technique=f"{name}_repeated",
                    **({"header_issues": first[name]} if name == "weak_security_header" else {}),
                    response_pairs=[_pair(baseline, repeat)],
                ))
        return observations or [self.observation("missing_content_security_policy")]

    async def _directory_listing(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        listed_path = urllib.parse.urlsplit(self.request.url).path or "/"
        def listing(result: ReplayTransportResult) -> bool:
            if (result.error_code and result.error_code != "incomplete_read") or result.status_code != 200:
                return False
            text = result.response_body[:500_000].decode("utf-8", "replace")
            return bool(_LISTING_RE.search(text)) and bool(
                directory_listing_links(result.response_body) or _own_directory_links(text, listed_path))

        if not listing(baseline) or self.left() < 2:
            return self.observation()
        repeat = await self.send(self.request)
        parsed = urllib.parse.urlsplit(self.request.url)
        parent = (parsed.path or "/").rstrip("/").rsplit("/", 1)[0]
        missing = f"{parent}/{_marker(self.seed, 'listing:missing')}/"
        control = await self.send(replace(self.request, url=urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, missing, "", ""))))
        if listing(repeat) and not listing(control):
            return self.observation(
                proof_contract=PROOF_CONTRACTS["directory_listing"], technique="autoindex_title_and_links_repeated",
                listed_links=len(directory_listing_links(repeat.response_body)),
                response_pairs=[_pair(control, baseline), _pair(control, repeat)],
            )
        return self.observation()

    async def _exposure(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.request.url)
        if self.request.method != "GET":
            return self.observation(inconclusive_reason="exposure is read with GET")
        if self.request.auth_type != "none" or self.request.has_sensitive_material:
            return self.observation(inconclusive_reason="the request carries an identity")

        def classify(result: ReplayTransportResult) -> Any:
            if (result.error_code and result.error_code != "incomplete_read") or result.status_code is None:
                return None
            return classify_exposure(path=parsed.path or "/", status=int(result.status_code),
                                     headers=dict(result.response_headers or {}), body=result.response_body)

        first = classify(baseline)
        if first is None or not first.proves_sensitive_exposure or not first.proof_contract or self.left() < 2:
            return self.observation(**({"exposure_class": first.exposure_class} if first else {}))
        repeat = await self.send(self.request)
        parent = (parsed.path or "/").rstrip("/").rsplit("/", 1)[0]
        missing = f"{parent}/{_marker(self.seed, 'exposure:missing')}" + ("/" if parsed.path.endswith("/") else "")
        control = await self.send(replace(self.request, url=urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, missing, "", ""))))
        second, mirrored = classify(repeat), classify(control)
        if (second is not None and second.exposure_class == first.exposure_class
                and (mirrored is None or mirrored.exposure_class != first.exposure_class)):
            return self.observation(
                first.exposure_class, proof_contract=first.proof_contract,
                technique="exposure_class_repeated_with_sibling_control", exposure_class=first.exposure_class,
                matched_pattern=first.matched_pattern, exposure_severity=first.severity,
                secret_keys=[item.get("key") for item in first.secret_evidence()][:20],
                response_pairs=[_pair(control, baseline), _pair(control, repeat)],
            )
        return self.observation(exposure_class=first.exposure_class)

    async def _unauthenticated_api(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.request.url)
        api = product_api_for(parsed.path or "/")
        if api is None or self.request.method != "GET":
            return self.observation(inconclusive_reason="not a known product management route")
        if self.request.auth_type != "none" or self.request.has_sensitive_material:
            # Only an anonymous answer shows a route that needs no authentication.
            return self.observation(inconclusive_reason="the request carries an identity")

        def answered(result: ReplayTransportResult) -> bool:
            if result.error_code or result.status_code is None or not 200 <= result.status_code < 300:
                return False
            # Every key of the product's answer, together (product_api: one key is any JSON API).
            return api.answers(result.response_body[:262_144].decode("utf-8", "replace"))

        if not answered(baseline) or self.left() < 2:
            return self.observation(product=api.product)
        repeat = await self.send(self.request)
        parent = (parsed.path or "/").rstrip("/").rsplit("/", 1)[0]
        missing = f"{parent}/{_marker(self.seed, 'api:missing')}"
        control = await self.send(replace(self.request, url=urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, missing, "", ""))))
        if answered(repeat) and not answered(control):
            return self.observation(
                proof_contract=PROOF_CONTRACTS["unauthenticated_api"],
                technique="anonymous_product_api_answer_repeated", product=api.product,
                response_pairs=[_pair(control, baseline), _pair(control, repeat)],
            )
        return self.observation(product=api.product)

    async def _graphql(self, baseline: ReplayTransportResult) -> list[dict[str, Any]]:
        parsed = urllib.parse.urlsplit(self.request.url)
        endpoint = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        post = self.request.method == "POST"
        headers = tuple(
            item for item in self.request.headers if str(item[0]).lower() not in {"content-type", "accept"}
        ) + graphql_probe.GRAPHQL_REQUEST_HEADERS

        def graphql_request(document: str | list[str]) -> ReplayRequest:
            if post:
                payload = ([{"query": item} for item in document] if isinstance(document, list)
                           else {"query": document})
                return replace(self.request, url=endpoint, body=json.dumps(payload).encode(),
                               headers=headers + (("Content-Type", "application/json"),))
            return replace(self.request, url=graphql_probe.graphql_request_url(endpoint, str(document)),
                           body=b"", headers=headers)

        async def send(url: str) -> tuple[int | None, bytes]:
            document = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("query", [""])[0]
            result = await self.send(graphql_request(document))
            return result.status_code, result.response_body

        outcome = await graphql_probe.check_endpoint(endpoint, send, can_send=lambda: self.left() > 0)
        if not outcome.get("graphql"):
            # It did not reject an undefined field, so no limit of it can be measured. Its schema
            # can still be shown: an introspection document answered twice with a schema whose
            # query root is one of its types, and a document naming an ordinary ``schema`` field
            # instead of the meta field answered without one. An echo of the request has neither.
            if self.left() < 3:
                return [self.observation("graphql_introspection", inconclusive_reason="budget")]
            # Type names only: the smallest document an introspecting server answers.
            document = "query{__schema{queryType{name}types{name}}}"
            control_query = document.replace("__schema", "schema")
            answers = [await self.send(graphql_request(document)) for _ in range(2)]
            control = await self.send(graphql_request(control_query))
            summaries = [graphql_probe.introspection_summary(graphql_probe.json_body(item.response_body))
                         for item in answers if item.status_code == 200]
            if (len(summaries) == 2 and all(summaries)
                    and graphql_probe.introspection_summary(graphql_probe.json_body(control.response_body)) is None):
                return [self.observation(
                    "graphql_introspection", proof_contract=PROOF_CONTRACTS["graphql_introspection"],
                    technique="schema_meta_field_answered_repeated_with_ordinary_field_control",
                    root_type=summaries[0]["query_type"],
                    response_pairs=[_pair(control, answers[0]), _pair(control, answers[1])],
                )]
            return [self.observation("graphql_introspection", inconclusive_reason="not_a_graphql_server")]
        observations: list[dict[str, Any]] = []
        if outcome.get("introspection"):
            observations.append(self.observation(
                "graphql_introspection", proof_contract=PROOF_CONTRACTS["graphql_introspection"],
                technique="schema_meta_field_answered_with_validation_control", repetitions=2,
                root_type=outcome.get("root_type"),
            ))
        for proof in outcome.get("proofs") or ():
            check = str(proof.get("check") or "")
            if check in PROOF_CONTRACTS:
                observations.append(self.observation(
                    check, proof_contract=PROOF_CONTRACTS[check], technique=f"{check}_with_validation_control",
                    repetitions=2, root_type=outcome.get("root_type"),
                    **{key: proof[key] for key in ("alias_count", "duplicate_count", "suggested_fields")
                       if key in proof},
                ))
        if post and self.left() >= 2:
            # A batch of operations in one request: every one answered. The same batch of the
            # undefined field must be answered with errors, so a server that answers any array
            # with an array of the same length is not counted.
            size = 10
            batch = await self.send(graphql_request([graphql_probe.TYPENAME_QUERY] * size))
            control = await self.send(graphql_request([graphql_probe.CONTROL_QUERY] * size))
            answered = graphql_probe.json_body(batch.response_body)
            refused = graphql_probe.json_body(control.response_body)
            if (
                batch.status_code == 200 and isinstance(answered, list) and len(answered) == size
                and all(graphql_probe.typename_root(item) for item in answered)
                and isinstance(refused, list) and refused
                and all(graphql_probe.rejected(item) for item in refused)
            ):
                observations.append(self.observation(
                    "batch_limit_absent", proof_contract=PROOF_CONTRACTS["batch_limit_absent"],
                    technique="operation_batch_answered_with_rejected_control", batch_size=size,
                    response_pairs=[_pair(control, batch)],
                ))
        return observations or [self.observation("graphql_introspection")]

    # -- writes ------------------------------------------------------------------------------

    async def _file_upload(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        retrieve = str(self.options.get("retrieve_path") or "")
        if "{filename}" not in retrieve or not retrieve.startswith("/"):
            raise RequestVerifyError("file_upload needs retrieve_path, a path containing {filename}")
        if self.left() < 5:
            return self.observation(inconclusive_reason="budget")
        parsed = urllib.parse.urlsplit(self.request.url)
        fields = list(self.options.get("form_fields") or ())

        def upload(label: str) -> tuple[ReplayRequest, str, bytes]:
            filename = _marker(self.seed, f"upload:{label}") + secrets.token_hex(4) + ".html"
            boundary = "----shakerscan" + secrets.token_hex(12)
            # What proves the file is served is its own markup: an element whose id and text are
            # random and are no part of the file name, so a page that prints the name it was asked
            # for (a landing page, a soft 404) does not have it, and one that prints the stored
            # text escaped does not have it as markup.
            stored = (f'<p id="sk{secrets.token_hex(6)}">sk{secrets.token_hex(8)}</p>').encode()
            content = b"<!doctype html><title>upload check</title>" + stored + b"\n"
            body = _multipart(fields, self.field, filename, content, "text/html", boundary)
            request = replace(_with_header(self.request, "Content-Type",
                                           f"multipart/form-data; boundary={boundary}"),
                              body=body, body_mode="raw")
            return request, filename, stored

        def fetch(filename: str) -> ReplayRequest:
            path = retrieve.replace("{filename}", urllib.parse.quote(filename))
            return replace(self.request, method="GET", body=b"", body_mode="none",
                           headers=tuple(item for item in self.request.headers
                                         if str(item[0]).lower() != "content-type"),
                           url=urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, *path.partition("?")[::2], "")))

        def served(result: ReplayTransportResult, stored: bytes) -> bool:
            disposition = str(_header(result.response_headers, "content-disposition") or "").lower()
            return (result.status_code == 200 and stored in result.response_body[:2_000_000]
                    and _content_type(result) in _HTML_TYPES and "attachment" not in disposition)

        request, filename, stored = upload("1")
        sent = await self.send(request)
        if not _accepted(sent):
            return self.observation(not_proven_reason="upload_refused", upload_status=sent.status_code)
        first = await self.send(fetch(filename))
        if not served(first, stored):
            return self.observation(not_proven_reason="not_served_as_html", served_status=first.status_code,
                                    served_content_type=_content_type(first) or None)
        request, filename_2, stored_2 = upload("2")
        await self.send(request)
        repeat = await self.send(fetch(filename_2))
        # A file name never uploaded: a route that answers every name with the last upload, or
        # with a page naming what it was asked for, is not serving what was stored.
        missing = _marker(self.seed, "upload:missing") + secrets.token_hex(4)
        control = await self.send(fetch(missing + ".html"))
        if _contains(control, missing):
            return self.observation(not_proven_reason="retrieve_route_echoes_the_requested_name",
                                    served_status=control.status_code)
        if served(repeat, stored_2) and not any(
                item in control.response_body[:2_000_000] for item in (stored, stored_2)):
            return self.observation(
                proof_contract=PROOF_CONTRACTS["file_upload"], technique="html_served_from_origin_repeated",
                served_content_type=_content_type(repeat), uploaded_extension=".html",
                response_pairs=[_pair(control, first), _pair(control, repeat)],
            )
        return self.observation()

    async def _rate_limit(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        path = urllib.parse.urlsplit(self.request.url).path or "/"
        attempts = min(int(self.options.get("attempts") or RATE_LIMIT_ATTEMPTS), RATE_LIMIT_ATTEMPTS)
        if self.left() < attempts:
            return self.observation(inconclusive_reason="budget")
        verdicts: list[str] = []
        statuses: list[int | None] = []
        first = last = None
        for index in range(attempts):
            if index:
                await asyncio.sleep(RATE_LIMIT_PACE_SECONDS)
            result = await self.send(self._with("Sk-" + secrets.token_urlsafe(12)))
            verdict = _verdict(result, path)
            verdicts.append(verdict)
            statuses.append(result.status_code)
            first = first or result
            last = result
            if verdict in {"rate_limited", "locked"} or verdict == "accepted":
                break
        throttled = [item for item in verdicts if item in {"rate_limited", "locked"}]
        if throttled:
            return self.observation(not_proven_reason="throttled", throttled_after=len(verdicts),
                                    throttle_verdict=throttled[0])
        if len(verdicts) == attempts and all(item == "rejected" for item in verdicts) and len(set(statuses)) == 1:
            # Stated, never verified. The check cannot tell whether the account name in the
            # request is a real account (a lockout counts failures of an account that exists), and
            # a run this short is under any threshold above it: "not rate limited" does not follow.
            # No proof contract, so no finding; the planner has the count to reason from.
            return self.observation(
                not_proven_reason="unthrottled_run_is_not_proof", technique="wrong_password_run_unthrottled",
                attempts_unthrottled=attempts, refusal_status=statuses[0],
                not_shown=["a per-account lockout (the account name is not known to be a real account)",
                           f"a threshold above {attempts} attempts or a window longer than the run"],
                response_pairs=[_pair(first, last)] if first and last else [],
            )
        return self.observation(not_proven_reason="refusal_not_recognised")

    async def _mass_assignment(self, baseline: ReplayTransportResult | None) -> dict[str, Any]:
        """A sign-up that stores a privileged field its user chose (capabilities/registration_mass_assignment)."""
        from .registration_mass_assignment import prove
        return await prove(self)

    async def _csrf(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        if not self.writes:
            raise RequestVerifyError("csrf needs a state-changing request (POST, PUT, PATCH or DELETE)")
        headers = {str(name).lower() for name, _value in self.request.headers}
        if "authorization" in headers:
            # A browser never adds a bearer token to a cross-site request: not forgeable.
            return self.observation(not_proven_reason="header_authenticated")
        if "cookie" not in headers:
            return self.observation(not_proven_reason="no_session_cookie")
        if not _accepted(baseline):
            return self.observation(not_proven_reason="original_refused", original_status=baseline.status_code)
        if self.left() < 3:
            return self.observation(inconclusive_reason="budget")
        content_type = _request_content_type(self.request)
        # Only what a browser adds by itself or a cross-site form can set: a custom anti-CSRF
        # header (X-CSRF-Token, X-Requested-With) is not among them and is dropped here.
        forged = replace(self.request, headers=tuple(
            item for item in self.request.headers if str(item[0]).lower() in _CROSS_SITE_KEPT_HEADERS
        ))
        token = str(self.options.get("token_field") or "")
        if token and not _anti_csrf_name(token.rsplit(".", 1)[-1]):
            # A field the planner names beside the ones recognised by name below.
            try:
                forged = _mutate(forged, token, "")
            except SQLiProofError as exc:
                raise RequestVerifyError(f"token_field: {exc}") from exc
        forged, removed, all_removed = _without_anti_csrf_fields(forged)
        if not all_removed:
            # The token is in a body this check cannot rewrite: the forged request would carry it.
            return self.observation(not_proven_reason="anti_csrf_field_not_removable",
                                    anti_csrf_fields=sorted(set(removed))[:10])
        if content_type and not content_type.startswith(_SIMPLE_CONTENT_TYPES):
            # A cross-site form can send a JSON document only as text/plain.
            forged = _with_header(forged, "Content-Type", "text/plain")
        site = f"https://{_marker(self.seed, 'csrf')}.{_CSRF_PROBE_DOMAIN}"
        forged = _with_header(_with_header(_with_header(forged, "Origin", site), "Referer", site + "/"),
                              "Sec-Fetch-Site", "cross-site")
        fields = {"anti_csrf_fields_removed": sorted(set(removed))[:10],
                  "token_field_removed": bool(token or removed)}
        own_path = urllib.parse.urlsplit(self.request.url).path or "/"
        if baseline.status_code in _REDIRECT_STATUSES and (urllib.parse.urlsplit(
                str(_header(baseline.response_headers, "location") or "")).path or "/").rstrip("/") == own_path.rstrip("/"):
            # The original is answered with a redirect back to its own page. So is a refused form
            # (the form again, with an error only the next page shows): the answer cannot tell an
            # accepted forgery from a rejected one, and nothing is proved from it.
            return self.observation(not_proven_reason="redirect_to_own_page_shows_no_write", **fields)
        probe = await self.send(forged)
        if not _accepted(probe) or not _same_answer(probe, baseline):
            return self.observation(not_proven_reason="cross_site_refused", forged_status=probe.status_code,
                                    **fields)
        repeat = await self.send(forged)
        # Without the session: the action must need it, or forging it from another site gains
        # nothing the attacker could not do directly.
        control = await self.send(_with_header(forged, "Cookie", None))
        cookie, same_site = _same_site_restricted_cookie(self.request, (baseline, probe, repeat))
        if cookie:
            # A browser does not attach a SameSite=Lax or Strict cookie to a cross-site POST: the
            # forged request this check sent is not one a victim's browser would send.
            return self.observation(not_proven_reason="session_cookie_same_site", same_site_cookie=cookie[:80],
                                    session_cookie_same_site=same_site, **fields)
        if (_accepted(repeat) and _same_answer(repeat, baseline)
                and not _accepted(control) and not _same_answer(control, probe)):
            return self.observation(
                proof_contract=PROOF_CONTRACTS["csrf"], technique="cross_site_simple_request_accepted_repeated",
                forged_content_type=_request_content_type(forged) or None,
                # ``not_observed``: no answer re-set a session cookie, so its SameSite attribute is
                # unknown to this check (it is given the Cookie header, not how it was set).
                session_cookie_same_site=same_site, **fields,
                response_pairs=[_pair(control, probe), _pair(control, repeat)],
            )
        return self.observation(not_proven_reason="session_not_required" if _accepted(control) else None, **fields)

    async def _ldap_injection(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        path = urllib.parse.urlsplit(self.request.url).path or "/"
        if self.left() < 4:
            return self.observation(inconclusive_reason="budget")
        literal = await self.send(self._with(_marker(self.seed, "ldap:literal")))
        if _verdict(literal, path) != "rejected":
            return self.observation(not_proven_reason="literal_not_refused")
        for wildcard in _LDAP_WILDCARDS:
            if self.left() < 3:
                break
            probe = await self.send(self._with(wildcard))
            if _verdict(probe, path) != "accepted":
                continue
            repeat = await self.send(self._with(wildcard))
            # The wildcard escaped as RFC 4515 asks: a directory filter reads it as a literal.
            control = await self.send(self._with(wildcard.replace("*", "\\2a").replace("(", "\\28").replace(")", "\\29")))
            if _verdict(repeat, path) == "accepted" and _verdict(control, path) == "rejected":
                return self.observation(
                    proof_contract=PROOF_CONTRACTS["ldap_injection"],
                    technique="wildcard_sign_in_accepted_repeated", payload_shape=wildcard,
                    response_pairs=[_pair(control, probe), _pair(control, repeat), _pair(literal, probe)],
                )
        return self.observation()

    async def _jwt(self, baseline: ReplayTransportResult) -> dict[str, Any]:
        token = jwt_forgery.bearer_jwt(dict(self.request.headers))
        if not token:
            return self.observation(not_proven_reason="no_bearer_jwt")
        if not isinstance(baseline.status_code, int) or not 200 <= baseline.status_code < 300:
            return self.observation(not_proven_reason="principal_refused", original_status=baseline.status_code)

        async def send(forged: str | None) -> tuple[int | None, str]:
            # The principal's other headers stay; None sends the request without the bearer.
            result = await self.send(_with_header(
                self.request, "Authorization", None if forged is None else f"Bearer {forged}"))
            return (None if result.error_code else result.status_code,
                    keyed_body_digest(result.response_body))

        proof = await jwt_forgery.check_token_handling(
            token, send=send, accepted_status=int(baseline.status_code),
            accepted_digest=keyed_body_digest(baseline.response_body), left=self.left,
        )
        if not proof:
            return self.observation()
        return self.observation(**{
            key: value for key, value in proof.items()
            if key not in {"kind", "proof_state", "finding_verdict"}
        })


class RequestVerifyAdapter:
    """Send one check's requests through a budgeted, cancellable transport."""

    capability_name = "request.verify"
    adapter_name = "request.verify"
    adapter_version = "1"
    manages_cancellation = True

    def __init__(
        self, *, check: str, target: TargetBinding, request: ReplayRequest, field: str | None,
        transport: ReplayTransport, requested_budget: Mapping[str, int], seed: str,
        request_class: str = "safe_read", options: Mapping[str, Any] | None = None,
    ) -> None:
        if int(requested_budget.get("http_requests") or 0) < MINIMUM_REQUESTS:
            raise RequestVerifyError(f"request verification needs at least {MINIMUM_REQUESTS} HTTP requests")
        self.check = check
        self.target = target
        self.request = request
        self.field = field
        self.transport = transport
        self.requested_budget = {str(k): int(v) for k, v in requested_budget.items()}
        self.seed = seed
        self.request_class = request_class
        self.options = dict(options or {})

    async def execute(self, *, heartbeat: Heartbeat, cancelled: Cancelled) -> CapabilityAdapterResult:
        started = time.monotonic()
        attempted = 0
        results: list[ReplayTransportResult] = []
        budget = self.requested_budget["http_requests"]
        wall = max(1, int(self.requested_budget.get("tool_wall_seconds") or 60))

        def left() -> int:
            return budget - attempted

        async def send(request: ReplayRequest) -> ReplayTransportResult:
            nonlocal attempted
            if cancelled():
                raise RequestVerifyError("cancelled")
            if attempted >= budget:
                raise RequestVerifyError("budget_exhausted")
            wall_left = wall - (time.monotonic() - started)
            if wall_left < 0.5:
                raise RequestVerifyError("deadline")
            attempted += 1  # counted before it is sent: a request cut off in flight still arrived
            result = await self.transport.send(
                request, target=self.target,
                # A check sends a handful of requests, not its whole hold: dividing the wall by the
                # hold (48) gave each request about a second, and slow answers timed out.
                timeout_seconds=max(0.5, min(15.0, wall_left / max(1, min(8, budget - attempted + 1)))),
                follow_redirects=False,
            )
            results.append(result)
            await heartbeat()
            return result

        def spent() -> dict[str, int]:
            used = {"http_requests": attempted,
                    "tool_wall_seconds": min(wall, max(1, math.ceil(time.monotonic() - started)))}
            for dimension in ("state_changing_requests", "verifier_write_requests"):
                if dimension in self.requested_budget and (
                    self.request.method not in {"GET", "HEAD", "OPTIONS"} or self.check == "file_upload"
                ):
                    used[dimension] = attempted
            return used

        verifier = RequestVerifier(
            check=self.check, request=self.request, field=self.field, seed=self.seed,
            send=send, left=left, options=self.options,
        )
        observations: list[dict[str, Any]] = []
        refused = None
        baseline = None
        classified_short = False
        try:
            if self.check in {"file_upload", "mass_assignment"}:
                # An upload or a sign-up builds each request it sends; the bare request is never sent.
                observations.extend(await verifier.run(None))
            else:
                baseline = await send(self.request)
                refused = request_refusal(
                    baseline.status_code, baseline.response_headers, request_class=self.request_class,
                    url=self.request.url, body=self.request.body,
                )
                # A short body is still the server's content for the checks that only classify it.
                usable = not baseline.error_code or (
                    baseline.error_code == "incomplete_read" and self.check in {"directory_listing", "exposure"})
                if refused is None and usable:
                    observations.extend(await verifier.run(baseline))
                    classified_short = bool(baseline.error_code)
        except RequestVerifyError as exc:
            reason = str(exc)
            if reason not in {"cancelled", "deadline", "budget_exhausted"} and not attempted:
                return CapabilityAdapterResult(
                    status="blocked", errors=(reason[:300],), execution_started=False,
                    actual_budget=spent(), parser_version=REQUEST_VERIFY_PARSER_VERSION,
                )
            return CapabilityAdapterResult(
                status="cancelled" if reason == "cancelled" else "partial",
                observations=tuple(observations), errors=(reason[:300],), execution_started=True,
                timed_out=reason == "deadline", actual_budget=spent(), partial=True,
                parser_version=REQUEST_VERIFY_PARSER_VERSION,
            )
        errors = tuple(item.error_code for item in results
                       if item.error_code and not (classified_short and item.error_code == "incomplete_read"))
        if refused is not None and baseline is not None:
            observations.append(verifier.observation(
                finding_verdict="inconclusive", inconclusive_reason=refused[1],
                control_status=baseline.status_code,
            ))
            errors = (refusal_error(*refused), *errors)
        elif baseline is not None and baseline.error_code and not classified_short:
            observations.append(verifier.observation(
                finding_verdict="inconclusive", inconclusive_reason=baseline.error_code,
            ))
        return CapabilityAdapterResult(
            status="partial" if errors else "success", observations=tuple(observations),
            errors=errors, actual_budget=spent(), partial=bool(errors),
            timed_out=any(item.timed_out for item in results), execution_started=True,
            parser_version=REQUEST_VERIFY_PARSER_VERSION,
            redacted_execution={
                "check": self.check, "method": self.request.method, "field_path": self.field,
                "proof_contract": next((item.get("proof_contract") for item in observations
                                        if item.get("proof_state") == "verified"), None),
                "secret_values_visible": False,
            },
        )


__all__ = [
    "FIELD_CHECKS", "MINIMUM_REQUESTS", "PROOF_CONTRACTS", "RATE_LIMIT_ATTEMPTS", "REQUEST_CHECKS",
    "REQUEST_VERIFY_PARSER_VERSION", "RequestVerifier", "RequestVerifyAdapter", "RequestVerifyError",
]
