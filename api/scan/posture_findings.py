"""Findings judged from recorded posture: header VALUES, CORS answers, open redirects, DNS/email.

Every rule here reads an observation the Scan already recorded (the pinned baseline response, the
two CORS probe responses, a redirect probe's Location header, the DNS posture records) and states
the observed value next to the expected one. Nothing here sends traffic. Each finding carries its
severity reason (``severity_basis``) because the severity depends on which weakness was observed,
not only on the class.

Presence checks the baseline does NOT turn into findings, with the reasoning, live in
``OPT_IN_HEADERS``.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Callable, Iterable, Mapping, Sequence

try:
    from scope.psl import registrable_domain
except ModuleNotFoundError:  # package import in host-side tests
    from ..scope.psl import registrable_domain

from .severity_calibration import SEVERITY_BASIS_SCHEMA, SEVERITY_ORDER

# Origins the CORS probes send. ``.invalid`` is reserved (RFC 6761): it never resolves, so a
# reflected value can only have come from the request.
CORS_PROBE_ORIGIN = "https://shakerscan-cors-probe.invalid"
CORS_PROBE_ACTIONS: Mapping[str, str] = {
    "baseline.cors": CORS_PROBE_ORIGIN,
    "baseline.cors_null": "null",
}
# The destination the open-redirect probe puts into a redirect parameter. Out of scope by
# construction and non-resolving: the probe never follows it, it only reads the Location header.
REDIRECT_CANARY_HOST = "shakerscan-redirect-probe.invalid"
REDIRECT_CANARY_URL = f"https://{REDIRECT_CANARY_HOST}/"

# Missing-header presence checks reported by the passive header template that are not findings:
#  * Cross-Origin-Embedder/Opener/Resource-Policy are opt-in isolation features a site needs only
#    for cross-origin isolation (SharedArrayBuffer, high-resolution timers) or to keep a resource
#    from being embedded; their absence is the browser default for nearly every site, not a
#    weakness, and reporting them on every origin buried the findings that matter.
#  * X-Permitted-Cross-Domain-Policies governs Flash/Acrobat cross-domain policy files; Flash
#    reached end of life in 2020.
#  * Clear-Site-Data is a logout-time instruction, not a header every response should carry.
# Their absence stays visible in the report's posture section (missing_security_headers).
OPT_IN_HEADERS = frozenset({
    "cross-origin-embedder-policy", "cross-origin-opener-policy", "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies", "clear-site-data",
})

_HSTS_MIN_SECONDS = 15_552_000  # 180 days, the floor browser preload lists and scanners use
_POWERFUL_FEATURES = ("camera", "microphone", "geolocation", "payment", "usb", "display-capture")
_REFERRER_TOKENS = {
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
}

FindingFactory = Callable[..., dict[str, Any]]

# A URL's query in a recorded header value: CSP report-uri endpoints (and Reporting-Endpoints,
# Location) commonly carry an ingest key or token there (Sentry's ?sentry_key=, report-uri.com).
_URL_QUERY = re.compile(r"(https?://[^\s;,'\"?#]+)\?([^\s;,'\"#]*)", re.IGNORECASE)


def redact_url_queries(value: str) -> str:
    """``value`` with every URL query value replaced by ``<redacted>``; parameter names are kept."""
    def redact(match: re.Match[str]) -> str:
        names = [part.split("=", 1)[0] for part in match.group(2).split("&") if part]
        return match.group(1) + "?" + "&".join(f"{name}=<redacted>" for name in names)
    return _URL_QUERY.sub(redact, value)


def _worst(levels: Iterable[str]) -> str:
    return max(levels, key=SEVERITY_ORDER.index, default="info")


def severity_basis(rule: str, severity: str, reason: str, factors: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
    return {
        "schema": SEVERITY_BASIS_SCHEMA, "rule": rule, "severity": severity,
        "producer_severity": severity, "reason": reason, "factors": [dict(item) for item in factors][:10],
    }


# --------------------------------------------------------------------------- header values


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() not in directives:
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return directives


def _csp_issues(policy: str) -> list[tuple[str, str, str]]:
    directives = _csp_directives(policy)
    script = directives.get("script-src", directives.get("default-src"))
    issues: list[tuple[str, str, str]] = []
    if script is None:
        # A policy that only sets framing (frame-ancestors) is still no script policy: an
        # injected script runs exactly as without a CSP, and no missing-CSP finding says so.
        only = ", ".join(sorted(directives)) or "no directives"
        issues.append(("low", "csp_no_script_policy",
                       f"No script-src or default-src directive (the policy sets only {only}): scripts may load from any origin."))
        script = []
    # 'strict-dynamic' (CSP3) makes browsers ignore host and scheme sources and 'unsafe-inline':
    # scripts load only through a nonce or hash and what those scripts load. Policies list
    # https: and 'unsafe-inline' beside it on purpose, as the fallback for older browsers.
    strict_dynamic = "'strict-dynamic'" in script
    wildcards = [] if strict_dynamic else [token for token in script if token in {"*", "http:", "https:", "data:", "blob:"}]
    if wildcards:
        issues.append(("low", "csp_script_any_origin",
                       f"Scripts may load from any origin ({' '.join(wildcards)}), so an attacker-hosted script is allowed."))
    if "'unsafe-eval'" in script:
        issues.append(("low", "csp_unsafe_eval", "'unsafe-eval' lets injected strings run as code (eval, new Function)."))
    neutralised = strict_dynamic or any(token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for token in script)
    if "'unsafe-inline'" in script and not neutralised:
        issues.append(("info", "csp_unsafe_inline",
                       "'unsafe-inline' without a nonce or hash lets an injected inline <script> run; the policy still limits where scripts load from."))
    ancestors = directives.get("frame-ancestors")
    if ancestors is not None and "*" in ancestors:
        issues.append(("low", "csp_frame_any_origin", "frame-ancestors * lets any site frame the page (clickjacking)."))
    return issues


def _hsts_issues(value: str, *, host: str) -> list[tuple[str, str, str]]:
    tokens = [token.strip().lower() for token in value.split(";") if token.strip()]
    max_age = None
    for token in tokens:
        name, _sep, raw = token.partition("=")
        if name.strip() == "max-age":
            raw = raw.strip().strip('"')
            max_age = int(raw) if raw.isdigit() else None
    issues: list[tuple[str, str, str]] = []
    if max_age is None:
        issues.append(("low", "hsts_no_max_age", "No valid max-age directive: browsers ignore the header."))
    elif max_age == 0:
        issues.append(("low", "hsts_disabled", "max-age=0 tells browsers to forget HSTS for this host."))
    elif max_age < _HSTS_MIN_SECONDS:
        days = max_age // 86_400
        issues.append(("low", "hsts_short_max_age",
                       f"max-age={max_age} ({days} day{'s' if days != 1 else ''}) is shorter than 180 days: the protection lapses between visits."))
    apex = registrable_domain(host) if host else None
    if max_age and "includesubdomains" not in tokens and apex and apex == host:
        issues.append(("info", "hsts_no_include_subdomains",
                       "This is the registrable domain and HSTS omits includeSubDomains, so its subdomains can still be reached over plain HTTP (cookie injection for the parent domain)."))
    return issues


def _referrer_issues(value: str) -> list[tuple[str, str, str]]:
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    effective = next((token for token in reversed(tokens) if token in _REFERRER_TOKENS), None)
    if effective is None:
        return [("info", "referrer_unrecognised", f"No recognised policy token in {value!r}: browsers fall back to their default.")]
    if effective == "unsafe-url":
        return [("low", "referrer_unsafe_url",
                 "unsafe-url sends the full URL, including path and query string, to every other site and even over plain HTTP.")]
    if effective == "no-referrer-when-downgrade":
        return [("info", "referrer_full_url_cross_origin",
                 "no-referrer-when-downgrade sends the full URL (path and query) to every other HTTPS site.")]
    return []


def _repeated_tokens(value: str) -> set[str]:
    """The distinct comma-separated values of a header a server sent more than once.

    Repeated header lines are recorded joined with ", " ("SAMEORIGIN, SAMEORIGIN"); the same
    value twice is that value, not an invalid one.
    """
    return {token.strip().upper() for token in value.split(",") if token.strip()}


def _xfo_issues(value: str, csp: str) -> list[tuple[str, str, str]]:
    tokens = _repeated_tokens(value)
    if (len(tokens) == 1 and tokens <= {"DENY", "SAMEORIGIN"}) or "frame-ancestors" in csp.lower():
        return []
    return [("low", "xfo_invalid",
             f"Browsers ignore X-Frame-Options: {value.strip()[:60]} (only DENY and SAMEORIGIN are honoured) and no CSP frame-ancestors is set, so any site can frame the page.")]


def _permissions_issues(value: str) -> list[tuple[str, str, str]]:
    granted = [
        feature for feature in _POWERFUL_FEATURES
        if re.search(rf"(?:^|,)\s*{feature}\s*=\s*(?:\*|\(\s*\*\s*\))", value.lower())
    ]
    if not granted:
        return []
    return [("info", "permissions_any_origin",
             f"{', '.join(granted)} {'is' if len(granted) == 1 else 'are'} granted to every origin, including embedded third-party frames.")]


# header -> (display, expected value)
_VALUE_CHECKS: Mapping[str, tuple[str, str]] = {
    "content-security-policy": ("Content-Security-Policy", "script-src 'self' with nonces or hashes; no *, scheme wildcards, 'unsafe-eval' or bare 'unsafe-inline'; frame-ancestors 'self'"),
    "strict-transport-security": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    "referrer-policy": ("Referrer-Policy", "strict-origin-when-cross-origin (or stricter)"),
    "x-frame-options": ("X-Frame-Options", "DENY or SAMEORIGIN (or CSP frame-ancestors)"),
    "x-content-type-options": ("X-Content-Type-Options", "nosniff"),
    "permissions-policy": ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
}


def header_value_issues(headers: Mapping[str, Any], *, origin: str) -> dict[str, list[tuple[str, str, str]]]:
    """Weaknesses in the VALUES of the security headers a response carried, per header."""
    lowered = {str(name).lower(): str(value) for name, value in headers.items() if value is not None}
    parsed = urllib.parse.urlsplit(origin)
    host = str(parsed.hostname or "").lower().rstrip(".")
    out: dict[str, list[tuple[str, str, str]]] = {}
    csp = lowered.get("content-security-policy", "")
    if csp.strip():
        out["content-security-policy"] = _csp_issues(csp)
    if parsed.scheme == "https" and lowered.get("strict-transport-security", "").strip():
        out["strict-transport-security"] = _hsts_issues(lowered["strict-transport-security"], host=host)
    if lowered.get("referrer-policy", "").strip():
        out["referrer-policy"] = _referrer_issues(lowered["referrer-policy"])
    if lowered.get("x-frame-options", "").strip():
        out["x-frame-options"] = _xfo_issues(lowered["x-frame-options"], csp)
    xcto = lowered.get("x-content-type-options", "").strip()
    if xcto and _repeated_tokens(xcto) != {"NOSNIFF"}:
        out["x-content-type-options"] = [("info", "xcto_invalid", f"Only nosniff is defined; browsers ignore {xcto[:60]!r} and may sniff content types.")]
    if lowered.get("permissions-policy", "").strip():
        out["permissions-policy"] = _permissions_issues(lowered["permissions-policy"])
    return {name: issues for name, issues in out.items() if issues}


def weak_header_findings(
    headers: Mapping[str, Any], *, origin: str, status: int, observed_response: Mapping[str, Any],
    make: FindingFactory,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lowered = {str(name).lower(): str(value) for name, value in headers.items() if value is not None}
    for header, issues in header_value_issues(headers, origin=origin).items():
        display, expected = _VALUE_CHECKS[header]
        severity = _worst(level for level, _code, _text in issues)
        check = f"weak_header_{header}"
        reason = (
            "The header is present but its value leaves the protection it exists for open: "
            + " ".join(text for level, _code, text in issues if level == severity)
            + (" It hardens the page against other flaws; it is not a vulnerability by itself." if severity in {"low", "info"} else "")
        )
        findings.append(make(
            tool="http_baseline", title=f"Weak {display} header value", severity=severity, cwe="CWE-693", url=origin,
            evidence={
                "check": check, "url": origin, "status": status, "header": header,
                "observed_value": redact_url_queries(lowered.get(header, ""))[:2_000], "expected_value": expected,
                "issues": [{"severity": level, "code": code, "text": text} for level, code, text in issues],
                "observed_response": dict(observed_response),
                "severity_basis": severity_basis(check, severity, reason, [{"factor": code, "text": text} for _l, code, text in issues]),
            },
            verification_reason=f"Pinned deterministic HTTP response carried a weak {display} value",
        ))
    return findings


# --------------------------------------------------------------------------------- CORS


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() == "true"


def cors_findings(
    action_id: str, request: Mapping[str, Any], response: Mapping[str, Any], *, make: FindingFactory,
) -> list[dict[str, Any]]:
    """Judge one CORS probe response: did the server grant the probe's Origin?"""
    sent = CORS_PROBE_ACTIONS.get(action_id)
    status = response.get("status")
    headers = response.get("security_headers") if isinstance(response.get("security_headers"), Mapping) else {}
    if sent is None or not isinstance(status, int) or not 100 <= status < 500:
        return []
    allowed = str(headers.get("access-control-allow-origin") or "").strip()
    credentials = _truthy(headers.get("access-control-allow-credentials"))
    origin = str(request.get("origin") or response.get("final_url") or "")
    path = str(request.get("path") or "/")
    if not allowed:
        return []
    if sent == "null" and allowed.lower() == "null":
        kind, severity, title = "cors_null_origin", ("high" if credentials else "low"), "CORS policy trusts the null origin"
        why = ("Any site can send requests from a sandboxed frame, whose Origin is null, and read the answers"
               + (" with the user's cookies: data the user can see is readable by that site." if credentials else
                  "; without credentials only what an anonymous request returns is exposed."))
    elif sent != "null" and allowed.lower() == sent.lower():
        kind, severity, title = "cors_reflected_origin", ("high" if credentials else "low"), "CORS policy reflects any origin"
        why = ("The server echoes whatever Origin it is sent, so every website is trusted"
               + (" and allowed to read responses with the user's cookies: data the user can see is readable by any site." if credentials else
                  "; without credentials only what an anonymous request returns is exposed, but internal-only responses become readable from a user's browser."))
    elif allowed == "*" and credentials:
        kind, severity, title = "cors_wildcard_credentials", "low", "CORS wildcard combined with credentials"
        why = ("Browsers refuse Access-Control-Allow-Origin: * together with credentials, so nothing is exposed by this "
               "response, but the configuration shows the policy is not deliberate; an origin-reflecting variant would be.")
    else:
        return []
    return [make(
        tool="http_baseline", title=title, severity=severity, cwe="CWE-942", url=origin,
        evidence={
            "check": kind, "url": origin, "path": path, "status": status,
            "request_origin_header": sent,
            "access_control_allow_origin": allowed[:300],
            "access_control_allow_credentials": credentials,
            "source_action_id": action_id,
            "severity_basis": severity_basis(kind, severity, why),
        },
        verification_reason=f"The pinned response to Origin: {sent} granted it in Access-Control-Allow-Origin",
    )]


# ------------------------------------------------------------------------- open redirect

REDIRECT_PARAMETER_NAMES = frozenset({
    "next", "url", "redirect", "redirecturl", "redirecturi", "redir", "return", "returnurl",
    "returnto", "returnpath", "continue", "continueurl", "dest", "destination", "desturl", "goto",
    "go", "target", "targeturl", "to", "out", "rurl", "forward", "forwardurl", "back", "backurl",
    "successurl", "failureurl", "cancelurl", "logouturl", "callbackurl", "checkouturl", "link",
    "location", "u", "r",
})


def is_redirect_parameter(name: Any) -> bool:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower()) in REDIRECT_PARAMETER_NAMES


def redirects_to_canary(location: Any) -> bool:
    """True when a Location header sends the browser to the canary host."""
    value = str(location or "").strip().replace("\\", "/")
    if not value:
        return False
    if value.startswith("//"):
        value = "https:" + value
    try:
        host = urllib.parse.urlsplit(value).hostname
    except ValueError:
        return False
    return str(host or "").lower().rstrip(".") == REDIRECT_CANARY_HOST


def open_redirect_finding(item: Mapping[str, Any], *, make: FindingFactory) -> dict[str, Any] | None:
    if item.get("proof_state") != "verified" or not redirects_to_canary(item.get("location")):
        return None
    url = str(item.get("url") or "")
    parameter = str(item.get("parameter") or "")[:120]
    reason = ("A link on this trusted origin forwards users to any site an attacker names: convincing phishing, "
              "and token theft when the parameter is an OAuth/SSO return address. It needs a victim to follow a "
              "crafted link and exposes no data by itself.")
    return make(
        tool="shakerscan_redirect_probe", title="Open redirect", severity="medium", cwe="CWE-601", url=url,
        evidence={
            "check": "open_redirect", "url": url, "parameter": parameter, "status": item.get("status"),
            "probe_destination": REDIRECT_CANARY_URL, "location": str(item.get("location") or "")[:500],
            "method": "GET", "severity_basis": severity_basis("open_redirect", "medium", reason),
        },
        verification_reason=f"The {parameter} parameter set to an external URL produced a redirect to it",
    )


# ------------------------------------------------------------------------- DNS / email

_SPF_LOOKUP_TERMS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr\b|ptr:|exists:|redirect=)", re.IGNORECASE)


def _spf_records(values: Sequence[Any]) -> list[str]:
    return [str(value).strip() for value in values if str(value).strip().lower().startswith("v=spf1")]


def dns_posture_findings(observation: Mapping[str, Any], *, make: FindingFactory) -> list[dict[str, Any]]:
    """SPF, DMARC and CAA posture of a domain target from the recorded DNS answers."""
    host = str(observation.get("canonical_host") or "").lower().rstrip(".")
    records = observation.get("records") if isinstance(observation.get("records"), Mapping) else {}
    names = observation.get("query_names") if isinstance(observation.get("query_names"), Mapping) else {}
    errors = [str(item) for item in observation.get("errors") or ()]
    apex = registrable_domain(host) if host else None
    if not apex:
        return []  # an address or a single-label name has no mail/CA policy of its own
    is_apex = apex == host
    url = f"https://{host}"  # as the takeover check names a host: its HTTPS origin
    # A label is judged only when its query was answered (records or an authoritative negative
    # answer recorded in record_metadata). A query that timed out or failed leaves its label with
    # an empty list too, and reading that as "no record" reported verified missing DMARC/CAA/SPF.
    metadata = observation.get("record_metadata") if isinstance(observation.get("record_metadata"), Mapping) else {}
    failed = {item.split(":", 1)[0] for item in errors}
    failed.update(label for label in ("host_txt", "dmarc", "host_caa") if label not in metadata)
    txt = list(records.get("host_txt") or ())
    mx = list(records.get("host_mx") or ())
    dmarc_values = [str(value) for value in records.get("dmarc") or () if str(value).lower().startswith("v=dmarc1")]
    findings: list[dict[str, Any]] = []

    def add(check: str, title: str, severity: str, why: str, **evidence: Any) -> None:
        findings.append(make(
            tool="dns.inspect", title=title, severity=severity, cwe=evidence.pop("cwe", "CWE-290"), url=url,
            evidence={"check": check, "host": host, "registrable_domain": apex, **evidence,
                      "severity_basis": severity_basis(check, severity, why)},
            verification_reason="Recorded DNS answers for the target's own names",
        ))

    sends_mail_context = bool(mx) or is_apex
    if "host_txt" not in failed:
        spf = _spf_records(txt)
        if len(spf) > 1:
            add("spf_multiple_records", "Multiple SPF records", "low",
                "RFC 7208 allows one SPF record; with several, receivers return permerror and SPF protects nothing.",
                spf_records=spf[:5], expected="exactly one v=spf1 record", query_name=names.get("host_txt"))
        elif not spf and sends_mail_context:
            severity = "low" if mx else "info"
            add("spf_missing", "No SPF record", severity,
                ("The domain receives mail but publishes no SPF policy, so receivers cannot tell forged senders from real ones."
                 if mx else "No SPF record: publishing 'v=spf1 -all' on a domain that sends no mail stops it being used as a forged sender."),
                spf_records=[], mx_hosts=[str(item.get("host") if isinstance(item, Mapping) else item) for item in mx][:5],
                expected="v=spf1 include:<your mail provider> -all (or v=spf1 -all if the domain sends no mail)",
                query_name=names.get("host_txt"))
        elif spf:
            record = spf[0]
            terms = record.split()[1:]
            qualifier_all = next((term.lower() for term in terms if term.lower().lstrip("+-~?") == "all"), None)
            if qualifier_all in {"+all", "all"}:
                add("spf_pass_all", "SPF record authorizes every sender (+all)", "medium",
                    "'+all' declares every server on the internet an authorized sender, so SPF passes forged mail for this domain.",
                    spf_record=record[:500], expected="end the record with -all (or ~all while rolling out)", query_name=names.get("host_txt"))
            elif qualifier_all == "?all":
                add("spf_neutral_all", "SPF record ends in ?all (neutral)", "low",
                    "'?all' makes every unlisted sender neutral: receivers treat forged mail as if no SPF existed.",
                    spf_record=record[:500], expected="end the record with -all or ~all", query_name=names.get("host_txt"))
            lookups = sum(1 for term in terms if _SPF_LOOKUP_TERMS.match(term))
            if lookups > 10:
                add("spf_too_many_lookups", "SPF record exceeds 10 DNS lookups", "low",
                    "Receivers stop after 10 DNS-querying mechanisms (RFC 7208 §4.6.4) and return permerror, so SPF protects nothing.",
                    spf_record=record[:500], lookup_count=lookups, counted="top-level mechanisms only (nested includes not resolved)",
                    expected="at most 10 include/a/mx/ptr/exists/redirect lookups in total", query_name=names.get("host_txt"))
    if is_apex and "dmarc" not in failed:
        if not dmarc_values:
            add("dmarc_missing", "No DMARC record", "low" if (mx or _spf_records(txt)) else "info",
                "Without DMARC, receivers apply no policy to mail that fails SPF/DKIM alignment and the owner receives no reports of spoofing.",
                dmarc_records=[], expected="v=DMARC1; p=quarantine (or p=reject); rua=mailto:<reports address>",
                query_name=names.get("dmarc") or f"_dmarc.{host}")
        else:
            tags = {part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip().lower()
                    for part in dmarc_values[0].split(";") if "=" in part}
            if tags.get("p") == "none":
                add("dmarc_policy_none", "DMARC policy is p=none (monitoring only)", "low",
                    "p=none asks receivers to deliver mail that fails DMARC anyway: spoofed mail is reported but not blocked.",
                    dmarc_record=dmarc_values[0][:500], expected="p=quarantine or p=reject once reports show legitimate mail aligns",
                    query_name=names.get("dmarc") or f"_dmarc.{host}")
    if is_apex and "host_caa" not in failed and not list(records.get("host_caa") or ()):
        add("caa_missing", "No CAA record", "info",
            "Without CAA any public CA may issue certificates for this domain; CAA narrows issuance to the CAs you use. Hardening only.",
            cwe="CWE-295", expected='0 issue "<your CA, e.g. letsencrypt.org>"', query_name=names.get("host_caa"))
    return findings


__all__ = [
    "CORS_PROBE_ACTIONS", "CORS_PROBE_ORIGIN", "OPT_IN_HEADERS", "REDIRECT_CANARY_HOST", "REDIRECT_CANARY_URL",
    "cors_findings", "dns_posture_findings", "header_value_issues", "is_redirect_parameter",
    "open_redirect_finding", "redact_url_queries", "redirects_to_canary", "severity_basis",
    "weak_header_findings",
]
