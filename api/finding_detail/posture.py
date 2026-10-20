"""CORS, open-redirect and DNS/email posture findings: the observed answer, the expected one, a fix."""

from __future__ import annotations

from typing import Any, Mapping
import urllib.parse

from .common import command, display_url, fact, facts, origin_of, q, text, url_parts

_CORS_EXAMPLES = (
    ("Express (cors)", "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))"),
    ("Spring", "@CrossOrigin(origins = \"https://app.example.com\", allowCredentials = \"true\")"),
    ("nginx", "map $http_origin $cors_ok { default \"\"; \"https://app.example.com\" $http_origin; }\nadd_header Access-Control-Allow-Origin $cors_ok always;"),
    ("Django (django-cors-headers)", "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\nCORS_ALLOW_CREDENTIALS = True"),
)


def build_cors(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    check = text(evidence.get("check"), 60)
    url = text(evidence.get("url") or finding.get("url"), 400)
    origin = origin_of(url) or url
    path = text(evidence.get("path"), 300) or "/"
    sent = text(evidence.get("request_origin_header"), 300)
    allowed = text(evidence.get("access_control_allow_origin"), 300)
    credentials = evidence.get("access_control_allow_credentials") is True
    target = origin.rstrip("/") + (path if path.startswith("/") else "/" + path)
    curl = f"curl -sS -o /dev/null -D - -H {q('Origin: ' + (sent or 'https://evil.example'))} {q(target)} | grep -i '^access-control-allow-'"
    summaries = {
        "cors_reflected_origin": f"{origin} copies any Origin it receives into Access-Control-Allow-Origin" + (" and allows credentials" if credentials else "") + ".",
        "cors_null_origin": f"{origin} grants the null Origin" + (" with credentials" if credentials else "") + ", which any site can send from a sandboxed frame.",
        "cors_wildcard_credentials": f"{origin} answers Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
    }
    context = []
    if credentials and check != "cors_wildcard_credentials":
        context.append("With credentials allowed, a page on any other site can make the user's browser call this origin with their cookies and read the answer: whatever the user can see here, that site can read.")
    elif check != "cors_wildcard_credentials":
        context.append("Credentials are not allowed, so only what an anonymous request returns is readable; that still includes content reachable only from the user's network (intranet, VPN).")
    else:
        context.append("Browsers refuse this combination, so this response exposes nothing; it shows the CORS policy is not deliberate and should be replaced by an explicit allowlist.")
    return {
        "class": f"cors.{check.removeprefix('cors_')}",
        "class_label": text(finding.get("title"), 120) or "CORS misconfiguration",
        "summary": summaries.get(check, text(finding.get("title"))),
        "where": facts(fact("Origin", origin, mono=True), fact("Path requested", path, mono=True)),
        "observed": facts(
            fact("Origin sent", sent, mono=True),
            fact("Access-Control-Allow-Origin", allowed, mono=True),
            fact("Access-Control-Allow-Credentials", "true" if credentials else "not set / false", mono=True),
            fact("Response status", evidence.get("status"), mono=True),
        ),
        "expected": ["Access-Control-Allow-Origin only for an explicit allowlist of your own origins (never echoed, never null); credentials only for those origins."],
        "context": context,
        "reproduce": command(curl, expect=f"access-control-allow-origin: {allowed}"),
        "verify": command(curl, expect="no Access-Control-Allow-Origin line for an origin that is not on your allowlist"),
        "fix": [
            "Replace origin reflection with a fixed allowlist of the exact origins that need cross-origin access.",
            "Never allow the null origin; send Access-Control-Allow-Credentials: true only together with an allowlisted origin, and Vary: Origin.",
        ],
        "examples": [{"label": label, "code": code} for label, code in _CORS_EXAMPLES],
    }


def _probe_request_url(url: str, parameter: str, destination: str) -> str:
    """The URL the probe requested. The stored copy has every query value masked, the redirect
    parameter's too, but that one carried the scanner's own destination, which is no secret."""
    if not parameter or not destination:
        return url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if parameter not in {name for name, _value in pairs}:
        return url
    query = urllib.parse.urlencode([(name, destination if name == parameter else value) for name, value in pairs])
    return urllib.parse.urlunsplit(parts._replace(query=query))


def build_open_redirect(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    url = text(evidence.get("url") or finding.get("url"), 800)
    parameter = text(evidence.get("parameter"), 120)
    location = text(evidence.get("location"), 500)
    destination = text(evidence.get("probe_destination"), 200)
    _scheme, _host, _port, path = url_parts(url)
    origin = origin_of(url)
    curl = f"curl -sS -o /dev/null -D - {q(_probe_request_url(url, parameter, destination))} | grep -i '^location:'"
    return {
        "class": "redirect.open",
        "class_label": "Open redirect",
        "summary": f"{origin}{path} redirects to whatever URL the {parameter} parameter names: given {destination} it answered {evidence.get('status')} with Location: {location}.",
        "where": facts(fact("URL", display_url(url), mono=True), fact("Parameter", parameter, mono=True), fact("Method", "GET", mono=True)),
        "observed": facts(
            fact("Parameter value sent", destination, mono=True),
            fact("Response status", evidence.get("status"), mono=True),
            fact("Location returned", location, mono=True),
        ),
        "expected": ["A redirect only to a relative path or to an allowlisted host; anything else replaced by a safe default."],
        "context": [
            "Phishing links can start on your trusted domain and land on an attacker's page.",
            f"If {parameter} is used as an OAuth/SSO return address, an attacker can steal the authorization code or token it carries.",
            "The probe destination does not exist (.invalid is reserved and never resolves); the scanner did not follow the redirect.",
        ],
        "reproduce": command(curl, expect=f"location: {location}"),
        "verify": command(curl, expect="no Location header pointing outside your own hosts"),
        "fix": [
            f"Validate {parameter} on the server: accept only relative paths that start with a single '/' (reject '//' and '/\\'), or look the value up in an allowlist of hosts.",
            "Better still, pass an identifier (e.g. return=orders) and map it to a URL server-side.",
        ],
    }


_DNS_FIXES = {
    "spf_pass_all": ["Replace +all with -all (or ~all while you confirm every legitimate sender is listed)."],
    "spf_neutral_all": ["Replace ?all with -all (or ~all while rolling out)."],
    "spf_missing": ["Publish one TXT record: v=spf1 include:<your mail provider> -all; use v=spf1 -all if the domain sends no mail."],
    "spf_multiple_records": ["Merge the SPF records into one v=spf1 record; delete the others."],
    "spf_too_many_lookups": ["Flatten includes (replace them with the ip4:/ip6: ranges they resolve to) or remove unused senders until at most 10 lookups remain."],
    "dmarc_missing": ["Publish TXT _dmarc.<domain>: v=DMARC1; p=none; rua=mailto:<reports address>, review the reports, then move to p=quarantine and p=reject."],
    "dmarc_policy_none": ["Once reports show your legitimate mail passes, change p=none to p=quarantine, then p=reject."],
    "caa_missing": ["Publish CAA records for the CAs you use, e.g. <domain> CAA 0 issue \"letsencrypt.org\"."],
}


def build_dns(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    check = text(evidence.get("check"), 60)
    host = text(evidence.get("host"), 255)
    name = text(evidence.get("query_name"), 300) or host
    record_type = "CAA" if check.startswith("caa") else "TXT"
    observed_record = text(evidence.get("spf_record") or evidence.get("dmarc_record"), 600)
    observed_list = evidence.get("spf_records") if isinstance(evidence.get("spf_records"), list) else None
    dig = f"dig +short {record_type} {q(name)}"
    basis = evidence.get("severity_basis") if isinstance(evidence.get("severity_basis"), Mapping) else {}
    return {
        "class": f"dns.{check}",
        "class_label": text(finding.get("title"), 120),
        "summary": f"{name}: {text(basis.get('reason'), 400) or text(finding.get('title'))}",
        "where": facts(fact("Domain", host, mono=True), fact("Record queried", f"{record_type} {name}", mono=True)),
        "observed": facts(
            fact("Record as published", observed_record or (", ".join(str(item) for item in observed_list[:3]) if observed_list else "none"), mono=True),
            fact("DNS lookups counted", evidence.get("lookup_count")),
            fact("Counting", evidence.get("counted")),
            fact("Mail servers (MX)", evidence.get("mx_hosts"), mono=True),
        ),
        "expected": [text(evidence.get("expected"), 300)] if evidence.get("expected") else [],
        "context": ["Read from the DNS answers the scan recorded for the target's own names; no mail was sent."],
        "reproduce": command(dig, expect=observed_record or "no matching record"),
        "verify": command(dig, expect=text(evidence.get("expected"), 200)),
        "fix": list(_DNS_FIXES.get(check, [])),
    }


__all__ = ["build_cors", "build_dns", "build_open_redirect"]
