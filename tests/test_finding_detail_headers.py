"""Header and cookie finding pages: the detected stack, and copyable advice that matches what was seen.

Unit fixtures modelled on recorded scan evidence (a Tomcat connector's Server header, a session
cookie without flags).
"""

from __future__ import annotations

import json

import pytest

from api.finding_detail import build_finding_detail
from api.finding_detail.common import detected_stack


@pytest.mark.parametrize("server", ["Apache-Coyote/1.1", "fixture/1.0, Apache-Coyote/1.1", "Apache Tomcat/9.0.85"])
def test_tomcat_connector_is_not_apache_httpd(server):
    assert detected_stack({"server": server}) == "tomcat"


def test_apache_httpd_is_still_apache():
    assert detected_stack({"server": "Apache/2.4.58 (Ubuntu)"}) == "apache"


def test_weak_header_on_tomcat_leads_with_the_tomcat_example():
    brief = build_finding_detail({"tool": "http_baseline", "severity": "info", "url": "http://app.fixture.invalid/",
        "evidence": {"check": "weak_header_content-security-policy", "header": "content-security-policy",
                     "url": "http://app.fixture.invalid/", "observed_value": "default-src 'self' 'unsafe-inline'",
                     "observed_response": {"response_status": 200, "observed_headers": {
                         "server": "fixture/1.0, Apache-Coyote/1.1"}}}})
    assert brief["stack"] == "tomcat"
    assert brief["examples"][0]["label"] == "Tomcat / Spring"
    assert "Header always set" not in json.dumps(brief["examples"][0])


def _cookie(check):
    return build_finding_detail({"tool": "http_baseline", "severity": "low", "url": "https://app.fixture.invalid/",
        "evidence": {"check": check, "cookie_name": "sessionid", "url": "https://app.fixture.invalid/",
                     "cookie_flags": {"secure": False, "httponly": False, "samesite": None}}})


@pytest.mark.parametrize("check,missing,other", [
    ("session_cookie_missing_secure", "Secure", "HttpOnly"),
    ("session_cookie_missing_httponly", "HttpOnly", "Secure"),
])
def test_cookie_fix_names_the_missing_flag_once(check, missing, other):
    fix = _cookie(check)["fix"][0]
    assert fix.count(missing) == 1, fix
    assert other in fix and "SameSite=Lax" in fix and "sessionid" in fix


CSP_NONE = "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
CSP_PROSE = ("script-src 'self' with nonces or hashes; no *, scheme wildcards, 'unsafe-eval' or bare "
             "'unsafe-inline'; frame-ancestors 'self'")


def _weak(header, observed, expected, title="Weak header value"):
    return {"tool": "http_baseline", "severity": "info", "title": title, "url": "http://app.fixture.invalid/",
            "proof_state": "verified", "evidence": {
                "check": f"weak_header_{header}", "header": header, "url": "http://app.fixture.invalid/",
                "observed_value": observed, "expected_value": expected,
                "issues": [{"severity": "info", "code": "x", "text": "The value is weak."}],
                "observed_response": {"response_status": 200, "observed_headers": {"server": "nginx/1.25.3"}}}}


def test_weak_csp_check_expects_a_header_not_prose_and_keeps_the_stricter_framing():
    brief = build_finding_detail(_weak("content-security-policy", CSP_NONE, CSP_PROSE))
    assert "with nonces" not in brief["verify"]["expect"]
    assert "Content-Security-Policy" in brief["verify"]["expect"]
    pasted = json.dumps(brief["examples"]) + json.dumps(brief["fix"]) + json.dumps(brief["expected"])
    assert "frame-ancestors 'self'" not in pasted
    assert "frame-ancestors 'none'" in json.dumps(brief["examples"])


def test_weak_csp_without_framing_or_with_any_origin_framing_recommends_self():
    for observed in ("default-src *", "default-src 'self'; frame-ancestors *"):
        brief = build_finding_detail(_weak("content-security-policy", observed, CSP_PROSE))
        assert "frame-ancestors 'self'" in json.dumps(brief["examples"])


def test_a_hostile_framing_directive_is_not_copied_into_an_example():
    observed = "default-src *; frame-ancestors 'none'\" always; return 200 \"x"
    examples = json.dumps(build_finding_detail(_weak("content-security-policy", observed, CSP_PROSE))["examples"])
    assert "return 200" not in examples


@pytest.mark.parametrize("header,observed,expected", [
    ("x-frame-options", "ALLOW-FROM https://a.example", "DENY or SAMEORIGIN (or CSP frame-ancestors)"),
    ("referrer-policy", "unsafe-url", "strict-origin-when-cross-origin (or stricter)"),
])
def test_prose_expectations_are_not_presented_as_header_lines(header, observed, expected):
    brief = build_finding_detail(_weak(header, observed, expected))
    assert expected not in brief["verify"]["expect"]


def test_a_literal_expected_value_is_still_the_expected_header_line():
    brief = build_finding_detail(_weak("strict-transport-security", "max-age=60", "max-age=31536000; includeSubDomains"))
    assert brief["verify"]["expect"] == "Strict-Transport-Security: max-age=31536000; includeSubDomains"


def test_weak_csp_guidance_is_the_unsafe_sources_entry_not_the_missing_header_one():
    from scanner.scanner_tools.remediation_kb import match_remediation
    entry, matched_by = match_remediation(_weak("content-security-policy", CSP_NONE, CSP_PROSE,
                                                title="Weak Content-Security-Policy header value"))
    assert entry["title"] == "Content Security Policy Allows Unsafe Sources"
    assert matched_by == "finding_type"
