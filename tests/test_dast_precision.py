import asyncio
import os
import sys


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from findings import apply_dast_precision_policy  # noqa: E402
from grading import grade  # noqa: E402
from scanner_tools import active_checks  # noqa: E402
from scanner_tools.finding_validator import apply_validation_to_finding, validate_finding, validate_sqli, validate_xss  # noqa: E402
from scanner_tools.tls_scanner import build_crypto_inventory  # noqa: E402

sys.path.pop(0)


def _healthy_grade_report(findings):
    return {
        "tls": {
            "endpoints": [{"tlsversion": "TLSv1.3"}],
            "certificate": {"not_after": "2099-01-01T00:00:00+00:00"},
            "ocsp": {"stapled": True},
        },
        "http": {
            "security_headers": {
                "hsts": "max-age=31536000; includeSubDomains; preload",
                "x_frame_options": "DENY",
                "x_content_type_options": "nosniff",
                "referrer_policy": "no-referrer",
            },
            "csp_evaluation": {
                "present": True,
                "score": 100,
                "directives": {"default-src": ["'self'"], "script-src": ["'self'"]},
            },
            "cookies": {"issues": []},
            "http2": True,
        },
        "dns": {"mx": [], "spf": True, "dmarc": {"fields": {"p": "reject"}}},
        "findings": findings,
    }


def test_ecdhe_rsa_is_not_static_rsa_key_exchange():
    tls = {
        "endpoints": [{"tlsversion": "tls13", "cipher": "TLS_AES_128_GCM_SHA256"}],
        "cipher_suites": {
            "TLSv1.2": [
                {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
                {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
            ],
            "TLSv1.3": [{"name": "TLS_AKE_WITH_AES_128_GCM_SHA256"}],
        },
    }

    inventory = build_crypto_inventory(tls, "gap-analytics.com", 443)

    assert inventory["algorithms"]["static_rsa_key_exchange"] is False
    assert "static_rsa_key_exchange" not in inventory["issues"]
    assert "static_rsa_key_exchange" not in inventory["pqc_readiness"]["blockers"]


def test_precision_policy_downgrades_gap_analytics_style_leads():
    findings = [
        {
            "tool": "bfla",
            "title": "Broken Function Level Authorization: None accessible",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.6,
            "evidence": {"url": "https://gap-analytics.com/admin", "path": None, "status_code": None},
        },
        {
            "tool": "client_side",
            "title": "Potential prototype pollution sink (2 occurrences)",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.6,
            "evidence": {
                "file": "https://gap-analytics.com/_next/static/chunks/03.js",
                "type": "prototype_pollution_sink",
            },
        },
        {
            "tool": "dom_xss",
            "title": "DOM-Based XSS (Function constructor)",
            "severity": "medium",
            "cvss_score": 6.1,
            "confidence": 0.7,
            "evidence": {"file": "https://clerk.gap-analytics.com/npm/@clerk/clerk-js/dist/clerk.browser.js"},
        },
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["severity"] == "low"
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[1]["severity"] == "low"
    assert adjusted[2]["severity"] == "info"
    assert all(item["suspected"] is True for item in adjusted)


def test_precision_policy_accepts_verified_evidence_flag():
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Sensitive File: /.env",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.8,
            "evidence": {
                "url": "https://example.test/.env",
                "path": "/.env",
                "status_code": 200,
                "content_type": "text/plain",
                "verified": True,
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["validation"]["evidence_level"] == "confirmed_exploit"
    assert adjusted[0]["severity"] == "high"


def test_grade_discounts_unverified_suspected_high_findings():
    suspected = {
        "tool": "bfla",
        "title": "Broken Function Level Authorization",
        "severity": "high",
        "cvss_score": 7.5,
        "confidence": 0.55,
        "suspected": True,
        "needs_verification": True,
    }
    confirmed = {
        "tool": "bfla",
        "title": "Broken Function Level Authorization",
        "severity": "high",
        "cvss_score": 7.5,
        "confidence": 0.9,
        "verified": True,
    }

    suspected_grade = grade(_healthy_grade_report([suspected]))
    confirmed_grade = grade(_healthy_grade_report([confirmed]))

    assert suspected_grade["score"] > confirmed_grade["score"]


def test_grade_ceiling_ignores_unverified_suspected_high_findings():
    suspected = {
        "tool": "bfla",
        "title": "Broken Function Level Authorization",
        "severity": "high",
        "cvss_score": 7.5,
        "confidence": 0.55,
        "suspected": True,
        "needs_verification": True,
    }

    result = grade(_healthy_grade_report([suspected]))

    assert result["grade"] in {"A", "B"}


def test_xss_payload_without_response_is_not_verified():
    finding = {
        "tool": "active_xss",
        "title": "Reflected XSS",
        "severity": "high",
        "cvss_score": 7.5,
        "evidence": {"payload": "<script>alert(1)</script>"},
    }

    validation = validate_xss(finding, response_body=None)
    updated = apply_validation_to_finding(finding, validation)

    assert validation.verified is False
    assert updated["verified"] is False
    assert updated["needs_verification"] is True
    assert updated["severity"] == "medium"


def test_sqli_error_indicator_is_strong_but_not_verified():
    finding = {
        "tool": "active_sqli",
        "title": "SQL injection",
        "severity": "high",
        "cvss_score": 7.5,
        "evidence": {},
    }

    validation = validate_sqli(finding, response_body="syntax error near SQL statement")

    assert validation.verified is False
    assert validation.confidence == 0.75
    assert validation.evidence_level == "strong_indicator"


def test_deterministic_hygiene_finding_is_not_suspected_lead():
    finding = {
        "tool": "csp_evaluator",
        "title": "CSP header missing",
        "severity": "medium",
        "cvss_score": 4.0,
        "evidence": {"present": False, "reproduction": "curl -sIL https://example.test/"},
    }

    validation = validate_finding(finding)
    updated = apply_validation_to_finding(finding, validation)

    assert validation.verified is False
    assert validation.evidence_level == "hygiene"
    assert validation.confidence == 0.85
    assert updated["verified"] is False
    assert updated.get("needs_verification") is not True
    assert updated.get("suspected") is not True
    assert updated["confidence_tier"] == "high"


def test_ssti_ignores_generic_next_html_shell_with_incidental_49(monkeypatch):
    async def fake_run(cmd, timeout=10):
        url = cmd[-1]
        html = (
            '<!DOCTYPE html><html><head><script src="/_next/static/chunks/app.js"></script></head>'
            "<body>Build 49 Checking admin access...</body></html>"
        )
        if "ssti_baseline" in url or "%7B%7B7%2A7%7D%7D" in url:
            return html, "", 0
        return html, "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(
        active_checks.ssti_test(
            "https://gap-analytics.com/api/user/?id=1",
            params_to_test=["id"],
            max_payloads=1,
        )
    )

    assert result["vulnerable"] is False
    assert result["evidence"] == []
