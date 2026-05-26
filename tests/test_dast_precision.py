import asyncio
import os
import sys


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from findings import apply_dast_precision_policy  # noqa: E402
from grading import grade  # noqa: E402
from scanner_tools import active_checks  # noqa: E402
from scanner_tools.tls_scanner import build_crypto_inventory  # noqa: E402

sys.path.pop(0)


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

    suspected_grade = grade({"findings": [suspected]})
    confirmed_grade = grade({"findings": [confirmed]})

    assert suspected_grade["score"] > confirmed_grade["score"]


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
