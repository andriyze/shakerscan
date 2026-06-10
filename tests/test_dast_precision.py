import asyncio
import importlib.util
import os
import sys


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from findings import apply_dast_precision_policy  # noqa: E402
from grading import grade  # noqa: E402
from reporting import _ai_rule_verdict, _generate_fallback_executive_summary  # noqa: E402
from scanner_tools import active_checks  # noqa: E402
from scanner_tools.finding_validator import apply_validation_to_finding, validate_finding, validate_sqli, validate_xss  # noqa: E402
from scanner_tools.tls_scanner import build_crypto_inventory  # noqa: E402

sys.path.pop(0)

SCANNER_MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner.py")
SCANNER_MAIN_SPEC = importlib.util.spec_from_file_location("scanner_main_for_tests", SCANNER_MAIN_PATH)
scanner_main = importlib.util.module_from_spec(SCANNER_MAIN_SPEC)
assert SCANNER_MAIN_SPEC and SCANNER_MAIN_SPEC.loader
SCANNER_MAIN_SPEC.loader.exec_module(scanner_main)
_refresh_ai_quality_metrics = scanner_main._refresh_ai_quality_metrics
apply_post_ai_precision_policy = scanner_main.apply_post_ai_precision_policy


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
    assert adjusted[0]["confidence"] == 0.49
    assert adjusted[0]["precision_policy"]["confidence_cap_reason"] == "missing_path_or_status"
    assert adjusted[1]["severity"] == "low"
    assert adjusted[1]["confidence"] == 0.49
    assert adjusted[2]["severity"] == "info"
    assert adjusted[2]["confidence"] == 0.34
    assert adjusted[2]["precision_policy"]["confidence_cap_reason"] == "vendor_or_framework_static_sink"
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


def test_cap_severity_preserves_earliest_original_across_chain():
    # Simulate a downgrade chain: critical → medium → low. The audit must keep
    # the first recorded severity (critical), not the intermediate one.
    from findings import _cap_severity

    finding = {"severity": "critical", "cvss_score": 9.8}

    _cap_severity(finding, "medium")
    _cap_severity(finding, "low")

    assert finding["severity"] == "low"
    assert finding["precision_policy"]["original_severity"] == "critical"
    assert finding["precision_policy"]["original_cvss_score"] == 9.8


def test_cap_severity_accepts_critical_target_without_keyerror():
    from findings import _cap_severity

    finding = {"severity": "high", "cvss_score": 7.5}

    # Should not raise even though `critical` was previously missing from the
    # cvss_score map.
    _cap_severity(finding, "critical")

    # `high` < `critical`, so nothing should change.
    assert finding["severity"] == "high"


def test_precision_policy_ai_true_positive_overrides_heuristic_downgrade():
    # A DOM XSS finding on a third-party CDN chunk would normally be capped to
    # info, but a high-confidence AI true_positive should override and verify.
    findings = [
        {
            "tool": "dom_xss",
            "title": "DOM XSS in vendor chunk",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.7,
            "evidence": {"file": "https://cdn.jsdelivr.net/npm/foo/x.js"},
            "ai_verdict": "true_positive",
            "ai_confidence": 0.9,
            "ai_classification_source": "provider",
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "high"
    assert adjusted[0]["confidence"] >= 0.9


def test_precision_policy_ai_false_positive_overrides_heuristic_verified():
    # Forced-browsing evidence marked verified by static heuristics, but the
    # AI judged it false_positive with high confidence — AI wins.
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Sensitive File: /admin",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.8,
            "verified": True,
            "evidence": {
                "url": "https://example.test/admin",
                "verified": True,
            },
            "ai_verdict": "false_positive",
            "ai_confidence": 0.92,
            "ai_classification_source": "provider",
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is False
    assert adjusted[0]["precision_policy"]["ai_overrode_verified"] is True
    assert adjusted[0]["precision_policy"]["confidence_cap_reason"] == "ai_false_positive"
    assert adjusted[0]["severity"] == "info"
    assert "AI judged false_positive" in adjusted[0]["verification_reason"]


def test_precision_policy_ai_false_positive_without_provenance_does_not_override_verified():
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Sensitive File: /admin",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.8,
            "verified": True,
            "evidence": {"url": "https://example.test/admin", "verified": True},
            "ai_verdict": "false_positive",
            "ai_confidence": 0.98,
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "high"


def test_precision_policy_ai_false_positive_does_not_override_poe():
    findings = [
        {
            "tool": "smart_sqli",
            "title": "SQL injection",
            "severity": "critical",
            "cvss_score": 9.8,
            "confidence": 0.95,
            "verified": True,
            "validation": {"poe_proven": True},
            "poe_result": {"proven": True},
            "ai_verdict": "false_positive",
            "ai_confidence": 0.98,
            "ai_classification_source": "provider",
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "critical"


def test_precision_policy_low_confidence_ai_verdict_ignored():
    # AI judged false_positive but only at 0.55 confidence — below trust
    # threshold, heuristics still rule.
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Sensitive File: /admin",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.8,
            "verified": True,
            "evidence": {"url": "https://example.test/admin", "verified": True},
            "ai_verdict": "false_positive",
            "ai_confidence": 0.55,
            "ai_classification_source": "provider",
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    # Low-confidence AI verdict does not override heuristic verified.
    assert adjusted[0]["verified"] is True


def test_precision_policy_syncs_validation_confidence_on_verified():
    findings = [
        {
            "tool": "smart_sqli",
            "title": "SQL Injection",
            "severity": "high",
            "cvss_score": 9.0,
            "confidence": 0.7,
            "verified": True,
            "validation": {"confidence": 0.75, "evidence_level": "strong_indicator"},
            "evidence": {"verified": True},
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["confidence"] >= 0.9
    assert adjusted[0]["validation"]["confidence"] == adjusted[0]["confidence"]


def test_precision_policy_does_not_auto_verify_forced_browsing_response_shape():
    # `content_validated` reflects response-shape filtering, not exploit proof.
    # Forced-browsing findings should remain unverified until POE or AI review
    # confirms the resource is actually sensitive.
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Sensitive File: /admin",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.8,
            "evidence": {
                "url": "https://example.test/admin",
                "path": "/admin",
                "status_code": 200,
                "content_type": "text/html",
                "content_validated": True,
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is False
    assert adjusted[0].get("validation", {}).get("evidence_level") != "confirmed_exploit"


def test_precision_policy_does_not_cap_verified_vendor_dom_xss():
    findings = [
        {
            "tool": "dom_xss",
            "title": "DOM-Based XSS with payload execution",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.7,
            "verified": True,
            "evidence": {
                "file": "https://cdn.jsdelivr.net/npm/example/widget.js",
                "verified": True,
                "payload_executed": True,
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "high"
    assert adjusted[0]["confidence"] >= 0.9
    assert "precision_policy" not in adjusted[0]


def test_precision_policy_keeps_dom_xss_on_target_app_bundle():
    findings = [
        {
            "tool": "dom_xss",
            "title": "DOM-Based XSS sink in app chunk",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.7,
            "evidence": {"file": "https://app.example.test/_next/static/chunks/03.js"},
        }
    ]

    adjusted = apply_dast_precision_policy(findings, target_host="app.example.test")

    assert adjusted[0]["precision_policy"]["confidence_cap_reason"] == "static_sink_without_execution"
    assert adjusted[0]["confidence"] == 0.49
    # Same-host framework chunk: not treated as vendor, but still capped to
    # "low" by the generic static-sink-without-execution threshold (0.49 < 0.50).
    assert adjusted[0]["severity"] == "low"


def test_precision_policy_caps_dom_xss_on_third_party_chunk_host():
    findings = [
        {
            "tool": "dom_xss",
            "title": "DOM-Based XSS sink in chunk on third-party host",
            "severity": "high",
            "cvss_score": 7.5,
            "confidence": 0.7,
            "evidence": {"file": "https://other.example.com/_next/static/chunks/03.js"},
        }
    ]

    adjusted = apply_dast_precision_policy(findings, target_host="app.example.test")

    assert adjusted[0]["precision_policy"]["confidence_cap_reason"] == "vendor_or_framework_static_sink"
    assert adjusted[0]["confidence"] == 0.34


def test_precision_policy_caps_2fa_rate_limit_lead_to_medium():
    findings = [
        {
            "tool": "2fa_bypass",
            "title": "2FA bypass possible via no_rate_limiting",
            "severity": "high",
            "cvss_score": 8.5,
            "confidence": 0.55,
            "evidence": {
                "method": "no_rate_limiting",
                "endpoint": "https://example.test/api/2fa/verify",
                "requests_sent": 10,
                "requests_processed": 10,
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["severity"] == "medium"
    assert adjusted[0]["confidence"] == 0.55
    assert adjusted[0]["needs_verification"] is True
    assert "not a confirmed 2FA bypass" in adjusted[0]["verification_reason"]


def test_precision_policy_accepts_graphql_verified_evidence_flag():
    findings = [
        {
            "tool": "graphql_vulnerability",
            "title": "GraphQL Vulnerability: introspection_enabled",
            "severity": "medium",
            "cvss_score": 5.0,
            "confidence": 0.85,
            "evidence": {
                "issue": "introspection_enabled",
                "verified": True,
                "evidence": [{"type": "introspection_enabled", "verified": True}],
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "medium"


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


def test_quick_public_scan_accepts_basic_tls_probe_for_completeness():
    report = _healthy_grade_report([])
    report["http"]["status"] = "HTTP/2 200"
    report["dns"]["a"] = ["203.0.113.10"]
    report["tls"]["sslyze"] = {"reason": "public_quick_mode", "skipped": True}
    report["tls"]["testssl"] = {"reason": "public_quick_mode", "skipped": True}
    report["tls"]["nmap"] = {"reason": "public_quick_mode", "skipped": True}
    report["tls"]["cipher_suites"] = {}

    coverage = scanner_main.assess_scan_completeness(
        report,
        public_only=True,
        quick_mode=True,
    )

    assert coverage["status"] == "complete"
    assert coverage["grade_reliable"] is True
    assert coverage["modules"]["tls"]["details"]["quick_public_tls"] is True
    assert coverage["issues"] == []


def test_non_quick_public_scan_does_not_accept_basic_tls_probe_only():
    report = _healthy_grade_report([])
    report["http"]["status"] = "HTTP/2 200"
    report["dns"]["a"] = ["203.0.113.10"]
    report["tls"]["sslyze"] = {"reason": "missing", "skipped": True}
    report["tls"]["testssl"] = {"reason": "missing", "skipped": True}
    report["tls"]["nmap"] = {"reason": "missing", "skipped": True}
    report["tls"]["cipher_suites"] = {}

    coverage = scanner_main.assess_scan_completeness(
        report,
        public_only=True,
        quick_mode=False,
    )

    assert coverage["status"] == "failed"
    assert coverage["grade_reliable"] is False
    assert coverage["modules"]["tls"]["details"]["basic_tls_probe"] is True
    assert coverage["modules"]["tls"]["details"]["quick_public_tls"] is False


def test_grade_only_discounts_trusted_ai_false_positives():
    base = {
        "tool": "dom_xss",
        "title": "DOM XSS static sink",
        "severity": "high",
        "cvss_score": 8.0,
        "confidence": 0.9,
        "ai_verdict": "false_positive",
        "ai_confidence": 0.98,
    }

    untrusted = grade(_healthy_grade_report([base]))
    trusted = grade(_healthy_grade_report([
        {**base, "ai_classification_source": "provider"}
    ]))

    assert untrusted["grade"] == "C"
    assert trusted["grade"] == "A"
    assert "likely FP" not in untrusted["summary"]
    assert "likely FP" in trusted["summary"]


def test_grade_does_not_discount_ai_false_positive_over_poe():
    finding = {
        "tool": "smart_sqli",
        "title": "SQL Injection",
        "severity": "critical",
        "cvss_score": 9.8,
        "confidence": 0.95,
        "validation": {"poe_proven": True},
        "poe_result": {"proven": True},
        "ai_verdict": "false_positive",
        "ai_confidence": 0.98,
        "ai_classification_source": "provider",
    }

    result = grade(_healthy_grade_report([finding]))

    assert result["grade"] in {"D", "F"}
    assert "likely FP" not in result["summary"]


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


def test_sqli_schema_extraction_indicator_is_verified():
    finding = {
        "tool": "smart_sqli",
        "title": "SQL Injection (None - schema_dump)",
        "severity": "high",
        "evidence": {
            "url": "https://example.test/api/search/",
            "type": "SQLi",
            "param": "keyword",
            "payload": "')) UNION SELECT sql,2,3 FROM sqlite_master--",
            "technique": "schema_dump",
            "evidence": ["Data extraction indicator: \\bsqlite_master\\b"],
        },
    }

    validation = validate_sqli(finding)

    assert validation.verified is True
    assert validation.confidence >= 0.95
    assert validation.evidence_level == "confirmed_exploit"


def test_sqli_extraction_proof_survives_validation_pipeline():
    finding = {
        "tool": "smart_sqli",
        "title": "SQL Injection (postgresql - boolean)",
        "severity": "critical",
        "cvss_score": 9.8,
        "confidence": 0.5,
        "verified": True,
        "proof_of_exploitation": True,
        "needs_verification": True,
        "suspected": True,
        "evidence": {
            "verified": True,
            "proof_of_exploitation": True,
            "extraction_evidence": ["Extracted sensitive rowset markers: password_hash, api_key"],
            "extracted_data": {"sensitive_markers": ["password_hash", "api_key"]},
        },
    }

    validation = validate_sqli(finding)
    updated = apply_validation_to_finding(finding, validation)
    adjusted = apply_dast_precision_policy([updated])[0]

    assert validation.verified is True
    assert validation.confidence >= 0.95
    assert adjusted["verified"] is True
    assert adjusted["confidence_tier"] == "verified"
    assert adjusted["needs_verification"] is False
    assert adjusted["suspected"] is False


def test_ai_rule_verdict_trusts_verified_exploitation_evidence():
    verdict, confidence, rationale = _ai_rule_verdict(
        {
            "tool": "smart_sqli",
            "title": "SQL Injection (postgresql - boolean)",
            "verified": True,
            "proof_of_exploitation": True,
            "evidence": {"proof_of_exploitation": True},
        },
        http_status="HTTP/2 200",
        target_host="honey.shakerscan.com",
    )

    assert verdict == "true_positive"
    assert confidence >= 0.95
    assert "verified exploitation evidence" in rationale


def test_ai_quality_metrics_refresh_after_ai_review():
    report = {
        "findings": [
            {"id": "f1", "ai_verdict": "true_positive"},
            {"id": "f2", "ai_verdict": "false_positive"},
        ],
        "quality_metrics": {
            "ai_validation": {
                "enabled": False,
                "verdicts": {"true_positive": 0, "false_positive": 0, "unclear": 0},
            },
            "reliability_notes": [],
        },
    }
    summary = {
        "classification_enabled": True,
        "used_provider": True,
        "provider_attempted": True,
        "provider_models_used": ["mock-model"],
        "provider_partial": True,
        "classification_source_counts": {"provider": 1, "heuristic_fallback": 1},
        "classification_min_severity": "medium",
        "classification_eligible_findings": 2,
        "classification_skipped_disabled": 0,
        "classification_skipped_by_min_severity": 3,
    }

    _refresh_ai_quality_metrics(report, summary)

    ai_quality = report["quality_metrics"]["ai_validation"]
    assert ai_quality["enabled"] is True
    assert ai_quality["used_provider"] is True
    assert ai_quality["provider_models_used"] == ["mock-model"]
    assert ai_quality["verdicts"] == {"true_positive": 1, "false_positive": 1, "unclear": 0}
    assert ai_quality["classification_source_counts"] == {"provider": 1, "heuristic_fallback": 1}
    assert "1 AI-eligible finding(s) used heuristic fallback classification" in report["quality_metrics"]["reliability_notes"]


def test_post_ai_precision_policy_applies_ai_false_positive_downgrade():
    report = _healthy_grade_report([
        {
            "id": "dom-xss-1",
            "tool": "dom_xss",
            "title": "DOM XSS static sink",
            "severity": "high",
            "confidence": 0.9,
            "cvss_score": 8.0,
            "evidence": {"verified": True, "file": "https://cdn.jsdelivr.net/lib.js"},
            "ai_verdict": "false_positive",
            "ai_confidence": 0.92,
            "ai_classification_source": "provider",
        }
    ])
    report["input"] = {"normalized_host": "app.example.test"}

    apply_post_ai_precision_policy(report)

    finding = report["findings"][0]
    assert finding["verified"] is False
    assert finding["severity"] == "info"
    assert finding["precision_policy"]["confidence_cap_reason"] == "ai_false_positive"
    assert finding["precision_policy"]["ai_overrode_reason"] == "ai_false_positive_high_confidence"


def test_focused_fallback_summary_uses_focused_remediation_only():
    report = {
        "input": {"normalized_host": "honey.shakerscan.com"},
        "result": {
            "score": 85,
            "grade": "D",
            "focused_active_scope": True,
            "remediation": [
                "Use parameterized queries/prepared statements for database access.",
                "Validate and type-check request parameters before using them in queries.",
            ],
        },
        "http": {"csp_evaluation": {"grade": "F"}, "security_headers": {}},
        "dns": {"dmarc": {"record": None}},
    }
    findings = [
        {
            "title": "SQL Injection (postgresql - boolean)",
            "severity": "critical",
            "verified": True,
            "confidence_tier": "verified",
        }
    ]

    summary = _generate_fallback_executive_summary(report, findings, 0, 0, 1)

    assert summary["confidence_summary"] == "1 confirmed finding(s), 0 likely false positives, 0 require verification."
    assert summary["recommendations"] == report["result"]["remediation"]
    assert all("DMARC" not in item and "Content Security Policy" not in item for item in summary["recommendations"])
    assert all("unclear" not in item for item in summary["next_steps"])


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


def test_append_bola_finding_preserves_evidence_and_triage():
    # Regression for the "enrichment silently dropped" class: the shared BOLA
    # report builder must carry the cross-user evidence AND the triage fields
    # (normalize_finding keeps neither on its own).
    report = {"findings": []}
    finding = {
        "title": "BOLA: Cross-user data access at /rest/basket/6",
        "severity": "high",
        "suspected": True,
        "needs_verification": True,
        "verification_reason": "two users received equivalent user-specific data",
        "confidence": 0.6,
        "evidence": {
            "url": "https://x.test/rest/basket/6",
            "responses_equivalent": True,
            "response_similarity": 1.0,
            "user_specific_signals": ["field:userid"],
        },
    }

    nf = scanner_main._append_bola_finding(
        report, finding, tool="smart_bola", default_title="BOLA/IDOR Vulnerability"
    )

    assert report["findings"] == [nf]
    # Triage classification preserved.
    assert nf["suspected"] is True
    assert nf["needs_verification"] is True
    assert nf["confidence"] == 0.6
    assert "equivalent" in nf["verification_reason"]
    # Cross-user evidence preserved through normalize_finding.
    ev = nf["evidence"]
    assert ev["response_similarity"] == 1.0
    assert ev["user_specific_signals"] == ["field:userid"]
    assert ev["responses_equivalent"] is True


def test_append_bola_finding_caps_response_snippet():
    report = {"findings": []}
    finding = {
        "title": "BOLA",
        "severity": "high",
        "evidence": {"response_snippet": "A" * 5000},
    }
    nf = scanner_main._append_bola_finding(
        report, finding, tool="bola_idor", default_title="BOLA", default_severity="critical"
    )
    assert len(nf["evidence"]["response_snippet"]) == 300


def test_append_bola_finding_uses_defaults_when_missing():
    report = {"findings": []}
    nf = scanner_main._append_bola_finding(
        report, {"evidence": {}}, tool="bola_idor",
        default_title="Broken Object Level Authorization", default_severity="critical",
    )
    assert nf["title"] == "Broken Object Level Authorization"
    # severity passes through normalize_finding's CVSS validation (which may
    # adjust an unsupported "critical" down) — just confirm it's a real band.
    assert nf["severity"] in {"critical", "high", "medium", "low", "info"}
    assert nf["tool"] == "bola_idor"
    # No triage fields leaked onto a bare finding.
    assert nf.get("suspected") is not True
    assert nf.get("needs_verification") is not True


def test_canonical_original_severity_set_on_precision_downgrade():
    # Consolidated audit: whichever pipeline downgrades, a single top-level
    # `original_severity` records the pre-downgrade severity.
    from findings import _cap_severity

    finding = {"severity": "critical", "cvss_score": 9.8}
    _cap_severity(finding, "low")
    assert finding["original_severity"] == "critical"
    # Structured per-pipeline audit still present alongside the canonical field.
    assert finding["precision_policy"]["original_severity"] == "critical"


def test_canonical_original_severity_not_set_without_downgrade():
    findings = [{
        "tool": "smart_sqli", "title": "SQLi", "severity": "high",
        "cvss_score": 9.0, "confidence": 0.7, "verified": True,
        "evidence": {"verified": True},
    }]
    adjusted = apply_dast_precision_policy(findings)
    # Verified finding, no downgrade -> no canonical original_severity recorded.
    assert "original_severity" not in adjusted[0]
