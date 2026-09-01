import asyncio
import importlib.util
import os
import sys
import types


SCANNER_DIR = os.path.join(os.path.dirname(__file__), "..", "scanner")
sys.path.insert(0, SCANNER_DIR)

from findings import apply_dast_precision_policy  # noqa: E402
from grading import grade  # noqa: E402
from reporting import _ai_rule_verdict, _generate_fallback_executive_summary  # noqa: E402
from scanner_tools import active_checks  # noqa: E402
from scanner_tools import nuclei as nuclei_module  # noqa: E402
from scanner_tools.finding_validator import apply_validation_to_finding, validate_finding, validate_sqli, validate_ssrf, validate_xss  # noqa: E402
from scanner_tools.tls_scanner import build_crypto_inventory  # noqa: E402

SCANNER_MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner.py")
SCANNER_MAIN_SPEC = importlib.util.spec_from_file_location("scanner_main_for_tests", SCANNER_MAIN_PATH)
scanner_main = importlib.util.module_from_spec(SCANNER_MAIN_SPEC)
assert SCANNER_MAIN_SPEC and SCANNER_MAIN_SPEC.loader
SCANNER_MAIN_SPEC.loader.exec_module(scanner_main)
sys.path.pop(0)
_refresh_ai_quality_metrics = scanner_main._refresh_ai_quality_metrics
apply_post_ai_precision_policy = scanner_main.apply_post_ai_precision_policy


def test_scanner_unraisablehook_filters_asyncio_subprocess_shutdown_noise():
    noisy = types.SimpleNamespace(
        exc_value=RuntimeError("Event loop is closed"),
        object="<function BaseSubprocessTransport.__del__ at 0xabc>",
    )
    real_error = types.SimpleNamespace(
        exc_value=RuntimeError("different failure"),
        object="<function BaseSubprocessTransport.__del__ at 0xabc>",
    )

    assert scanner_main._is_asyncio_subprocess_shutdown_unraisable(noisy) is True
    assert scanner_main._is_asyncio_subprocess_shutdown_unraisable(real_error) is False


def test_nuclei_wave_does_not_inflate_coverage_when_process_times_out(monkeypatch):
    async def fake_run(cmd, timeout=60):
        return "", "timeout after 1s", 124

    monkeypatch.setattr(nuclei_module, "run", fake_run)
    monkeypatch.setattr(nuclei_module.os.path, "isdir", lambda path: True)

    result = asyncio.run(
        nuclei_module._run_nuclei_wave("https://example.com", ["cve", "rce", "takeover"], timeout=1)
    )

    assert result["scan_completed"] is False
    assert result["templates_executed"] == 0
    assert "templates_executed_estimated" not in result


def test_nuclei_wave_estimates_only_successful_no_stats_run(monkeypatch):
    async def fake_run(cmd, timeout=60):
        return "", "", 0

    monkeypatch.setattr(nuclei_module, "run", fake_run)
    monkeypatch.setattr(nuclei_module.os.path, "isdir", lambda path: True)

    result = asyncio.run(
        nuclei_module._run_nuclei_wave("https://example.com", ["cve", "rce"], timeout=1)
    )

    assert result["scan_completed"] is True
    assert result["templates_executed"] == 2
    assert result["templates_executed_estimated"] is True


def test_nuclei_wave_reports_enforced_budget_block_without_fake_coverage(monkeypatch):
    async def fake_run(cmd, timeout=60):
        return "", "unmetered network tool is disabled by the request budget", 75

    monkeypatch.setattr(nuclei_module, "run", fake_run)
    monkeypatch.setattr(nuclei_module.os.path, "isdir", lambda path: True)

    result = asyncio.run(
        nuclei_module._run_nuclei_wave("https://example.com", ["cve", "rce"], timeout=1)
    )

    assert result["scan_completed"] is False
    assert result["blocked_by_request_budget"] is True
    assert result["templates_executed"] == 0
    assert "enforced request budget" in result["error"]


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


def test_precision_policy_accepts_typed_deterministic_proof():
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
                "proof_of_exploitation": True,
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["validation"]["evidence_level"] == "confirmed_exploit"
    assert adjusted[0]["severity"] == "high"


def test_precision_policy_rejects_generic_verified_evidence_flag():
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

    assert adjusted[0]["verified"] is False
    assert adjusted[0]["suspected"] is True
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[0]["precision_policy"]["generic_verified_ignored"] is True


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


def test_precision_policy_ai_true_positive_is_likely_not_verified():
    # docs §8: AI never promotes to `verified`. A high-confidence AI true_positive
    # keeps the finding visible at its severity as a `likely_vulnerable` SUSPECTED
    # lead, but it is NOT deterministically verified.
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

    assert adjusted[0]["verified"] is False  # AI never promotes to verified
    assert adjusted[0]["proof_state"] == "likely_vulnerable"
    assert adjusted[0]["suspected"] is True
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[0]["precision_policy"]["ai_supported_likely"] is True
    # Registry severity rules prevent an unexecuted XSS lead from remaining High.
    assert adjusted[0]["severity"] == "medium"
    assert adjusted[0]["registry_contract"]["contract_satisfied"] is False


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
    assert adjusted[0]["precision_policy"]["generic_verified_ignored"] is True
    assert "ai_overrode_verified" not in adjusted[0]["precision_policy"]
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

    assert adjusted[0]["verified"] is False
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[0]["precision_policy"]["generic_verified_ignored"] is True
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
            "evidence": {
                "url": "https://example.test/search",
                "method": "GET",
                "param": "q",
                "payload": "' OR 1=1--",
                "response_delta": {"control": 200, "payload": 500},
            },
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

    # Low-confidence AI verdict does not add a downgrade, but the generic
    # verified flag still does not become deterministic proof.
    assert adjusted[0]["verified"] is False
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[0]["precision_policy"]["generic_verified_ignored"] is True


def test_precision_policy_syncs_validation_confidence_on_verified():
    findings = [
        {
            "tool": "smart_sqli",
            "title": "SQL Injection",
            "severity": "high",
            "cvss_score": 9.0,
            "confidence": 0.7,
            "verified": True,
            "validation": {"verified": True, "confidence": 0.75, "evidence_level": "confirmed_exploit"},
            "evidence": {
                "verified": True,
                "url": "https://example.test/search",
                "method": "GET",
                "param": "q",
                "payload": "' OR 1=1--",
                "response_delta": {"control": 200, "payload": 500},
            },
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


def test_precision_policy_does_not_treat_metric_names_as_exploitation_proof():
    findings = [
        {
            "tool": "forced_browsing",
            "title": "Accessible Debug/Development Endpoint",
            "severity": "high",
            "cvss_score": 7.5,
            "evidence": {
                "url": "https://example.test/observability",
                "status_code": 200,
                "signal_type": "sensitive_metric_names_exposed",
                "proof_state": "observed",
                "sensitive_metric_categories": ["commerce", "identity"],
                "sensitive_metric_names": [
                    "service_users_registered",
                    "service_orders_placed_total",
                    "service_wallet_balance_total",
                ],
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is False
    assert adjusted[0]["severity"] == "medium"
    assert adjusted[0]["needs_verification"] is True
    assert adjusted[0]["proof_state"] != "exploited"


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
                "browser_proof": {
                    "proof_producer": "shakerscan",
                    "proven": True,
                    "evidence_type": "dom_execution",
                    "technique": "headless_xss_dialog",
                },
                "payload": "<svg onload=alert(1)>",
            },
        }
    ]

    adjusted = apply_dast_precision_policy(findings)

    assert adjusted[0]["verified"] is True
    assert adjusted[0]["severity"] == "high"
    assert adjusted[0]["confidence"] >= 0.9
    assert "precision_policy" not in adjusted[0]


def test_registry_contract_rejects_generic_sqli_poe_without_request_proof():
    finding = {
        "tool": "smart_sqli",
        "title": "SQL injection",
        "severity": "critical",
        "cvss_score": 9.8,
        "confidence": 0.95,
        "proof_of_exploitation": True,
    }

    adjusted = apply_dast_precision_policy([finding])[0]

    assert adjusted["verified"] is False
    assert adjusted["severity"] == "medium"
    assert adjusted["proof_state"] == "likely_vulnerable"
    assert set(adjusted["registry_contract"]["proof_fields_missing"]) == {
        "method", "url", "parameter", "payload", "response_delta",
    }


def test_registry_contract_accepts_complete_sqli_runtime_proof():
    finding = {
        "tool": "smart_sqli",
        "title": "SQL injection",
        "severity": "critical",
        "cvss_score": 9.8,
        "confidence": 0.95,
        "proof_type": "repeated_semantic_response_diff",
        "evidence": {
            "url": "https://example.test/search",
            "method": "GET",
            "param": "q",
            "payload": "' OR 1=1--",
            "response_delta": {"control": 200, "payload": 500},
        },
    }

    adjusted = apply_dast_precision_policy([finding])[0]

    assert adjusted["verified"] is True
    assert adjusted["severity"] == "critical"
    assert adjusted["registry_contract"]["contract_satisfied"] is True
    assert adjusted["proof_contract_v2"]["schema_version"] == "proof-contract/v2"


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
                "proof_type": "data_extraction",
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
        "proof_of_exploitation": True,
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

    assert result["original_grade"] in {"A", "B"}
    assert result["grade"] in {"A*", "B*"}
    assert result["grade_reliable"] is False
    assert result["suspected_high_critical_count"] == 1


def test_grade_is_reliable_when_high_finding_has_deterministic_proof():
    confirmed = {
        "tool": "smart_sqli",
        "title": "Confirmed SQL injection",
        "severity": "high",
        "cvss_score": 8.8,
        "proof_type": "data_extraction",
    }

    result = grade(_healthy_grade_report([confirmed]))

    assert result["grade"].endswith("*") is False
    assert result["grade_reliable"] is True
    assert result["suspected_high_critical_count"] == 0


def test_grade_does_not_full_weight_generic_verified_without_proof():
    generic_verified = {
        "tool": "legacy_probe",
        "title": "Legacy verified high",
        "severity": "high",
        "cvss_score": 7.5,
        "confidence": 0.6,
        "verified": True,
    }
    proven = {
        **generic_verified,
        "proof_of_exploitation": True,
    }

    generic_grade = grade(_healthy_grade_report([generic_verified]))
    proven_grade = grade(_healthy_grade_report([proven]))

    assert generic_grade["score"] > proven_grade["score"]


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


def test_quick_scan_does_not_expect_nuclei_for_completeness():
    report = _healthy_grade_report([])
    report["http"]["status"] = "HTTP/2 200"
    report["dns"]["a"] = ["203.0.113.10"]
    report["tls"]["nmap"] = {"scan_completed": True}
    report["discovery"] = {
        "nuclei": {"scan_completed": False, "templates_used": 0, "skipped": True}
    }

    coverage = scanner_main.assess_scan_completeness(
        report,
        public_only=False,
        quick_mode=True,
    )

    assert coverage["status"] == "complete"
    assert coverage["grade_reliable"] is True
    assert "nuclei" not in coverage["modules"]
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

    assert untrusted["grade"] == "B*"
    assert untrusted["score"] < trusted["score"]
    assert untrusted["grade_reliable"] is False
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


def test_failed_browser_proof_is_not_trusted_as_verified_xss():
    # A FAILED browser proof attempt (proven=false) must NOT be treated as
    # confirmed XSS — otherwise a low-confidence non-execution blob becomes a
    # trusted high-confidence finding.
    finding = {
        "tool": "hash_route_dom_xss",
        "title": "DOM XSS in Hash Route",
        "severity": "high",
        "cvss_score": 7.4,
        "browser_proof": {"proven": False, "confidence": 0.2},
        "evidence": {"payload": "<img src=x onerror=alert(1)>"},
    }
    validation = validate_xss(finding, response_body="<html>no execution here</html>")
    assert validation.verified is False
    assert validation.evidence_level != "confirmed_exploit"


def test_proven_browser_proof_is_trusted_as_verified_xss():
    # The positive case still works: a proven dialog-fired DOM XSS is confirmed
    # even though its payload never appears in the server response (client-side).
    finding = {
        "tool": "hash_route_dom_xss",
        "title": "DOM XSS in Hash Route",
        "severity": "high",
        "cvss_score": 7.4,
        "browser_proof": {
            "proof_producer": "shakerscan",
            "proven": True,
            "evidence_type": "dom_execution",
            "technique": "headless_xss_dialog",
            "confidence": 0.99,
        },
        "poe_result": {"proven": True, "confidence": 0.99},
        "evidence": {"payload": "<img src=x onerror=alert(1)>"},
    }
    validation = validate_xss(finding, response_body="<html>search results</html>")
    assert validation.verified is True
    assert getattr(validation, "downgrade_to", None) is None


def test_negative_browser_execution_prose_never_promotes_xss():
    for detail in ("no execution proof available", "payload executed: false"):
        finding = {
            "tool": "dom_xss",
            "title": "DOM XSS",
            "severity": "high",
            "evidence": {"payload": "<svg onload=alert(1)>", "detail": detail},
        }
        validation = validate_xss(finding, response_body="<html>safe</html>")
        adjusted = apply_dast_precision_policy([finding])[0]
        assert validation.verified is False
        assert adjusted["verified"] is False
        assert adjusted.get("proof_state") != "exploited"


def test_nonverified_dalfox_result_remains_a_candidate():
    finding = {
        "tool": "dalfox",
        "title": "Reflected XSS candidate",
        "severity": "high",
        "evidence": {
            "payload": "<img src=x onerror=alert(1)>",
            "detail": {"type": "Not Verified", "message": "reflection only"},
        },
    }

    validation = validate_xss(finding, response_body=None)

    assert validation.verified is False
    assert validation.evidence_level == "strong_indicator"


def test_dalfox_requires_explicit_verified_parser_field():
    finding = {
        "tool": "dalfox",
        "title": "Reflected XSS",
        "severity": "high",
        "evidence": {
            "payload": "<img src=x onerror=alert(1)>",
            "detail": {"verified": True},
        },
    }

    assert validate_xss(finding, response_body=None).verified is True


def test_possible_ssrf_network_error_is_not_verified():
    validation = validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"target": "http://169.254.169.254/"}},
        response_body="connect: connection refused",
    )

    assert validation.verified is False
    assert validation.evidence_level == "strong_indicator"


def test_ssrf_target_string_without_callback_or_content_is_not_verified():
    validation = validate_ssrf({
        "tool": "ssrf_probe",
        "evidence": {"payload": "http://169.254.169.254/latest/meta-data/"},
    })

    assert validation.verified is False


def test_ssrf_verifies_structured_cloud_metadata_without_trusting_reflected_hosts():
    # Each verified case pairs the internal-content response with a causal
    # request whose payload actually targeted a metadata endpoint.
    causal_cases = [
        (
            {"tool": "ssrf_probe", "evidence": {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}},
            '''{\n  "Code": "Success",\n  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}''',
        ),
        (
            {"tool": "ssrf_probe", "evidence": {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}},
            '{"access_token":"ya29.a0AfH6SM-example-token","expires_in":3599,"token_type":"Bearer"}',
        ),
        (
            {"tool": "ssrf_probe", "evidence": {"payload": "http://169.254.169.254/metadata/identity/oauth2/token"}},
            '{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.example-token","expires_in":"3599"}',
        ),
        (
            {"tool": "ssrf_probe", "evidence": {"payload": "http://169.254.169.254/latest/meta-data/"}},
            "ami-id\nami-launch-index\ninstance-id\niam/\n",
        ),
    ]
    for finding, body in causal_cases:
        assert validate_ssrf(finding, body).verified is True

    # Reflected metadata hostname in the response (no metadata-targeting payload)
    # stays unverified, and so does creds-shaped content without a causal link.
    assert validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {}},
        "requested http://metadata.google.internal/computeMetadata/v1/",
    ).verified is False

    non_causal = validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "http://example.com/fetch"}},
        '''{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}''',
    )
    assert non_causal.verified is False
    assert non_causal.evidence_level == "strong_indicator"


def test_ssrf_content_match_requires_causal_metadata_payload():
    creds_body = '''{
  "Code": "Success",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}'''

    # (a) payload targets the AWS metadata endpoint + creds JSON -> verified
    verified = validate_ssrf(
        {
            "tool": "ssrf_probe",
            "evidence": {
                "url": "https://app.example.test/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "param": "url",
                "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            },
        },
        creds_body,
    )
    assert verified.verified is True
    assert verified.evidence_level == "confirmed_exploit"

    # (b) ordinary-URL payload + creds-shaped response -> suspected, not verified
    suspected = validate_ssrf(
        {
            "tool": "ssrf_probe",
            "evidence": {
                "url": "https://app.example.test/proxy?url=http://example.com/feed",
                "param": "url",
                "payload": "http://example.com/feed",
            },
        },
        creds_body,
    )
    assert suspected.verified is False
    assert suspected.evidence_level == "strong_indicator"
    assert 0.55 <= suspected.confidence <= 0.65


def test_ssrf_directory_listing_requires_causal_metadata_payload():
    listing_body = "ami-id\nami-launch-index\ninstance-id\niam/\n"

    # (c) payload targets metadata + 3-marker directory listing -> verified
    verified = validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "http://169.254.169.254/latest/meta-data/"}},
        listing_body,
    )
    assert verified.verified is True

    # (d) same listing but the request targeted a normal URL -> suspected
    suspected = validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "http://example.com/feed"}},
        listing_body,
    )
    assert suspected.verified is False
    assert suspected.evidence_level == "strong_indicator"


def test_ssrf_causality_accepts_local_file_private_network_and_encoded_metadata_targets():
    passwd = "root:x:0:0:root:/root:/bin/bash\n"
    assert validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "file:///etc/passwd"}},
        passwd,
    ).verified is True
    assert validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "http://10.0.0.5/admin"}},
        passwd,
    ).verified is True

    creds = (
        '{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
    )
    encoded = "http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F"
    assert validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": encoded}},
        creds,
    ).verified is True


def test_cloud_metadata_signature_does_not_promote_for_an_unrelated_private_target():
    creds = (
        '{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
    )
    result = validate_ssrf(
        {"tool": "ssrf_probe", "evidence": {"payload": "http://10.0.0.5/admin"}},
        creds,
    )
    assert result.verified is False
    assert result.evidence_level == "strong_indicator"

    lookalike = validate_ssrf(
        {
            "tool": "ssrf_probe",
            "evidence": {"payload": "https://metadata.google.internal.attacker.example/creds"},
        },
        creds,
    )
    assert lookalike.verified is False


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
                "url": "https://example.test/search",
                "method": "GET",
                "param": "q",
                "payload": "' UNION SELECT password_hash,api_key FROM users--",
                "response_delta": {"control": 200, "payload": 200, "extracted_rows": 1},
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


def test_ai_rule_verdict_does_not_trust_generic_verified_flags_as_proof():
    verdict, confidence, rationale = _ai_rule_verdict(
        {
            "tool": "custom_probe",
            "title": "Potential issue",
            "verified": True,
            "evidence": {"verified": True},
            "validation": {"verified": True, "confidence": 0.9},
        },
        http_status="HTTP/2 200",
        target_host="honey.shakerscan.com",
    )

    assert verdict == "unclear"
    assert confidence == 0.5
    assert "verified exploitation evidence" not in rationale


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
    assert finding["precision_policy"]["generic_verified_ignored"] is True
    assert "ai_overrode_reason" not in finding["precision_policy"]


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


def test_smart_authz_cross_principal_replay_is_verified():
    finding = {
        "tool": "smart_authz",
        "title": "Broken object authorization: user2 can access user1 object",
        "severity": "high",
        "cvss_score": 8.0,
        "evidence": {
            "url": "https://example.test/workshop/api/shop/orders/15",
            "proof_type": "cross_principal_replay",
            "owner_status": 200,
            "attacker_status": 200,
            "responses_equivalent": True,
            "object_id_absent_from_attacker_listing": True,
            "authz_diff": {
                "replayed_owner_object_missing_from_attacker_listing": True,
                "owner_resource_equivalent_to_attacker_resource": True,
            },
            "producer_endpoint": "GET /workshop/api/shop/orders/all",
            "consumer_endpoint": "GET /workshop/api/shop/orders/15",
        },
    }

    validation = validate_finding(finding)
    updated = apply_validation_to_finding(finding, validation)

    assert validation.verified is True
    assert validation.confidence == 0.95
    assert validation.evidence_level == "confirmed_exploit"
    assert updated["verified"] is True
    assert updated["needs_verification"] is False
    assert updated["confidence_tier"] == "verified"


def test_precision_policy_caps_unverified_smart_bola_lead_below_high():
    finding = {
        "tool": "smart_bola",
        "title": (
            "BOLA: Cross-user data access at "
            "https://example.test/identity/api/v2/user/dashboard?id={id}"
        ),
        "severity": "high",
        "cvss_score": 8.0,
        "confidence": 0.5,
        "suspected": True,
        "needs_verification": True,
        "validation": {
            "verified": False,
            "confidence": 0.5,
            "evidence_level": "weak_indicator",
            "reason": "IDOR pattern detected but not confirmed",
        },
        "evidence": {
            "url": "https://example.test/identity/api/v2/user/dashboard?id=9999",
            "responses_equivalent": True,
            "response_similarity": 0.969,
            "user_specific_signals": ["field:email"],
        },
    }

    adjusted = apply_dast_precision_policy([finding])[0]

    assert adjusted["severity"] == "medium"
    assert adjusted["cvss_score"] <= 6.0
    assert adjusted["verified"] is False
    assert adjusted["needs_verification"] is True
    assert adjusted["suspected"] is True
    assert adjusted["confidence_tier"] == "low"
    assert adjusted["precision_policy"]["confidence_cap_reason"] == "bola_lead_without_cross_principal_proof"


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
