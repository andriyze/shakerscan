from scanner.grading import grade
from scanner.reporting import emit_config_findings
from scanner.target_context import is_local_or_private_scan_target


def _local_posture_report() -> dict:
    return {
        "input": {
            "target": "http://host.docker.internal:3001",
            "normalized_host": "host.docker.internal",
            "port": 3001,
            "scheme": "http",
        },
        "http": {
            "final_url": "http://host.docker.internal:3001/",
            "security_headers": {
                "x_frame_options": "SAMEORIGIN",
                "x_content_type_options": "nosniff",
            },
            "csp_evaluation": {"present": False, "issues": ["CSP header missing."]},
            "cookies": {"details": [], "issues": []},
            "scheme_redirect": "none",
            "http2": False,
            "http3": None,
        },
        "tls": {
            "endpoints": [],
            "certificate": {},
            "ocsp": {"stapled": False},
            "sslyze": {"tls_versions": {}, "ocsp_stapling": False},
            "testssl": {"issues": [], "supports_tls13": None},
            "nmap": {"weak_indicators": []},
        },
        "dns": {
            "mx": [],
            "spf": None,
            "dmarc": {"fields": {}, "record": None},
            "dnssec": {"status": "timeout"},
            "caa": {"records": []},
            "mta_sts": {},
            "tls_rpt": {},
        },
        "discovery": {},
        "findings": [],
    }


def test_local_target_context_classifies_lab_hosts():
    assert is_local_or_private_scan_target("http://localhost:3000")
    assert is_local_or_private_scan_target("host.docker.internal")
    assert is_local_or_private_scan_target("http://127.0.0.1:8080")
    assert is_local_or_private_scan_target("http://10.0.0.10")
    assert not is_local_or_private_scan_target("https://honey.shakerscan.com")


def test_corporate_dot_local_is_not_classified_as_local():
    # `.local` is widely used by corporate AD networks for internal hosts
    # behind public PKI; we should not blanket-suppress posture for them.
    assert not is_local_or_private_scan_target("https://intranet.corp.local")
    assert not is_local_or_private_scan_target("https://wiki.example.local")


def test_local_targets_suppress_public_posture_findings_but_keep_app_headers():
    report = _local_posture_report()

    emit_config_findings(report)

    findings = report["findings"]
    tools = {finding["tool"] for finding in findings}
    titles = {finding["title"] for finding in findings}

    assert report["target_context"]["local_or_private_scan_target"] is True
    assert "tls_config" not in tools
    assert "dns_policy" not in tools
    assert "redirect_check" not in tools
    assert "HSTS header missing" not in titles
    assert "csp_evaluator" in tools
    assert "Referrer-Policy missing" in titles


def test_local_targets_do_not_grade_public_delivery_controls():
    result = grade(_local_posture_report())

    notes = "\n".join(result["notes"])
    assert "Local/private target detected" in notes
    assert "Modern TLS" not in notes
    assert "OCSP stapling" not in notes
    assert "HSTS missing" not in notes
    assert "SPF missing" not in notes
    assert "DMARC missing" not in notes
    assert "DNSSEC not validated" not in notes
    assert "Does not redirect to HTTPS" not in notes
    assert "No HTTP/2" not in notes


def test_optional_trusted_types_csp_finding_stays_low_severity():
    report = _local_posture_report()
    report["http"]["csp_evaluation"] = {
        "present": True,
        "grade": "C",
        "issues": ["Trusted Types not required (optional)."],
        "directives": {"default-src": ["'self'"], "script-src": ["'self'"]},
    }

    emit_config_findings(report)

    finding = next(
        finding
        for finding in report["findings"]
        if finding["title"] == "CSP: Trusted Types not required (optional)."
    )
    assert finding["severity"] == "low"
    assert finding["cvss_score"] == 3.0


def test_waf_config_finding_deduplicates_existing_waf_detection():
    report = _local_posture_report()
    report["findings"] = [
        {
            "tool": "waf_detection",
            "title": "WAF Detected: cloudflare",
            "severity": "info",
        }
    ]
    report["discovery"] = {
        "waf_detection": {
            "waf_detected": True,
            "waf_products": ["cloudflare"],
            "confidence": "none",
        }
    }

    emit_config_findings(report)

    waf_findings = [
        finding
        for finding in report["findings"]
        if str(finding.get("tool", "")).startswith("waf_")
    ]
    assert [finding["tool"] for finding in waf_findings] == ["waf_detection"]
