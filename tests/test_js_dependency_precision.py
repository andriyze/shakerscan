from scanner.scanner_tools.client_side import js_dependency_report_severity


def test_dependency_only_high_cve_reports_as_medium_until_usage_is_proven():
    severity = js_dependency_report_severity({
        "severity": "high",
        "cve": "CVE-2020-11023",
        "summary": "jQuery DOM manipulation XSS",
    })

    assert severity == "medium"


def test_dependency_high_cve_can_promote_with_runtime_usage_evidence():
    severity = js_dependency_report_severity({
        "severity": "high",
        "cve": "CVE-2020-11023",
        "runtime_proof": {"sink": "$.html", "attacker_controlled": True},
    })

    assert severity == "high"


def test_dependency_medium_cve_stays_medium():
    severity = js_dependency_report_severity({
        "severity": "medium",
        "cve": "CVE-2019-11358",
    })

    assert severity == "medium"
