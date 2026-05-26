from scanner.reporting import emit_http_method_findings


def test_advertised_http_methods_are_collapsed_to_one_info_finding():
    report = {"findings": []}
    emit_http_method_findings(report, {
        "vulnerable": True,
        "trace_enabled": False,
        "risky_methods": [
            {"url": "https://example.test/api/a", "methods": ["PUT", "DELETE"]},
            {"url": "https://example.test/api/b", "methods": ["DELETE", "PUT"]},
            {"url": "https://example.test/api/a", "methods": ["PUT", "DELETE"]},
        ],
    })

    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["tool"] == "http_methods"
    assert finding["severity"] == "info"
    assert finding["title"] == "Risky HTTP methods advertised: DELETE, PUT (2 endpoints)"
    assert finding["evidence"]["all_urls"] == [
        "https://example.test/api/a",
        "https://example.test/api/b",
    ]
    assert "no method execution proof" in finding["evidence"]["detail"]


def test_trace_echo_remains_separate_method_finding():
    report = {"findings": []}
    emit_http_method_findings(report, {
        "vulnerable": True,
        "trace_enabled": True,
        "trace_evidence": {"response_snippet": "TRACE / HTTP/1.1"},
        "risky_methods": [
            {"url": "https://example.test/api/a", "methods": ["PUT"]},
        ],
    })

    assert len(report["findings"]) == 2
    trace = report["findings"][0]
    advertised = report["findings"][1]
    assert trace["title"] == "HTTP TRACE echo enabled"
    assert trace["severity"] == "medium"
    assert advertised["severity"] == "info"
