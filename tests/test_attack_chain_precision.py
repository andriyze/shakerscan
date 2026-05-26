from scanner.scanner_tools.attack_chains import analyze_attack_chains


def test_unverified_sqli_is_partial_not_complete_chain():
    result = analyze_attack_chains(
        [
            {
                "id": "finding-1",
                "tool": "smart_sqli",
                "type": "SQLi",
                "title": "SQL Injection (None - quote)",
                "severity": "high",
                "confidence": 0.7,
                "verified": False,
            }
        ]
    )

    assert result["summary"]["total_chains"] == 0
    assert result["summary"]["total_partial_chains"] == 1
    partial = result["partial_chains"][0]
    assert partial["chain_type"] == "sqli_to_privilege_escalation"
    assert partial["status"] == "partial"
    assert "verified_exploit_evidence" in partial["missing_required"]


def test_verified_sqli_can_form_complete_chain():
    result = analyze_attack_chains(
        [
            {
                "id": "finding-1",
                "tool": "smart_sqli",
                "type": "SQLi",
                "title": "SQL Injection with extracted data",
                "severity": "high",
                "confidence": 0.95,
                "verified": True,
            }
        ]
    )

    assert result["summary"]["total_chains"] == 1
    chain = result["chains"][0]
    assert chain["chain_type"] == "sqli_to_privilege_escalation"
    assert chain["status"] == "complete"


def test_unverified_wildcard_cors_is_not_complete_chain():
    result = analyze_attack_chains(
        [
            {
                "id": "finding-1",
                "tool": "cors_check",
                "title": "CORS Misconfiguration: Wildcard CORS (Access-Control-Allow-Origin: *)",
                "severity": "info",
                "confidence": 0.5,
                "verified": False,
            }
        ]
    )

    assert result["summary"]["total_chains"] == 0
    assert result["summary"]["total_partial_chains"] == 1
    assert result["partial_chains"][0]["chain_type"] == "cors_to_data_theft"
