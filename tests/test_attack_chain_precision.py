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


def test_proven_sqli_is_only_an_observed_entry_point_not_a_complete_chain():
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
                "proof_of_exploitation": True,
            }
        ]
    )

    assert result["summary"]["total_chains"] == 0
    chain = result["partial_chains"][0]
    assert chain["chain_type"] == "sqli_to_privilege_escalation"
    assert chain["status"] == "partial"
    assert chain["steps"][0]["status"] == "observed"
    assert all(step["status"] == "hypothetical" for step in chain["steps"][1:])
    assert "unobserved_chain_steps:2,3" in chain["missing_required"]


def test_complete_chain_requires_reference_backed_observation_for_every_step():
    result = analyze_attack_chains(
        [{
            "id": "finding-1",
            "tool": "smart_sqli",
            "type": "SQLi",
            "title": "SQL Injection with observed escalation",
            "severity": "critical",
            "confidence": 0.99,
            "proof_of_exploitation": True,
            "attack_chain_observations": [
                {"step_number": 2, "observed": True, "evidence_ref": "response:credential-row"},
                {"step_number": 3, "observed": True, "evidence_ref": "response:admin-control"},
            ],
        }]
    )

    assert result["summary"]["total_chains"] == 1
    chain = result["chains"][0]
    assert chain["status"] == "complete"
    assert all(step["status"] == "observed" for step in chain["steps"])


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
