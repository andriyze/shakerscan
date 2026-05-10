from scanner.scanner_tools.compliance_mapper import (
    generate_compliance_report,
    generate_grc_evidence_matrix,
)


def test_grc_evidence_matrix_maps_api_ai_iso_and_sla_controls():
    findings = [
        {
            "id": "f-api-bola",
            "title": "BOLA on account API",
            "severity": "critical",
            "tool": "authz",
            "category": "BOLA",
            "cwe": "CWE-639",
            "url": "https://example.test/api/accounts/2",
            "evidence": {
                "request": "GET /api/accounts/2",
                "response": "200 OK",
                "proof": "User A received User B account data",
                "replay_command": "curl -H 'Authorization: Bearer user-a' https://example.test/api/accounts/2",
                "business_impact": "Cross-tenant account data exposure.",
            },
        },
        {
            "id": "f-ai-mcp",
            "title": "MCP OAuth token audience confusion",
            "severity": "high",
            "tool": "ai_gate",
            "source_type": "ai",
            "owasp": "LLM08:2025",
            "url": "https://example.test/mcp",
            "evidence": {
                "transcript": [{"role": "assistant", "content": "accepted mismatched audience token"}],
                "proof": "MCP server accepted token with wrong audience.",
            },
        },
    ]

    matrix = generate_grc_evidence_matrix(findings, {"target": "https://example.test", "scan_id": "scan-1"})

    assert matrix["frameworks"]["owasp_api_security"]["controls"]["API1"]["count"] == 1
    assert matrix["frameworks"]["owasp_llm_agentic"]["controls"]["LLM08"]["count"] == 1
    assert matrix["frameworks"]["nist_ai_rmf"]["controls"]["MANAGE"]["count"] == 1
    assert matrix["frameworks"]["iso_27001_2022"]["controls"]["A.5.15"]["count"] == 2
    assert matrix["frameworks"]["internal_sla"]["controls"]["SLA-CRITICAL"]["sla_hours"] == 24
    assert matrix["frameworks"]["internal_sla"]["controls"]["SLA-CRITICAL"]["count"] == 1
    assert matrix["summary"]["findings_with_proof"] == 2
    assert matrix["summary"]["findings_with_replay"] == 1
    assert matrix["summary"]["findings_with_transcript"] == 1
    assert matrix["summary"]["findings_with_request_response"] == 1


def test_compliance_report_includes_grc_evidence_without_replacing_existing_maps():
    findings = [
        {
            "id": "f-sqli",
            "title": "SQL injection on search API",
            "severity": "high",
            "tool": "sqli",
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "url": "https://example.test/api/search?q=test",
            "evidence": {"request": "GET /api/search?q='", "response": "SQL syntax error"},
        }
    ]

    report = generate_compliance_report(findings, {"target": "https://example.test"}, frameworks=["pci_dss"])

    assert "pci_dss" in report["frameworks"]
    assert report["owasp_mapping"]["framework"] == "OWASP Top 10 2021"
    assert report["grc_evidence"]["frameworks"]["owasp_top10_2025"]["controls"]["A03:2025"]["count"] == 1
    assert report["grc_evidence"]["frameworks"]["internal_sla"]["controls"]["SLA-HIGH"]["count"] == 1
