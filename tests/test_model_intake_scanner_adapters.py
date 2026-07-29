import json

from scanner.scanner_tools.model_intake_scanners import _parse_external_scanner


def test_json_scanners_never_pass_empty_or_malformed_output():
    for scanner in ("modelscan", "gitleaks", "syft", "trivy", "osv-scanner", "pip-audit"):
        assert _parse_external_scanner(scanner, "", "", 0)[0] == "INCOMPLETE"
        assert _parse_external_scanner(scanner, "not-json", "", 0)[0] == "INCOMPLETE"


def test_sbom_and_sca_adapters_validate_schema_and_findings():
    assert _parse_external_scanner("syft", json.dumps({"bomFormat": "CycloneDX", "components": []}), "", 0)[0] == "PASS"
    trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": "HIGH"}]}]}
    assert _parse_external_scanner("trivy", json.dumps(trivy), "", 0)[0] == "FAIL"
    osv = {"results": [{"packages": [{"vulnerabilities": [{"id": "OSV-TEST"}]}]}]}
    assert _parse_external_scanner("osv-scanner", json.dumps(osv), "", 0)[0] == "FAIL"


def test_secret_model_and_malware_adapters_are_fail_closed():
    assert _parse_external_scanner("gitleaks", "[]", "", 0)[0] == "PASS"
    assert _parse_external_scanner("gitleaks", '[{"RuleID":"dummy"}]', "", 1)[0] == "FAIL"
    assert _parse_external_scanner("modelscan", '{"issues":[]}', "", 0)[0] == "PASS"
    assert _parse_external_scanner("modelscan", '{}', "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("modelscan", '{"issues":[{"operator":"GLOBAL"}]}', "", 1)[0] == "FAIL"
    assert _parse_external_scanner("clamav", "----------- SCAN SUMMARY -----------\nInfected files: 0", "", 0)[0] == "PASS"
    assert _parse_external_scanner("clamav", "", "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("clamav", "----------- SCAN SUMMARY -----------\nInfected files: 0", "", 2)[0] == "CRASHED"


def test_fickling_requires_semantic_output():
    assert _parse_external_scanner("fickling", "", "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("fickling", "analysis completed safely", "", 0)[0] == "PASS"
    assert _parse_external_scanner("fickling", "unsafe import detected", "", 1)[0] == "FAIL"
