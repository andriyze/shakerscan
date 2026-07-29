import json

from scanner.scanner_tools import model_intake_scanners as scanners
from scanner.scanner_tools.model_intake_scanners import _parse_external_scanner


def test_json_scanners_never_pass_empty_or_malformed_output():
    for scanner in ("modelscan", "semgrep", "gitleaks", "syft", "trivy", "osv-scanner", "pip-audit"):
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


def test_semgrep_parser_requires_schema_and_preserves_findings():
    assert _parse_external_scanner("semgrep", '{"results":[],"errors":[]}', "", 0)[0] == "PASS"
    status, findings, summary = _parse_external_scanner(
        "semgrep",
        json.dumps({"results": [{"check_id": "model-intake.exec", "extra": {"severity": "ERROR"}}], "errors": []}),
        "",
        1,
    )
    assert status == "FAIL"
    assert len(findings) == 1
    assert summary["finding_count"] == 1
    assert _parse_external_scanner("semgrep", '{"results":[]}', "", 0)[0] == "PASS"
    assert _parse_external_scanner("semgrep", '{"errors":[]}', "", 0)[0] == "INCOMPLETE"


def test_scanner_plan_is_format_and_repository_fact_driven(tmp_path):
    safe_repo = tmp_path / "safe"
    safe_repo.mkdir()
    (safe_repo / "model.safetensors").write_bytes(b"safe")
    (safe_repo / "modeling_custom.py").write_text("print('loaded')")
    strict_safe = scanners.resolve_scanner_plan(safe_repo, profile="strict")
    by_name = {item["spec"].name: item for item in strict_safe}
    assert by_name["semgrep"]["required"] is True
    assert by_name["modelscan"]["applicable"] is False
    assert by_name["fickling"]["applicable"] is False

    pickle_repo = tmp_path / "pickle"
    pickle_repo.mkdir()
    (pickle_repo / "pytorch_model.bin").write_bytes(b"pickle")
    strict_pickle = scanners.resolve_scanner_plan(pickle_repo, profile="strict")
    pickle_by_name = {item["spec"].name: item for item in strict_pickle}
    assert pickle_by_name["modelscan"]["required"] is True
    assert pickle_by_name["fickling"]["required"] is True
    assert pickle_by_name["semgrep"]["applicable"] is False


def test_requested_adapter_is_required_and_unknown_names_are_not_in_plan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("transformers==1\n")
    plan = scanners.resolve_scanner_plan(repo, requested_names={"trivy"}, profile="baseline")
    assert [(item["spec"].name, item["required"]) for item in plan] == [("trivy", True)]


def test_adapter_catalog_separates_provider_kind_and_policy():
    catalog = {item["name"]: item for item in scanners.scanner_adapter_catalog()}
    assert catalog["modelscan"]["adapter_kind"] == "evidence_scanner"
    assert catalog["semgrep"]["applicability"] == "repository_code"
    assert catalog["fickling"]["target_scope"] == "artifact"
    assert catalog["trivy"]["required_profiles"] == ["strict"]
    assert catalog["syft"]["enabled_by_default"] is False
