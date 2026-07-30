import json
from datetime import datetime, timedelta, timezone
import zipfile
from pathlib import Path

from scanner.scanner_tools import model_intake_scanners as scanners
from scanner.scanner_tools.model_intake_scanners import _parse_external_scanner


def test_json_scanners_never_pass_empty_or_malformed_output():
    for scanner in ("modelscan", "semgrep", "trivy"):
        assert _parse_external_scanner(scanner, "", "", 0)[0] == "INCOMPLETE"
        assert _parse_external_scanner(scanner, "not-json", "", 0)[0] == "INCOMPLETE"


def test_trivy_sca_adapter_validates_schema_and_findings():
    trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": "HIGH"}]}]}
    assert _parse_external_scanner("trivy", json.dumps(trivy), "", 0)[0] == "FAIL"


def test_modelscan_adapter_is_fail_closed():
    assert _parse_external_scanner("modelscan", '{"issues":[]}', "", 0)[0] == "PASS"
    modelscan_preamble = (
        "No settings file detected at /app/modelscan-settings.toml. Using defaults.\n\n"
        "Scanning /tmp/model.pkl using PickleUnsafeOpScan model scan\n"
        '{"issues":[{"operator":"GLOBAL"}],"errors":[]}'
    )
    assert _parse_external_scanner("modelscan", modelscan_preamble, "", 1)[0] == "FAIL"
    assert _parse_external_scanner("modelscan", "untrusted preamble\n{\"issues\":[]}", "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("modelscan", '{}', "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("modelscan", '{"issues":[{"operator":"GLOBAL"}]}', "", 1)[0] == "FAIL"


def test_fickling_requires_semantic_output():
    assert _parse_external_scanner("fickling", "", "", 0)[0] == "PASS"
    assert _parse_external_scanner("fickling", "analysis completed safely", "", 0)[0] == "PASS"
    assert _parse_external_scanner("fickling", "Warning: file may be unsafe", "", 1)[0] == "FAIL"
    assert _parse_external_scanner("fickling", "failed to parse", "", 2)[0] == "INCOMPLETE"


def test_semgrep_parser_requires_schema_and_preserves_findings():
    assert _parse_external_scanner("semgrep", '{"results":[],"errors":[]}', "", 0)[0] == "PASS"
    status, findings, summary = _parse_external_scanner(
        "semgrep",
        json.dumps({"results": [{
            "check_id": "model-intake.exec",
            "path": "/quarantine/snapshot/modeling.py",
            "start": {"line": 42},
            "extra": {"severity": "ERROR", "message": "Dynamic execution is unsafe."},
        }], "errors": []}),
        "",
        1,
    )
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0] == {
        "id": "semgrep_finding",
        "severity": "high",
        "evidence_sha256": findings[0]["evidence_sha256"],
        "rule_id": "model-intake.exec",
        "path": "modeling.py",
        "line": 42,
        "message": "Dynamic execution is unsafe.",
        "tool_severity": "ERROR",
    }
    assert summary["finding_count"] == 1
    assert _parse_external_scanner("semgrep", '{"results":[]}', "", 0)[0] == "PASS"
    assert _parse_external_scanner("semgrep", '{"errors":[]}', "", 0)[0] == "INCOMPLETE"
    warning_status, _, warning_summary = _parse_external_scanner(
        "semgrep",
        json.dumps({"results": [{"check_id": "review", "extra": {"severity": "WARNING"}}], "errors": []}),
        "",
        0,
    )
    assert warning_status == "WARNING"
    assert warning_summary["warning_only"] is True


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

    torch_zip = tmp_path / "torch"
    torch_zip.mkdir()
    with zipfile.ZipFile(torch_zip / "pytorch_model.bin", "w") as archive:
        archive.writestr("archive/data.pkl", b"pickle")
    zip_plan = scanners.resolve_scanner_plan(torch_zip, profile="strict")
    zip_by_name = {item["spec"].name: item for item in zip_plan}
    assert zip_by_name["modelscan"]["applicable"] is True
    assert zip_by_name["fickling"]["applicable"] is False
    assert zip_by_name["fickling"]["reason"] == "pytorch_zip_not_supported_by_fickling"


def test_requested_adapter_is_required_and_unknown_names_are_not_in_plan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("transformers==1\n")
    plan = scanners.resolve_scanner_plan(repo, requested_names={"trivy"}, profile="baseline")
    assert [(item["spec"].name, item["required"]) for item in plan] == [("trivy", True)]


def test_adapter_catalog_separates_provider_kind_and_policy():
    catalog = {item["name"]: item for item in scanners.scanner_adapter_catalog()}
    assert set(catalog) == {"modelscan", "semgrep", "fickling", "trivy"}
    assert catalog["modelscan"]["adapter_kind"] == "evidence_scanner"
    assert catalog["semgrep"]["applicability"] == "repository_code"
    assert catalog["fickling"]["target_scope"] == "artifact"
    assert catalog["trivy"]["required_profiles"] == ["strict"]


def test_readiness_requires_functional_self_test_for_default_adapters(tmp_path, monkeypatch):
    receipt = {
        "status": "PASS",
        "tested_at": "2026-01-01T00:00:00+00:00",
        "receipt_sha256": "a" * 64,
        "checks": [
            {"name": name, "passed": True, "actual_status": "FAIL"}
            for name in ("modelscan", "semgrep", "fickling", "trivy")
        ],
    }
    receipt_path = tmp_path / "self-test.json"
    receipt_path.write_text(json.dumps(receipt))
    monkeypatch.setattr(scanners, "ADAPTER_SELF_TEST_PATH", str(receipt_path))
    monkeypatch.setattr(scanners.shutil, "which", lambda name: f"/opt/tools/{name}")
    monkeypatch.setattr(scanners, "_tool_version", lambda *args: "test-version")
    monkeypatch.setattr(Path, "is_file", lambda path: True)
    monkeypatch.setattr(scanners, "_hash_path", lambda path: "b" * 64)
    monkeypatch.setattr(Path, "read_text", lambda path, *args, **kwargs: json.dumps(receipt))
    monkeypatch.setattr(scanners, "_scanner_material_state", lambda spec: {
        "ready": True,
        "rules": {"present": True, "fresh": True, "sha256": "b" * 64} if spec.rules_path else None,
        "database": {"present": True, "fresh": True, "sha256": "b" * 64} if spec.database_path else None,
    })

    readiness = scanners.scanner_adapter_readiness()
    by_name = {item["name"]: item for item in readiness["adapters"]}

    assert readiness["self_test"]["status"] == "PASS"
    assert all(by_name[name]["ready"] for name in ("modelscan", "semgrep", "fickling", "trivy"))
    assert by_name["modelscan"]["last_self_test"]["passed"] is True


def test_scanner_material_freshness_is_measured_and_bounded(tmp_path, monkeypatch):
    now = datetime(2026, 7, 30, tzinfo=timezone.utc)
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    recent = (now - timedelta(days=1)).timestamp()
    __import__("os").utime(rules, (recent, recent))
    database = tmp_path / "metadata.json"
    database.write_text(json.dumps({"UpdatedAt": now.isoformat(), "NextUpdate": (now + timedelta(days=1)).isoformat()}))
    monkeypatch.setenv("MODEL_INTAKE_SCANNER_MAX_RULE_AGE_DAYS", "90")
    monkeypatch.setenv("MODEL_INTAKE_SCANNER_MAX_DATABASE_AGE_DAYS", "14")
    spec = scanners.ScannerSpec(
        "fixture", "fixture", (), rules_path=str(rules), database_path=str(database), required=True,
    )

    state = scanners._scanner_material_state(spec, now=now)

    assert state["ready"] is True
    assert state["rules"]["fresh"] is True
    assert state["database"]["fresh"] is True
    assert state["database"]["max_age_days"] == 14


def test_stale_scanner_material_fails_before_tool_execution(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    old = (now - timedelta(days=100)).timestamp()
    __import__("os").utime(rules, (old, old))
    monkeypatch.setenv("MODEL_INTAKE_SCANNER_MAX_RULE_AGE_DAYS", "30")
    monkeypatch.setattr(scanners.shutil, "which", lambda _name: (_ for _ in ()).throw(AssertionError("tool must not run")))
    spec = scanners.ScannerSpec("fixture", "fixture", (), rules_path=str(rules), required=True)

    result = scanners.run_external_scanner(spec, tmp_path, {"kind": "repository", "digest": "sha256:" + "a" * 64})

    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["execution"]["error"] == "scanner_material_missing_or_stale"
    assert result["execution"]["reassessment_trigger"] == "scanner_data_stale"
    assert result["summary"]["materials"]["rules"]["reason"] == "material_stale"
