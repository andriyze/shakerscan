import json
from datetime import datetime, timedelta, timezone
import zipfile
from pathlib import Path

from scanner.scanner_tools import model_intake_scanners as scanners
from scanner.scanner_tools.model_intake_scanners import _parse_external_scanner


def test_json_scanners_never_pass_empty_or_malformed_output():
    for scanner in ("modelscan", "semgrep", "trivy", "osv-scanner", "pip-audit"):
        assert _parse_external_scanner(scanner, "", "", 0)[0] == "INCOMPLETE"
        assert _parse_external_scanner(scanner, "not-json", "", 0)[0] == "INCOMPLETE"


def test_semgrep_summary_reports_bounded_safe_file_coverage():
    output = {
        "results": [], "errors": [],
        "paths": {"scanned": ["modeling.py", "config.json"], "skipped": ["weights.bin"]},
    }

    status, findings, summary = _parse_external_scanner("semgrep", json.dumps(output), "", 0)

    assert status == "PASS"
    assert findings == []
    assert summary["files_scanned"] == 2
    assert summary["files_skipped"] == 1
    assert summary["scanned_files"] == ["modeling.py", "config.json"]
    assert summary["skipped_files"] == ["weights.bin"]


def test_semgrep_summary_rejects_unsafe_or_unrelated_paths(tmp_path):
    subject = tmp_path / "subject"
    subject.mkdir()
    output = {
        "results": [], "errors": [],
        "paths": {
            "scanned": [str(subject / "modeling.py"), "/etc/passwd", "../escape.py"],
            "skipped": [{"path": str(subject / "weights.bin")}],
        },
    }

    _, _, summary = _parse_external_scanner(
        "semgrep", json.dumps(output), "", 0, subject_path=subject,
    )

    assert summary["scanned_files"] == ["modeling.py"]
    assert summary["skipped_files"] == ["weights.bin"]


def test_osv_adapter_uses_explicit_packaged_database_and_go_runtime_boundary():
    spec = next(item for item in scanners.EXTERNAL_SCANNERS if item.name == "osv-scanner")

    assert ("--local-db-path", "/opt/osv-cache") == (
        spec.args[spec.args.index("--local-db-path")],
        spec.args[spec.args.index("--local-db-path") + 1],
    )
    command = scanners._bounded_command("/opt/tools/osv-scanner", ["--version"])
    assert "--no-address-space-limit" in command


def test_trivy_sca_adapter_validates_schema_and_findings():
    trivy = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-TEST", "Severity": "HIGH", "PkgName": "demo",
        "InstalledVersion": "1.0", "FixedVersion": "1.1",
    }]}]}
    status, findings, _ = _parse_external_scanner("trivy", json.dumps(trivy), "", 0)
    assert status == "FAIL"
    assert findings[0]["package"] == "demo"
    assert findings[0]["fixed_versions"] == ["1.1"]


def test_osv_and_pip_audit_normalize_exact_package_advisories():
    osv = {"results": [{"packages": [{
        "package": {"name": "requests", "version": "2.19.0"},
        "groups": [{
            "ids": ["GHSA-test"], "aliases": ["CVE-2024-0001"], "max_severity": 9.1,
        }],
        "vulnerabilities": [{
            "id": "GHSA-test", "aliases": ["CVE-2024-0001"],
            "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.32.0"}]}]}],
        }],
    }]}]}
    status, findings, summary = _parse_external_scanner("osv-scanner", json.dumps(osv), "", 1)
    assert status == "FAIL"
    assert findings[0]["id"] == "CVE-2024-0001"
    assert findings[0]["fixed_versions"] == ["2.32.0"]
    assert summary["packages_scanned"] == 1

    pip_audit = {"dependencies": [{
        "name": "requests", "version": "2.19.0", "vulns": [{
            "id": "PYSEC-1", "aliases": ["CVE-2024-0001"], "fix_versions": ["2.32.0"],
        }],
    }], "fixes": []}
    status, findings, summary = _parse_external_scanner("pip-audit", json.dumps(pip_audit), "", 1)
    assert status == "WARNING"
    assert findings[0]["severity_source"] == "not_reported"
    assert summary["severity_available"] is False


def test_osv_clean_result_uses_generated_input_as_coverage_denominator(monkeypatch, tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "osv-scanner.json").write_text(json.dumps({
        "results": [{
            "source": {"path": "fixture", "type": "test"},
            "packages": [
                {"package": {"name": "requests", "version": "2.32.0", "ecosystem": "PyPI"}},
                {"package": {"name": "urllib3", "version": "2.6.0", "ecosystem": "PyPI"}},
            ],
        }],
    }))
    monkeypatch.setattr(scanners, "_scanner_material_state", lambda _spec: {
        "ready": True, "rules": None, "database": {"sha256": "d" * 64},
    })
    monkeypatch.setattr(scanners.shutil, "which", lambda _name: "/opt/tools/osv-scanner")
    monkeypatch.setattr(scanners, "_tool_version", lambda *_args: "2.5.0")
    monkeypatch.setattr(scanners, "_prepare_unprivileged_paths", lambda *_args: None)
    monkeypatch.setattr(scanners, "_bounded_command", lambda executable, args: [executable, *args])

    class Completed:
        returncode = 0

    def fake_run(_argv, **kwargs):
        kwargs["stdout"].write(b'{"results":[]}')
        return Completed()

    monkeypatch.setattr(scanners.subprocess, "run", fake_run)
    spec = next(item for item in scanners.EXTERNAL_SCANNERS if item.name == "osv-scanner")

    result = scanners.run_external_scanner(
        spec, evidence, {"kind": "dependency_evidence", "digest": "sha256:" + "a" * 64},
    )

    assert result["execution"]["status"] == "PASS"
    assert result["summary"]["packages_scanned"] == 2
    assert result["summary"]["packages_returned_with_results"] == 0
    assert len(result["summary"]["input_sha256"]) == 64


def test_osv_zero_package_input_fails_closed(monkeypatch, tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "osv-scanner.json").write_text('{"results":[{"packages":[]}]}')
    monkeypatch.setattr(scanners, "_scanner_material_state", lambda _spec: {
        "ready": True, "rules": None, "database": {"sha256": "d" * 64},
    })
    monkeypatch.setattr(scanners.shutil, "which", lambda _name: "/opt/tools/osv-scanner")
    monkeypatch.setattr(scanners, "_tool_version", lambda *_args: "2.5.0")
    monkeypatch.setattr(scanners, "_prepare_unprivileged_paths", lambda *_args: None)
    monkeypatch.setattr(scanners, "_bounded_command", lambda executable, args: [executable, *args])

    class Completed:
        returncode = 0

    def fake_run(_argv, **kwargs):
        kwargs["stdout"].write(b'{"results":[]}')
        return Completed()

    monkeypatch.setattr(scanners.subprocess, "run", fake_run)
    spec = next(item for item in scanners.EXTERNAL_SCANNERS if item.name == "osv-scanner")

    result = scanners.run_external_scanner(
        spec, evidence, {"kind": "dependency_evidence", "digest": "sha256:" + "b" * 64},
    )

    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["summary"]["error"] == "osv_input_has_no_packages"


def test_trivy_license_adapter_preserves_inventory_and_requires_review():
    trivy = {"Results": [{
        "Target": "/snapshot/LICENSE.custom",
        "Licenses": [
            {"Name": "MIT", "Category": "permissive", "Severity": "LOW", "PkgName": "safe-lib"},
            {"Name": "GPL-3.0-only", "Category": "reciprocal", "Severity": "MEDIUM", "PkgName": "copyleft-lib"},
            {"Name": "Acme Research Terms", "Category": "unknown", "Severity": "UNKNOWN"},
        ],
    }]}

    status, findings, summary = _parse_external_scanner("trivy", json.dumps(trivy), "", 0)

    assert status == "WARNING"
    assert findings == []
    assert summary["licenses"] == 3
    assert summary["license_class_counts"] == {"permissive": 1, "reciprocal": 1, "unknown": 1}
    assert [item["license"] for item in summary["license_inventory"]] == [
        "MIT", "GPL-3.0-only", "Acme Research Terms",
    ]
    assert all(len(item["evidence_sha256"]) == 64 for item in summary["license_inventory"])


def test_trivy_forbidden_and_restricted_licenses_fail():
    trivy = {"Results": [{"Licenses": [
        {"Name": "AGPL-3.0-only", "Category": "restricted", "Severity": "HIGH"},
        {"Name": "Proprietary", "Category": "forbidden", "Severity": "CRITICAL"},
    ]}]}

    status, findings, summary = _parse_external_scanner("trivy", json.dumps(trivy), "", 1)

    assert status == "FAIL"
    assert [item["severity"] for item in findings] == ["high", "critical"]
    assert summary["licenses"] == 2


def test_modelscan_adapter_is_fail_closed():
    assert _parse_external_scanner("modelscan", '{"issues":[]}', "", 0)[0] == "PASS"
    modelscan_preamble = (
        "No settings file detected at /app/modelscan-settings.toml. Using defaults.\n\n"
        "Scanning /tmp/model.pkl using PickleUnsafeOpScan model scan\n"
        '{"issues":[{"operator":"GLOBAL"}],"errors":[]}'
    )
    status, findings, _ = _parse_external_scanner("modelscan", modelscan_preamble, "", 1)
    assert status == "FAIL"
    assert findings[0]["operator"] == "GLOBAL"
    assert findings[0]["classification"] == "unsafe_serialization_primitive"
    assert _parse_external_scanner("modelscan", "untrusted preamble\n{\"issues\":[]}", "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("modelscan", '{}', "", 0)[0] == "INCOMPLETE"
    assert _parse_external_scanner("modelscan", '{"issues":[{"operator":"GLOBAL"}]}', "", 1)[0] == "FAIL"
    error_status, error_findings, error_summary = _parse_external_scanner(
        "modelscan",
        '{"issues":[],"errors":[{"description":"unsupported format"}]}',
        "",
        1,
    )
    assert error_status == "INCOMPLETE"
    assert error_findings == []
    assert error_summary["error"] == "modelscan_incomplete_coverage"
    assert error_summary["error_count"] == 1


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
        "classification": "prohibited_capability",
    }
    assert summary["finding_count"] == 1
    assert _parse_external_scanner("semgrep", '{"results":[]}', "", 0)[0] == "PASS"
    assert _parse_external_scanner("semgrep", '{"errors":[]}', "", 0)[0] == "INCOMPLETE"
    warning_status, warning_findings, warning_summary = _parse_external_scanner(
        "semgrep",
        json.dumps({"results": [{"check_id": "review", "extra": {"severity": "WARNING"}}], "errors": []}),
        "",
        0,
    )
    assert warning_status == "WARNING"
    assert warning_findings[0]["classification"] == "review_required"
    assert warning_summary["warning_only"] is True


def test_semgrep_rule_contract_distinguishes_prohibited_review_and_safe_patterns():
    rules = (Path(__file__).resolve().parents[1] / "scanner/scanner_tools/model_intake_semgrep.yml").read_text()

    assert "torch.load(..., weights_only=False, ...)" in rules
    assert "pattern-not: torch.load(..., weights_only=$VALUE, ...)" in rules
    assert "shakerscan.model-intake.hub-code-or-artifact-fetch" in rules
    assert "shakerscan.model-intake.native-library-load" in rules
    dynamic = rules.split("shakerscan.model-intake.dynamic-import", 1)[1].split("  - id:", 1)[0]
    remote = rules.split("shakerscan.model-intake.remote-code-opt-in", 1)[1].split("  - id:", 1)[0]
    assert "severity: WARNING" in dynamic
    assert "severity: WARNING" in remote
    fixtures = Path(__file__).resolve().parent / "fixtures/model_intake_semgrep"
    assert "weights_only=True" in (fixtures / "safe.py").read_text()
    assert "weights_only=False" in (fixtures / "prohibited.py").read_text()
    assert "import_module" in (fixtures / "review.py").read_text()


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
    assert zip_by_name["trivy"]["applicable"] is True
    assert zip_by_name["trivy"]["reason"] == "complete_repository_snapshot"


def test_requested_adapter_is_required_and_unknown_names_are_not_in_plan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("transformers==1\n")
    plan = scanners.resolve_scanner_plan(repo, requested_names={"trivy"}, profile="baseline")
    assert [(item["spec"].name, item["required"]) for item in plan] == [("trivy", True)]


def test_requested_but_inapplicable_adapter_is_explicit_not_applicable_not_required(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"fixture")

    plan = scanners.resolve_scanner_plan(artifact, requested_names={"semgrep"}, profile="strict")

    assert len(plan) == 1
    assert plan[0]["spec"].name == "semgrep"
    assert plan[0]["requested"] is True
    assert plan[0]["applicable"] is False
    assert plan[0]["required"] is False
    assert plan[0]["requirement_source"] == "not_applicable"


def test_adapter_catalog_separates_provider_kind_and_policy():
    catalog = {item["name"]: item for item in scanners.scanner_adapter_catalog()}
    assert set(catalog) == {"modelscan", "semgrep", "fickling", "trivy", "osv-scanner", "pip-audit"}
    assert catalog["modelscan"]["adapter_kind"] == "evidence_scanner"
    assert catalog["semgrep"]["applicability"] == "repository_code"
    assert catalog["fickling"]["target_scope"] == "artifact"
    assert catalog["trivy"]["required_profiles"] == ["strict"]
    assert catalog["trivy"]["applicability"] == "repository_compliance"
    assert catalog["osv-scanner"]["target_scope"] == "dependency_evidence"
    assert catalog["pip-audit"]["applicability"] == "resolved_python_dependencies"


def test_readiness_requires_functional_self_test_for_default_adapters(tmp_path, monkeypatch):
    receipt = {
        "status": "PASS",
        "tested_at": "2026-01-01T00:00:00+00:00",
        "receipt_sha256": "a" * 64,
        "checks": [
            {"name": name, "passed": True, "actual_status": "FAIL"}
            for name in ("modelscan", "semgrep", "fickling", "trivy", "osv-scanner", "pip-audit")
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
    assert all(by_name[name]["ready"] for name in ("modelscan", "semgrep", "fickling", "trivy", "osv-scanner", "pip-audit"))
    assert by_name["modelscan"]["last_self_test"]["passed"] is True


def test_runtime_dependency_evidence_uses_fixed_profile_without_mutating_repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "helpers.py").write_text("VALUE = 1\n")
    (repo / "modeling.py").write_text(
        "import torch\nfrom transformers import AutoModel\nimport regex\nfrom . import helpers\n"
    )
    (repo / "README.md").write_text(
        "```python\nfrom sentence_transformers import SentenceTransformer\n```\n"
    )
    before = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))

    result, evidence = scanners.materialize_runtime_dependency_evidence(
        repo, tmp_path / "evidence", {"digest": "sha256:" + "a" * 64, "complete": True},
    )

    after = sorted(path.relative_to(repo).as_posix() for path in repo.rglob("*"))
    assert before == after
    assert result["execution"]["status"] == "WARNING"
    assert result["execution"]["network_used"] is False
    assert {path.name for path in evidence.iterdir()} == {
        "requirements.txt", "runtime-components.json", "osv-scanner.json",
    }
    inventory = json.loads((evidence / "runtime-components.json").read_text())
    assert inventory["profile"]["id"] == scanners.RUNTIME_PROFILE_ID
    assert len(inventory["components"]) == 41
    inferred = {item["import_name"]: item for item in inventory["inferred_requirements"]}
    assert inferred["torch"]["version"] == "2.13.0+cpu"
    assert inferred["sentence_transformers"]["required_for_fixed_loader"] is False


def test_unknown_runtime_import_fails_closed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "modeling.py").write_text("import definitely_not_in_fixed_runtime\n")
    result, _ = scanners.materialize_runtime_dependency_evidence(
        repo, tmp_path / "evidence", {"digest": "sha256:" + "b" * 64, "complete": True},
    )
    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["coverage"]["unresolved_required"] == ["definitely_not_in_fixed_runtime"]


def test_vulnerability_reconciliation_preserves_sources_and_severity():
    results = [
        {"scanner": {"name": "osv-scanner"}, "execution": {"status": "FAIL"}, "findings": [{
            "id": "CVE-2024-0001", "aliases": ["GHSA-test"], "severity": "high",
            "package": "Requests", "installed_version": "2.19.0", "fixed_versions": ["2.32.0"],
            "evidence_sha256": "a" * 64,
        }]},
        {"scanner": {"name": "pip-audit"}, "execution": {"status": "WARNING"}, "findings": [{
            "id": "CVE-2024-0001", "aliases": ["PYSEC-1"], "severity": "medium",
            "severity_source": "not_reported", "package": "requests", "installed_version": "2.19.0",
            "fixed_versions": ["2.31.0"], "evidence_sha256": "b" * 64,
        }]},
    ]
    reconciled = scanners.reconcile_vulnerability_evidence(results)
    assert reconciled["summary"]["total"] == 1
    assert reconciled["summary"]["multi_scanner_agreement"] == 1
    assert reconciled["vulnerabilities"][0]["sources"] == ["osv-scanner", "pip-audit"]
    assert reconciled["vulnerabilities"][0]["severity"] == "high"


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
