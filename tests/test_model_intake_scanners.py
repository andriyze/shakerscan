import hashlib
import os

from scanner.scanner_tools import model_intake_scanners as scanners


def _subject(digest="a" * 64, kind="model_artifact"):
    return {"kind": kind, "digest": f"sha256:{digest}", "complete": True}


def test_semgrep_version_uses_pinned_environment_metadata(monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    semgrep = bin_dir / "semgrep"
    python = bin_dir / "python"
    semgrep.write_text("fixture")
    python.write_text("fixture")
    captured = {}

    class Completed:
        stdout = "1.172.0\n"
        stderr = ""

    def fake_run(argv, **_kwargs):
        captured["argv"] = list(argv)
        return Completed()

    monkeypatch.setattr(scanners, "_bounded_command", lambda executable, args: [executable, *args])
    monkeypatch.setattr(scanners.subprocess, "run", fake_run)

    version = scanners._tool_version(str(semgrep), ("--version",), {}, tmp_path)

    assert version == "1.172.0"
    assert captured["argv"][0] == str(python)
    assert "importlib.metadata" in captured["argv"][2]


def test_missing_required_external_scanner_is_unsupported_and_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(scanners.shutil, "which", lambda executable: None)
    spec = scanners.ScannerSpec("required-tool", "missing", ("{subject}",), required=True)

    result = scanners.run_external_scanner(spec, tmp_path / "subject", _subject())
    summary = scanners.generated_evidence_summary([result])

    assert result["execution"]["status"] == "UNSUPPORTED"
    assert result["execution"]["required"] is True
    assert result["provenance_class"] == "shakerscan_generated"
    assert len(result["evidence_sha256"]) == 64
    assert summary["required_non_pass"] == ["required-tool"]


def test_trivy_full_license_mode_is_limited_to_complete_repository(monkeypatch, tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "LICENSE").write_text("fixture")
    captured: list[list[str]] = []

    monkeypatch.setattr(scanners, "_scanner_material_state", lambda _spec: {
        "ready": True,
        "rules": None,
        "database": {"sha256": "d" * 64},
    })
    monkeypatch.setattr(scanners.shutil, "which", lambda _name: "/usr/bin/trivy")
    monkeypatch.setattr(scanners, "_tool_version", lambda *_args: "test")
    monkeypatch.setattr(scanners, "_prepare_unprivileged_paths", lambda *_args: None)
    monkeypatch.setattr(scanners, "_bounded_command", lambda executable, args: [executable, *args])

    class Completed:
        returncode = 0

    def fake_run(argv, **_kwargs):
        captured.append(list(argv))
        _kwargs["stdout"].write(b'{"Results":[]}')
        return Completed()

    monkeypatch.setattr(scanners.subprocess, "run", fake_run)
    spec = next(item for item in scanners.EXTERNAL_SCANNERS if item.name == "trivy")

    complete = scanners.run_external_scanner(spec, snapshot, _subject(kind="repository_snapshot"))
    incomplete = scanners.run_external_scanner(
        spec, snapshot, {**_subject(kind="repository_snapshot"), "complete": False},
    )

    assert "--license-full" in captured[0]
    assert "--license-full" not in captured[1]
    assert "--license-full" in complete["execution"]["argv_contract"]
    assert "--license-full" not in incomplete["execution"]["argv_contract"]
    assert complete["execution"]["license_scan_mode"] == "full_repository"
    assert incomplete["execution"]["license_scan_mode"] == "package_metadata"
    assert complete["execution"]["database_sha256"] == "d" * 64


def test_unprivileged_selected_artifact_can_traverse_disposable_snapshot(monkeypatch, tmp_path):
    disposable = tmp_path / "model-intake-subject-fixture"
    snapshot = disposable / "snapshot"
    snapshot.mkdir(parents=True)
    artifact = snapshot / "pytorch_model.bin"
    artifact.write_bytes(b"fixture")
    scratch = tmp_path / "scanner-scratch"
    scratch.mkdir()
    disposable.chmod(0o700)
    snapshot.chmod(0o700)

    account = type("Account", (), {"pw_uid": 1002, "pw_gid": 1002})()
    monkeypatch.setattr(scanners.os, "geteuid", lambda: 0)
    monkeypatch.setattr(scanners.os, "chown", lambda *args: None)
    monkeypatch.setattr(scanners.pwd, "getpwnam", lambda name: account)

    scanners._prepare_unprivileged_paths(artifact, scratch)

    assert disposable.stat().st_mode & 0o777 == 0o711
    assert snapshot.stat().st_mode & 0o777 == 0o711
    assert artifact.stat().st_mode & 0o777 == 0o444


def test_skipped_required_scanner_is_a_required_non_pass():
    result = scanners._scanner_result(
        name="required-tool",
        version=None,
        status="SKIPPED_BY_POLICY",
        subject=_subject(),
        started_at="2026-07-29T00:00:00+00:00",
        finished_at="2026-07-29T00:00:01+00:00",
        execution={"required": True, "reason": "scanner_omitted_by_request"},
    )

    summary = scanners.generated_evidence_summary([result])

    assert summary["required_non_pass"] == ["required-tool"]
    assert summary["expectation_matrix"][0]["satisfied"] is False


def test_required_warning_needs_resolution_and_cannot_satisfy_static_gate():
    result = scanners._scanner_result(
        name="semgrep",
        version="1",
        status="WARNING",
        subject=_subject(),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        execution={"required": True, "applicability": "repository_code"},
    )

    summary = scanners.generated_evidence_summary([result])

    assert summary["required_non_pass"] == ["semgrep"]
    assert summary["expectation_matrix"] == [{
        "scanner": "semgrep",
        "required": True,
        "applicability": "repository_code",
        "reason": None,
        "acceptable_statuses": ["PASS", "NOT_APPLICABLE"],
        "actual_status": "WARNING",
        "satisfied": False,
    }]


def test_external_scanner_without_parser_contract_can_never_pass_from_exit_zero():
    status, findings, summary = scanners._default_external_parser('{"looks":"clean"}', "", 0)

    assert status == "INCOMPLETE"
    assert findings == []
    assert summary["error"] == "scanner_parser_contract_missing"


def test_published_review_and_not_run_statuses_fail_closed_when_required():
    for status in ("REVIEW_REQUIRED", "NOT_RUN"):
        result = scanners._scanner_result(
            name="fixture",
            version="1",
            status=status,
            subject=_subject(),
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            execution={"required": True},
        )
        assert result["execution"]["status"] in scanners.REQUIRED_NON_PASS_STATUSES


def test_builtin_pickle_scanner_detects_executable_opcodes(tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")

    result = scanners.run_builtin_pickle_scan(artifact, _subject(hashlib.sha256(artifact.read_bytes()).hexdigest()))

    assert result["execution"]["status"] == "FAIL"
    assert result["coverage"]["pickle_streams_discovered"] == 1
    assert result["coverage"]["pickle_streams_analyzed"] == 1
    assert result["coverage"]["inventory_truncated"] is False
    assert result["execution"]["required"] is True
    assert result["findings"][0]["id"] == "dangerous_pickle_global"
    assert result["findings"][0]["globals"][0]["global"] == "posix.system"


def test_builtin_pickle_scanner_does_not_call_framework_reconstruction_malicious(tmp_path):
    artifact = tmp_path / "pytorch_model.bin"
    artifact.write_bytes(
        b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00c"
        b"torch\nBFloat16Storage\nq\x01ccollections\nOrderedDict\nq\x02."
    )

    result = scanners.run_builtin_pickle_scan(artifact, _subject())

    assert result["execution"]["status"] == "PASS"
    assert result["summary"]["semantic_classification"] == "expected_framework_pickle"
    assert result["summary"]["capability_only"] is True
    assert {item["severity"] for item in result["findings"]} == {"info"}


def test_builtin_pickle_scanner_detects_stack_global_command_execution(tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"\x80\x04\x8c\x05posix\x8c\x06system\x93.")

    result = scanners.run_builtin_pickle_scan(artifact, _subject())

    assert result["execution"]["status"] == "FAIL"
    assert result["findings"][0]["id"] == "dangerous_pickle_global"
    assert result["findings"][0]["globals"][0]["global"] == "posix.system"


def test_builtin_pickle_scanner_requires_review_for_unknown_global(tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"\x80\x02cacme.model\nCustomTensor\nq\x00.")

    result = scanners.run_builtin_pickle_scan(artifact, _subject())

    assert result["execution"]["status"] == "WARNING"
    assert result["summary"]["semantic_classification"] == "manual_review_required"


def test_builtin_pickle_scanner_marks_oversized_stream_incomplete(monkeypatch, tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"safe")
    monkeypatch.setattr(scanners, "MAX_PICKLE_MEMBER_BYTES", 1)

    result = scanners.run_builtin_pickle_scan(artifact, _subject())

    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["coverage"]["pickle_streams_discovered"] == 1
    assert result["coverage"]["pickle_streams_analyzed"] == 0


def test_builtin_source_scanner_records_dangerous_calls_without_execution(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "modeling.py").write_text(
        "import os\nimport torch\ndef load(path):\n    os.system('echo unsafe')\n    return torch.load(path)\n",
        encoding="utf-8",
    )

    result = scanners.run_builtin_source_scan(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "WARNING"
    calls = {finding["call"] for finding in result["findings"]}
    assert calls == {"os.system", "torch.load"}
    assert result["coverage"]["python_files_discovered"] == 1
    assert result["coverage"]["python_files_analyzed"] == 1
    assert result["coverage"]["inventory_truncated"] is False
    assert result["execution"]["required"] is True


def test_builtin_pickle_scanner_covers_directory_subjects(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "safe.txt").write_text("safe")
    (snapshot / "unsafe.pkl").write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")

    result = scanners.run_builtin_pickle_scan(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "FAIL"
    assert result["coverage"]["files_discovered"] == 2
    assert result["coverage"]["pickle_streams_discovered"] == 1
    assert result["findings"][0]["path"] == "unsafe.pkl"


def test_source_parse_failure_keeps_other_findings_and_fails_closed(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "dangerous.py").write_text("import os\nos.system('id')\n")
    (snapshot / "broken.py").write_text("def broken(:\n")

    result = scanners.run_builtin_source_scan(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["execution"]["required"] is True
    assert {finding["id"] for finding in result["findings"]} == {
        "dangerous_python_call",
        "source_parse_failed",
    }


def test_subject_inventory_truncation_reports_prelimit_counts(monkeypatch, tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "a.txt").write_text("a")
    (snapshot / "b.txt").write_text("b")
    monkeypatch.setattr(scanners, "MAX_SUBJECT_FILES", 1)

    result = scanners.run_builtin_secret_scan(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "INCOMPLETE"
    assert result["coverage"]["files_discovered"] == 2
    assert result["coverage"]["files_enumerated"] == 1
    assert result["coverage"]["inventory_truncated"] is True


def test_large_opaque_weights_are_explicitly_excluded_from_text_secret_scan(monkeypatch, tmp_path):
    weights = tmp_path / "model.safetensors"
    weights.write_bytes(b"\0binary-weights")
    monkeypatch.setattr(scanners, "MAX_SOURCE_FILE_BYTES", 1)

    result = scanners.run_builtin_secret_scan(weights, _subject())

    assert result["execution"]["status"] == "PASS"
    assert result["coverage"]["files_excluded_by_type"] == 1
    assert result["coverage"]["files_skipped_large"] == 0


def test_large_text_files_are_streamed_for_secrets(monkeypatch, tmp_path):
    tokenizer = tmp_path / "tokenizer.json"
    tokenizer.write_bytes(b"x" * 64 + b'\n"token":"AKIAABCDEFGHIJKLMNOP"\n')
    monkeypatch.setattr(scanners, "MAX_SOURCE_FILE_BYTES", 32)

    result = scanners.run_builtin_secret_scan(tokenizer, _subject())

    assert result["execution"]["status"] == "FAIL"
    assert result["coverage"]["files_streamed_large"] == 1
    assert result["coverage"]["files_skipped_large"] == 0
    assert result["findings"][0]["id"] == "aws_access_key"


def test_malware_scan_streams_large_files_without_incomplete_status(monkeypatch, tmp_path):
    weights = tmp_path / "model.safetensors"
    weights.write_bytes(b"A" * 32 + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + b"B" * 32)
    monkeypatch.setattr(scanners, "MAX_PICKLE_MEMBER_BYTES", 1)

    result = scanners.run_builtin_malware_scan(weights, _subject())

    assert result["execution"]["status"] == "FAIL"
    assert result["coverage"]["files_analyzed"] == 1
    assert result["findings"][0]["id"] == "eicar_test_file"


def test_materialize_snapshot_tree_preserves_paths_and_rejects_collision(tmp_path):
    quarantine = tmp_path / "quarantine"
    payload = b"source"
    digest = hashlib.sha256(payload).hexdigest()
    object_path = quarantine / "sha256" / digest[:2] / digest
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(payload)
    snapshot = {"files": [{"path": "nested/modeling.py", "sha256": digest}]}

    root = scanners.materialize_snapshot_tree(snapshot, quarantine, tmp_path / "view")

    target = root / "nested" / "modeling.py"
    assert target.read_bytes() == payload
    assert os.stat(target).st_ino != os.stat(object_path).st_ino
    assert target.stat().st_mode & 0o777 == 0o444

    collision = {
        "files": [
            {"path": "Model.py", "sha256": digest},
            {"path": "model.py", "sha256": digest},
        ]
    }
    try:
        scanners.materialize_snapshot_tree(collision, quarantine, tmp_path / "collision")
    except ValueError as exc:
        assert "case-colliding" in str(exc)
    else:
        raise AssertionError("expected a case-colliding snapshot to be rejected")


def test_generated_evidence_digest_changes_with_status():
    subject = _subject()
    first = scanners._scanner_result(
        name="test",
        version="1",
        status="PASS",
        subject=subject,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )
    second = scanners._scanner_result(
        name="test",
        version="1",
        status="FAIL",
        subject=subject,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
    )

    assert first["evidence_sha256"] != second["evidence_sha256"]
    assert scanners.generated_evidence_summary([first])["statuses"] == {"test": "PASS"}


def test_builtin_secret_scanner_hashes_matches_without_disclosing_values(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    secret = "AKIAABCDEFGHIJKLMNOP"
    (snapshot / "config.py").write_text(f"API_KEY='{secret}'\n", encoding="utf-8")

    result = scanners.run_builtin_secret_scan(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "FAIL"
    assert result["execution"]["required"] is True
    assert any(item["id"] == "aws_access_key" for item in result["findings"])
    assert secret not in str(result)


def test_builtin_malware_scanner_detects_eicar_marker(tmp_path):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    result = scanners.run_builtin_malware_scan(artifact, _subject())

    assert result["execution"]["status"] == "FAIL"
    assert result["findings"][0]["id"] == "eicar_test_file"


def test_builtin_sbom_scanner_generates_digest_bound_cyclonedx(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "requirements.txt").write_text("transformers==4.57.0\nnumpy>=2\n", encoding="utf-8")

    result = scanners.run_builtin_sbom_scan(snapshot, _subject(kind="repository_snapshot"))
    sbom = result["summary"]["sbom"]

    assert result["execution"]["status"] == "WARNING"
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["provenance_class"] == "shakerscan_generated"
    assert sbom["subject_digest"] == _subject()["digest"]
    assert sbom["components"][0]["purl"] == "pkg:pypi/transformers@4.57.0"


def test_builtin_binary_inventory_records_native_executables(tmp_path):
    artifact = tmp_path / "extension.so"
    artifact.write_bytes(b"\x7fELF" + b"\0" * 32)

    result = scanners.run_builtin_binary_inventory(artifact, _subject())

    assert result["execution"]["status"] == "WARNING"
    assert result["findings"][0]["format"] == "elf"


def test_builtin_license_inventory_identifies_license_and_binds_file_digest(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "LICENSE").write_text(
        "MIT License\nCopyright 2026 Example Corp\nPermission is hereby granted, free of charge, to any person obtaining a copy",
        encoding="utf-8",
    )

    result = scanners.run_builtin_license_inventory(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "PASS"
    assert result["summary"]["licenses"][0]["spdx_candidates"] == ["MIT"]
    assert len(result["summary"]["licenses"][0]["sha256"]) == 64
    assert result["summary"]["licenses"][0]["copyright_notices"] == ["Copyright 2026 Example Corp"]


def test_builtin_license_inventory_distinguishes_bsd_and_reciprocal_families(tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "LICENSE-BSD").write_text(
        "Redistribution and use in source and binary forms are permitted. Neither the name of Acme",
        encoding="utf-8",
    )
    (snapshot / "COPYING").write_text(
        "GNU Affero General Public License Version 3",
        encoding="utf-8",
    )

    result = scanners.run_builtin_license_inventory(snapshot, _subject(kind="repository_snapshot"))
    inventory = {item["path"]: item["spdx_candidates"] for item in result["summary"]["licenses"]}

    assert inventory["LICENSE-BSD"] == ["BSD-3-Clause"]
    assert inventory["COPYING"] == ["AGPL-3.0-only"]


def test_materialized_converted_snapshot_is_rescanned_as_exact_safe_subject(monkeypatch, tmp_path):
    snapshot = tmp_path / "converted"
    snapshot.mkdir()
    (snapshot / "model.safetensors").write_bytes(b"safe")
    (snapshot / "config.json").write_text('{"model_type":"bert"}')
    monkeypatch.setattr(scanners, "resolve_scanner_plan", lambda *_args, **_kwargs: [])

    result = scanners.scan_materialized_snapshot(
        snapshot,
        artifact_relative_path="model.safetensors",
        snapshot_sha256="a" * 64,
    )

    assert result["status"] == "REVIEW_REQUIRED"
    assert result["statuses"]["python-pickletools"] == "NOT_APPLICABLE"
    assert all(
        item["subject"]["digest"] == "sha256:" + "a" * 64
        for item in result["results"]
    )


def test_materialized_snapshot_scans_legacy_alternates_when_safetensors_is_selected(monkeypatch, tmp_path):
    snapshot = tmp_path / "mixed"
    snapshot.mkdir()
    (snapshot / "model.safetensors").write_bytes(b"safe")
    # Protocol 0 is a small, valid pickle stream and proves the built-in scan
    # receives the repository rather than only the preferred safetensors file.
    (snapshot / "pytorch_model.bin").write_bytes(b"(dp0\nVweight\np1\nI1\ns.")
    modelscan = next(spec for spec in scanners.EXTERNAL_SCANNERS if spec.name == "modelscan")
    observed_paths = []

    def fake_plan(path, **kwargs):
        if kwargs.get("evidence_scope") == "dependency_evidence":
            return []
        return [{
            "spec": modelscan,
            "applicable": True,
            "files_considered": 2,
            "reason": "serialized_model_artifact_present",
        }]

    def fake_external(spec, path, subject):
        observed_paths.append(path)
        now = scanners._utc_iso()
        return scanners._scanner_result(
            name=spec.name,
            version="test",
            status="PASS",
            subject=subject,
            started_at=now,
            finished_at=now,
            execution={"required": False},
        )

    monkeypatch.setattr(scanners, "resolve_scanner_plan", fake_plan)
    monkeypatch.setattr(scanners, "run_external_scanner", fake_external)

    result = scanners.scan_materialized_snapshot(
        snapshot,
        artifact_relative_path="model.safetensors",
        snapshot_sha256="c" * 64,
        profile="baseline",
    )

    assert observed_paths == [snapshot.resolve()]
    assert result["statuses"]["python-pickletools"] == "PASS"


def test_materialized_converted_snapshot_rescan_blocks_unchanged_dangerous_code(monkeypatch, tmp_path):
    snapshot = tmp_path / "converted"
    snapshot.mkdir()
    (snapshot / "model.safetensors").write_bytes(b"safe")
    (snapshot / "modeling.py").write_text("import os\nos.system('id')\n")
    monkeypatch.setattr(scanners, "resolve_scanner_plan", lambda *_args, **_kwargs: [])

    result = scanners.scan_materialized_snapshot(
        snapshot,
        artifact_relative_path="model.safetensors",
        snapshot_sha256="b" * 64,
    )

    assert result["status"] == "FAIL"
    assert result["statuses"]["python-ast-security"] == "WARNING"
    assert any(
        finding.get("severity") == "high"
        for item in result["results"]
        for finding in item.get("findings") or []
    )


def test_secret_scanner_status_survives_redaction():
    """A scanner's control state must stay readable in the exported summary.

    ``shakerscan-secret-rules`` matches the shared sensitive-key fragment
    matcher, so the generic redactor masked its ``PASS`` to ``***`` and an
    operator could not tell whether the secret scan had run at all.
    """
    from scanner.scanner_tools.model_intake import redact_generated_evidence

    evidence = {
        "statuses": {
            "shakerscan-secret-rules": "PASS",
            "semgrep": "WARNING",
            "shakerscan-malware-rules": "PASS",
        },
        "results": [
            {
                "scanner": {"name": "shakerscan-secret-rules"},
                "findings": [{"secret": "hunter2", "path": "config.json"}],
            }
        ],
    }

    redacted = redact_generated_evidence(evidence)

    assert redacted["statuses"]["shakerscan-secret-rules"] == "PASS"
    assert redacted["statuses"]["semgrep"] == "WARNING"
    assert redacted["statuses"]["shakerscan-malware-rules"] == "PASS"
    # A matched secret inside a finding is still masked.
    assert redacted["results"][0]["findings"][0]["secret"] == "***"
    assert redacted["results"][0]["findings"][0]["path"] == "config.json"


def test_a_status_outside_the_normalized_vocabulary_stays_redacted():
    """Restoring is limited to the closed control-state vocabulary."""
    from scanner.scanner_tools.model_intake import redact_generated_evidence

    redacted = redact_generated_evidence(
        {"statuses": {"shakerscan-secret-rules": "sk-live-abcdef0123456789"}}
    )

    assert redacted["statuses"]["shakerscan-secret-rules"] == "***"


def test_dependency_inventory_covers_the_manifests_model_repositories_actually_ship():
    # The inventory read requirements*.txt and package-lock.json only, and
    # matched pyproject.toml without having a parser for it — so a Poetry or
    # conda repository produced an empty, clean-looking SBOM.
    import json as _json
    import tempfile
    from pathlib import Path as _Path

    from scanner.scanner_tools.model_intake_scanners import (
        _is_dependency_file,
        _requirement_components,
    )

    root = _Path(tempfile.mkdtemp())
    cases = {
        "requirements.txt": ("transformers==4.44.0\ntorch>=2.0\n", {"pkg:pypi/transformers@4.44.0"}),
        "requirements-train.txt": ("accelerate==0.34.0\n", {"pkg:pypi/accelerate@0.34.0"}),
        "pyproject.toml": (
            '[project]\nname="m"\ndependencies=["safetensors==0.4.5"]\n'
            '[tool.poetry.dependencies]\npython="^3.10"\neinops="0.8.0"\n',
            {"pkg:pypi/safetensors@0.4.5", "pkg:pypi/einops@0.8.0"},
        ),
        "poetry.lock": ('[[package]]\nname="tqdm"\nversion="4.66.5"\n', {"pkg:pypi/tqdm@4.66.5"}),
        "Pipfile.lock": (
            _json.dumps({"default": {"sentencepiece": {"version": "==0.2.0"}}}),
            {"pkg:pypi/sentencepiece@0.2.0"},
        ),
        "setup.cfg": ("[options]\ninstall_requires =\n    scipy==1.14.1\n", {"pkg:pypi/scipy@1.14.1"}),
        "environment.yml": (
            "dependencies:\n  - numpy=1.26.4\n  - pip:\n    - transformers==4.44.0\n",
            {"pkg:conda/numpy@1.26.4", "pkg:pypi/transformers@4.44.0"},
        ),
        "package.json": (_json.dumps({"dependencies": {"onnxruntime": "1.19.2"}}), {"pkg:npm/onnxruntime@1.19.2"}),
        "package-lock.json": (
            _json.dumps({"packages": {"node_modules/ws": {"name": "ws", "version": "8.18.0"}}}),
            {"pkg:npm/ws@8.18.0"},
        ),
        "yarn.lock": ('"lodash@^4.0.0":\n  version "4.17.21"\n', {"pkg:npm/lodash@4.17.21"}),
    }
    for name, (body, expected) in cases.items():
        assert _is_dependency_file(name), f"{name} is not recognized as a dependency manifest"
        path = root / name
        path.write_text(body)
        components, _ = _requirement_components(path)
        assert expected <= {item["purl"] for item in components}, name


def test_version_ranges_are_reported_unpinned_rather_than_invented():
    import json as _json
    import tempfile
    from pathlib import Path as _Path

    from scanner.scanner_tools.model_intake_scanners import _requirement_components

    root = _Path(tempfile.mkdtemp())
    # A caret/tilde/inequality range is not a pin. Recording one as a concrete
    # version would put a component in the SBOM that is not what ships.
    for name, body in (
        ("requirements.txt", "torch>=2.0\n"),
        ("package.json", _json.dumps({"dependencies": {"react": "^18.0.0"}})),
        ("pyproject.toml", '[tool.poetry.dependencies]\nnumpy="^1.26"\n'),
    ):
        path = root / name
        path.write_text(body)
        components, unpinned = _requirement_components(path)
        assert components == [], name
        assert unpinned, name


def test_dependency_manifests_are_never_executed_and_stay_bounded():
    import tempfile
    from pathlib import Path as _Path

    from scanner.scanner_tools.model_intake_scanners import (
        MAX_DEPENDENCY_FILE_BYTES,
        _requirement_components,
    )

    root = _Path(tempfile.mkdtemp())
    # setup.py is deliberately not a supported manifest: parsing it safely is
    # possible but reading it is not, and executing it never is.
    from scanner.scanner_tools.model_intake_scanners import _is_dependency_file
    assert not _is_dependency_file("setup.py")

    oversized = root / "requirements.txt"
    oversized.write_text("a==1\n" * (MAX_DEPENDENCY_FILE_BYTES // 5 + 10))
    components, notes = _requirement_components(oversized)
    assert components == []
    assert notes == ["requirements.txt:file_too_large"]

    malformed = root / "pyproject.toml"
    malformed.write_text("[project\nbroken")
    components, notes = _requirement_components(malformed)
    assert components == []
    assert notes == ["pyproject.toml:parse_error"]
