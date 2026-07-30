import hashlib
import os

from scanner.scanner_tools import model_intake_scanners as scanners


def _subject(digest="a" * 64, kind="model_artifact"):
    return {"kind": kind, "digest": f"sha256:{digest}", "complete": True}


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
        "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy",
        encoding="utf-8",
    )

    result = scanners.run_builtin_license_inventory(snapshot, _subject(kind="repository_snapshot"))

    assert result["execution"]["status"] == "PASS"
    assert result["summary"]["licenses"][0]["spdx_candidates"] == ["MIT"]
    assert len(result["summary"]["licenses"][0]["sha256"]) == 64


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
