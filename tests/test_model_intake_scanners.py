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


def test_builtin_pickle_scanner_detects_executable_opcodes(tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")

    result = scanners.run_builtin_pickle_scan(artifact, _subject(hashlib.sha256(artifact.read_bytes()).hexdigest()))

    assert result["execution"]["status"] == "FAIL"
    assert result["coverage"] == {"pickle_streams_discovered": 1, "pickle_streams_analyzed": 1}
    assert result["findings"][0]["id"] == "dangerous_pickle_opcodes"
    assert any(item["opcode"] == "GLOBAL" for item in result["findings"][0]["opcodes"])


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
    assert result["coverage"] == {"python_files_discovered": 1, "python_files_analyzed": 1}


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
