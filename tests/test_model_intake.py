import asyncio
import hashlib
import zipfile

from scanner.scanner_tools.model_intake import run_model_intake_scan


def test_model_intake_detects_pickle_and_missing_controls(tmp_path):
    artifact = tmp_path / "unsafe.pkl"
    artifact.write_bytes(b"\x80\x04cposix\nsystem\nq\x00.")

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            {
                "require_deployment_approval": True,
                "metadata_json": {},
            },
        )
    )

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsafe_serialization" in finding_ids
    assert "model_intake:missing_signature" in finding_ids
    assert "model_intake:missing_checksum" in finding_ids
    assert "model_intake:missing_deployment_approval" in finding_ids
    assert result["model_intake"]["summary"]["format_posture"] == "unsafe_executable_serialization"
    assert result["result"]["grade"] == "F"


def test_model_intake_accepts_signed_safetensors_with_provenance(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"safe tensor bytes")
    expected_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = asyncio.run(
        run_model_intake_scan(
            str(artifact),
            {
                "expected_sha256": expected_sha,
                "signature_url": "https://example.test/model.safetensors.sig",
                "model_card_url": "https://example.test/model-card",
                "deployment_approved": True,
                "require_deployment_approval": True,
                "metadata_json": {
                    "source_repo": "https://github.com/example/model",
                    "commit_sha": "abc123",
                    "training_data_ref": "dataset:v1",
                },
            },
        )
    )

    assert result["findings"] == []
    assert result["model_intake"]["summary"]["format_posture"] == "safer_static_format"
    assert result["result"]["grade"] == "A"


def test_model_intake_detects_pickle_and_executable_inside_archive(tmp_path):
    artifact = tmp_path / "bundle.zip"
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("model/data.pkl", b"pickle")
        zf.writestr("scripts/install.sh", b"#!/bin/sh")

    result = asyncio.run(run_model_intake_scan(str(artifact), {"require_deployment_approval": False}))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:unsafe_serialization" in finding_ids
    assert "model_intake:embedded_executable" in finding_ids
    archive = result["model_intake"]["artifact"]["archive"]
    assert "model/data.pkl" in archive["pickle_entries"]
    assert "scripts/install.sh" in archive["executable_entries"]


def test_model_intake_records_fetch_failures_as_findings(tmp_path):
    missing = tmp_path / "missing.safetensors"

    result = asyncio.run(run_model_intake_scan(str(missing), {"require_deployment_approval": False}))

    finding_ids = {finding["id"] for finding in result["findings"]}
    assert "model_intake:artifact_fetch_failed" in finding_ids
    assert result["model_intake"]["artifact"]["fetch"]["error"].startswith("FileNotFoundError")
