import hashlib
import json

import pytest

from scripts.model_intake_build_oci_layout import build_layout


def test_oci_layout_binds_exact_artifact_snapshot_bundle_and_admission(tmp_path):
    artifact = tmp_path / "model.safetensors"
    snapshot = tmp_path / "snapshot.tar"
    artifact.write_bytes(b"model")
    snapshot.write_bytes(b"snapshot")
    bundle = {
        "bundle_sha256": "a" * 64,
        "model_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "repository_snapshot_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        "target_environment": "production",
    }
    admission = {
        "schema_version": "model-intake-admission/v2",
        "statement_sha256": "b" * 64,
    }
    output = tmp_path / "oci"

    result = build_layout(output, deployment_bundle=bundle, admission_package=admission, artifact=artifact, repository_snapshot=snapshot)

    assert result["layers"] == 4
    assert (output / "oci-layout").exists()
    index = json.loads((output / "index.json").read_text())
    assert index["manifests"][0]["digest"] == result["manifest_digest"]


def test_oci_layout_rejects_artifact_drift(tmp_path):
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes(b"changed")
    with pytest.raises(ValueError, match="does not match"):
        build_layout(
            tmp_path / "oci",
            deployment_bundle={
                "bundle_sha256": "a" * 64,
                "model_artifact_sha256": "b" * 64,
                "repository_snapshot_sha256": "c" * 64,
                "target_environment": "production",
            },
            admission_package={"schema_version": "model-intake-admission/v2"},
            artifact=artifact,
        )
