import hashlib
import os
from pathlib import Path
import sys
import uuid

import pytest


API_DIR = Path(__file__).resolve().parents[1] / "api"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

import artifact_storage


def _clear_storage_env(monkeypatch):
    for name in (
        "ARTIFACT_STORAGE_BACKEND",
        "ARTIFACT_STORAGE_REQUIRED",
        "ARTIFACT_S3_PREFIX",
        "ARTIFACT_RETENTION_ATTACHMENT_DAYS",
        "ARTIFACT_RETENTION_CHECKPOINT_DAYS",
        "ARTIFACT_RETENTION_DIAGNOSTIC_DAYS",
        "ARTIFACT_RETENTION_RESULT_DAYS",
        "ARTIFACT_RETENTION_SCREENSHOT_DAYS",
        "EVIDENCE_STORAGE_BACKEND",
        "SHAKERSCAN_NODE_ID",
    ):
        monkeypatch.delenv(name, raising=False)


def test_local_artifact_round_trip_is_deterministic_and_hash_verified(tmp_path, monkeypatch):
    _clear_storage_env(monkeypatch)
    scan_id = str(uuid.uuid4())
    first = artifact_storage.store_bytes(
        b"first",
        results_dir=tmp_path,
        scan_id=scan_id,
        artifact_type="result",
        shard_index=3,
        filename="result.json",
        content_type="application/json",
    )
    second = artifact_storage.store_bytes(
        b"second",
        results_dir=tmp_path,
        scan_id=scan_id,
        artifact_type="result",
        shard_index=3,
        filename="result.json",
        content_type="application/json",
    )

    assert first["storage_uri"] == second["storage_uri"]
    assert f"{scan_id}/shard-3/result/result.json" in second["storage_uri"]
    assert artifact_storage.read_bytes(
        results_dir=tmp_path,
        storage_uri=second["storage_uri"],
        expected_sha256=second["content_sha256"],
    ) == b"second"
    with pytest.raises(artifact_storage.ArtifactStorageError, match="integrity mismatch"):
        artifact_storage.read_bytes(
            results_dir=tmp_path,
            storage_uri=second["storage_uri"],
            expected_sha256=hashlib.sha256(b"first").hexdigest(),
        )


def test_joined_worker_requires_remote_backend(tmp_path, monkeypatch):
    _clear_storage_env(monkeypatch)
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(uuid.uuid4()))
    with pytest.raises(artifact_storage.ArtifactStorageError, match="requires"):
        artifact_storage.store_bytes(
            b"data",
            results_dir=tmp_path,
            scan_id=str(uuid.uuid4()),
            artifact_type="diagnostic",
        )


def test_artifact_uri_rejects_traversal(tmp_path, monkeypatch):
    _clear_storage_env(monkeypatch)
    assert artifact_storage.local_path(tmp_path, "local:scan_artifacts/../../secret") is None
    assert artifact_storage.parse_s3_uri("s3:scan_artifacts/bucket/../../secret") is None
    with pytest.raises(ValueError, match="artifact_type"):
        artifact_storage.object_key(
            scan_id=str(uuid.uuid4()), artifact_type="../result"
        )


def test_retention_policy_is_per_type_and_zero_means_keep(monkeypatch):
    _clear_storage_env(monkeypatch)
    monkeypatch.delenv("ARTIFACT_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("ARTIFACT_RETENTION_RESULT_DAYS", raising=False)
    assert artifact_storage.retention_days("checkpoint") == 14
    assert artifact_storage.retention_days("result") == 365

    monkeypatch.setenv("ARTIFACT_RETENTION_DAYS", "42")
    assert artifact_storage.retention_days("attachment") == 42
    monkeypatch.setenv("ARTIFACT_RETENTION_RESULT_DAYS", "0")
    assert artifact_storage.retention_days("result") is None
