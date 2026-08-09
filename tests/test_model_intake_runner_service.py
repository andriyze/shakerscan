import json
import os
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import model_intake_runner_service as runner_service  # noqa: E402
from model_intake_runner_service import DurableRunnerQueue, RunnerJobRequest, _authorize  # noqa: E402


def _request() -> dict:
    digest = "a" * 64
    return {
        "submission_id": "c0fe360d-1184-4c1c-bcc4-efcb6624cd63",
        "environment": "production",
        "subject_path": "/var/lib/shakerscan/model-intake-quarantine/snapshot",
        "repository_manifest_path": "/var/lib/shakerscan/model-intake-quarantine/manifest.json",
        "repository_snapshot_sha256": digest,
        "model_artifact_sha256": digest,
        "tokenizer_sha256": digest,
        "configuration_sha256": digest,
        "deployment_bundle_sha256": digest,
        "runtime_image_digest": f"sha256:{digest}",
        "loader_profile": {"profile_id": "safetensors-transformers-v1", "allow_pickle": False},
        "loader_profile_sha256": digest,
    }


def test_runner_request_rejects_arbitrary_execution_fields():
    request = _request()
    request["command"] = ["/bin/sh", "-c", "id"]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RunnerJobRequest.model_validate(request)


def test_runner_service_authentication_is_fail_closed(monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN", "x" * 40)
    _authorize("x" * 40)
    with pytest.raises(Exception) as denied:
        _authorize("wrong")
    assert denied.value.status_code == 403


def test_runner_health_requires_the_internal_token(monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_INTERNAL_TOKEN", "x" * 40)
    monkeypatch.setattr(runner_service, "firecracker_readiness", lambda: {"ready": True})
    with pytest.raises(Exception) as denied:
        runner_service.health(None)
    assert denied.value.status_code == 403
    assert runner_service.health("x" * 40)["ready"] is True


def test_runner_restart_fails_interrupted_jobs_without_reexecution(tmp_path, monkeypatch):
    job_id = "27a69ab1-a813-44f6-b1aa-b591f5c3c954"
    root = tmp_path / "jobs"
    root.mkdir()
    (root / f"{job_id}.json").write_text(json.dumps({
        "id": job_id,
        "state": "running",
        "request": _request(),
        "result": None,
        "error": None,
    }))
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_JOB_ROOT", str(root))
    monkeypatch.setattr(DurableRunnerQueue, "_loop", lambda self: None)
    queue = DurableRunnerQueue()
    recovered = queue.get(job_id)
    assert recovered["state"] == "failed"
    assert recovered["error"]["code"] == "runner_restarted"
    assert recovered["finished_at"]


def test_runner_job_id_cannot_escape_job_root(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_JOB_ROOT", str(tmp_path))
    monkeypatch.setattr(DurableRunnerQueue, "_loop", lambda self: None)
    queue = DurableRunnerQueue()
    with pytest.raises(Exception) as missing:
        queue.get("../../etc/passwd")
    assert missing.value.status_code == 404


def test_runner_queue_adds_mandatory_bounded_smoke_inputs(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_RUNNER_JOB_ROOT", str(tmp_path))
    monkeypatch.setattr(DurableRunnerQueue, "_loop", lambda self: None)
    queue = DurableRunnerQueue()
    request = RunnerJobRequest.model_validate({**_request(), "known_answer_inputs": ["operator case"]})

    submitted = queue.submit(request)
    stored = queue.get(submitted["id"])["request"]["known_answer_inputs"]

    assert "operator case" in stored
    assert "" in stored
    assert any("東京" in item for item in stored)
    assert any(len(item) > 4000 for item in stored)
