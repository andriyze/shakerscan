"""Model Intake scans run on a dedicated worker, isolated from Web DAST slots.

The Model Intake image split moves the artifact toolchain (semgrep, modelscan, trivy, osv-scanner,
...) out of the general scanner image. For a Web DAST worker to stop needing that toolchain, Model
Intake work must route to its own queue and its own worker -- the same isolation the agent-tool
worker already has. These tests pin that routing across the API, the worker, and both compose
stacks so a Web DAST worker can never be handed a Model Intake job it lacks the tools to run.
"""

from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_the_api_routes_model_intake_scans_to_the_dedicated_queue():
    router = (ROOT / "api" / "model_intake" / "router.py").read_text(encoding="utf-8")
    assert 'MODEL_INTAKE_QUEUE_NAME = os.environ.get("MODEL_INTAKE_QUEUE_NAME", "model_intake_jobs")' in router
    # Both the initial scan and the re-check enqueue onto the dedicated queue, never scan_jobs.
    assert router.count("enqueue_job(r, MODEL_INTAKE_QUEUE_NAME, job_data)") == 2
    assert "enqueue_job(r, QUEUE_NAME, job_data)" not in router


def test_the_worker_declares_the_model_intake_role_and_queue():
    worker = (ROOT / "api" / "worker.py").read_text(encoding="utf-8")
    assert 'MODEL_INTAKE_ONLY_WORKER = str(os.environ.get("MODEL_INTAKE_ONLY_WORKER"' in worker
    assert 'MODEL_INTAKE_QUEUE_NAME = os.environ.get("MODEL_INTAKE_QUEUE_NAME", "model_intake_jobs")' in worker
    # The role and queue are threaded through the queue-key selection.
    assert "model_intake_only=MODEL_INTAKE_ONLY_WORKER" in worker
    assert "model_intake_queue=MODEL_INTAKE_QUEUE_NAME" in worker


def _service(compose_path, name):
    return yaml.safe_load(compose_path.read_text(encoding="utf-8"))["services"][name]


def test_both_stacks_run_an_isolated_model_intake_worker():
    for fn in ("docker-compose.yml", "docker-compose.release.yml"):
        compose = ROOT / fn
        services = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]
        assert "model-intake-worker" in services, fn
        env = set(_service(compose, "model-intake-worker")["environment"])
        assert "MODEL_INTAKE_ONLY_WORKER=true" in env, fn
        assert any(e.startswith("MODEL_INTAKE_QUEUE_NAME=") for e in env), fn
        # It must NOT declare a Web DAST role, so it consumes only the Model Intake queue.
        assert "AGENT_TOOL_ONLY_WORKER=true" not in env, fn
        # The worker drives the sandbox file queue and writes evidence, so it mounts results.
        assert any(v.endswith(":/results") for v in _service(compose, "model-intake-worker")["volumes"]), fn
        # It runs the standard worker entrypoint; dispatch by run_kind does the rest.
        assert _service(compose, "model-intake-worker")["command"] == ["python3", "/app/worker.py"], fn


def test_the_model_intake_worker_reuses_an_image_and_owns_no_second_build():
    # A dedicated build block would export the multi-gigabyte image a second time on a clean start.
    for fn in ("docker-compose.yml", "docker-compose.release.yml"):
        service = _service(ROOT / fn, "model-intake-worker")
        assert "build" not in service, fn
        assert isinstance(service.get("image"), str) and service["image"], fn
