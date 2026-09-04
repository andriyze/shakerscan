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
    # Both the initial scan and the re-check enqueue through the one Model Intake boundary,
    # which targets the dedicated queue and never a fleet route; never scan_jobs.
    assert router.count("_enqueue_model_intake_job(r, job_data)") == 2
    assert "enqueue_job(r, MODEL_INTAKE_QUEUE_NAME, job_data)" not in router
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


class _ListRedis:
    """Minimal Redis double: no streams, so enqueue_job takes the RPUSH path."""

    def __init__(self):
        self.pushed = []
        self.routes = []

    def rpush(self, queue, encoded):
        self.pushed.append((queue, encoded))

    def sadd(self, key, member):  # only reached when a placement routes the job
        self.routes.append((key, member))

    def smembers(self, key):
        return set()

    def set(self, key, value):
        pass


def _router_module():
    import importlib
    return importlib.import_module("api.model_intake.router")


def test_model_intake_jobs_are_never_routed_to_a_fleet_placement_queue():
    import json

    router = _router_module()
    redis = _ListRedis()
    job = {
        "job_id": "job-1", "scan_id": "scan-1", "target": "https://models.example/x.safetensors",
        "options": {"policy_profile": "staging", "placement": {"node_id": "remote-node-7"}},
        "placement": {"node_id": "remote-node-7"},
    }
    router._enqueue_model_intake_job(redis, job)
    assert redis.routes == [], "a placement must never create a route queue for Model Intake"
    assert len(redis.pushed) == 1
    queue, encoded = redis.pushed[0]
    assert queue == router.MODEL_INTAKE_QUEUE_NAME
    payload = json.loads(encoded)
    assert "placement" not in payload
    assert "placement" not in payload["options"]
    assert payload["options"]["policy_profile"] == "staging"
    # The caller's dict is left untouched.
    assert job["options"]["placement"] == {"node_id": "remote-node-7"}


def test_rescan_options_drop_a_stored_placement():
    router = _router_module()
    options, receipt, authority = router._prepare_model_intake_rescan_options(
        {"policy_profile": "staging", "placement": {"node_id": "remote-node-7"}, "approval_receipt_id": "r1"}
    )
    assert "placement" not in options
    assert receipt == "r1"
    assert options["run_kind"] == "model_intake"


def test_no_model_intake_request_model_accepts_a_placement():
    router = _router_module()
    from pydantic import BaseModel

    for name in dir(router):
        obj = getattr(router, name)
        if isinstance(obj, type) and issubclass(obj, BaseModel) and name.startswith("ModelIntake"):
            assert "placement" not in obj.model_fields, name
