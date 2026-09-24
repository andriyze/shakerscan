"""The sandbox identity the launcher records reaches every service that must honour it."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _service(compose, name):
    return yaml.safe_load((ROOT / compose).read_text(encoding="utf-8"))["services"][name]


def test_every_worker_that_can_acquire_learns_the_configured_sandbox_group():
    # On a clean install the artifact acquisition of an automatic review ran on a general
    # DAST worker (worker-16), not the model-intake worker, so both must know the group.
    for compose in ("docker-compose.yml", "docker-compose.release.yml"):
        for service in ("model-intake-worker", "worker"):
            env = _service(compose, service)["environment"]
            assert "MODEL_INTAKE_SANDBOX_GID=${MODEL_INTAKE_SANDBOX_GID:-10001}" in env, (compose, service)
            assert "MODEL_INTAKE_SANDBOX_UID=${MODEL_INTAKE_SANDBOX_UID:-10001}" in env, (compose, service)


def test_the_release_api_can_read_the_quarantine_it_stages_for_the_runner():
    # A root install keeps the API at 10002 and the sandbox at 10001; without the sandbox
    # group the API cannot traverse the quarantine and prepare_isolated_runtime fails with EACCES.
    api = _service("docker-compose.release.yml", "api")
    assert "${MODEL_INTAKE_SANDBOX_GID:-10001}" in [str(item) for item in api.get("group_add", [])]
