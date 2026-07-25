import json
import os
import sys
from pathlib import Path

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import fleet_agent  # noqa: E402
import fleet_worker_entrypoint  # noqa: E402
sys.path.pop(0)


NODE_ID = "11111111-1111-4111-8111-111111111111"


class FakeDocker:
    def __init__(self):
        self.containers = [self._container("one", 1, "running")]
        self.calls = []

    @staticmethod
    def _container(container_id, number, state):
        return {
            "Id": container_id,
            "State": state,
            "Labels": {
                "com.docker.compose.project": "fleet-test",
                "com.docker.compose.service": "worker",
                "com.docker.compose.container-number": str(number),
                "com.shakerscan.node_id": NODE_ID,
            },
        }

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path.startswith("/containers/json"):
            return 200, [dict(item) for item in self.containers]
        if method == "GET" and path.endswith("/json"):
            container_id = path.split("/")[2]
            item = next(row for row in self.containers if row["Id"] == container_id)
            return 200, {
                "Config": {
                    "Image": "registry/shakerscan@sha256:" + "a" * 64,
                    "Cmd": ["python3", "/app/worker.py"],
                    "Env": ["REDIS_URL=redis://control"],
                    "Labels": dict(item["Labels"]),
                },
                "HostConfig": {
                    "Binds": ["/srv/results:/results:rw"],
                    "NetworkMode": "fleet-net",
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "Privileged": True,  # must not be copied by the allowlist
                },
            }
        if method == "POST" and path.startswith("/containers/create?"):
            number = int(body["Labels"]["com.docker.compose.container-number"])
            container_id = f"created-{number}"
            self.containers.append(self._container(container_id, number, "created"))
            return 201, {"Id": container_id}
        if method == "POST" and path.endswith("/start"):
            container_id = path.split("/")[2]
            next(item for item in self.containers if item["Id"] == container_id)["State"] = "running"
            return 204, {}
        if method == "POST" and "/stop" in path:
            container_id = path.split("/")[2]
            next(item for item in self.containers if item["Id"] == container_id)["State"] = "exited"
            return 204, {}
        if method == "DELETE":
            return 204, {}
        raise AssertionError((method, path, body))


def test_state_file_must_be_owner_only(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"node_id": NODE_ID}), encoding="utf-8")
    state_path.chmod(0o644)
    with pytest.raises(fleet_agent.AgentError, match="owner-only"):
        fleet_agent.load_state(state_path)


def test_state_file_requires_identity_transport_and_ca(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"node_id": NODE_ID}), encoding="utf-8")
    state_path.chmod(0o600)
    with pytest.raises(fleet_agent.AgentError, match="node_credential"):
        fleet_agent.load_state(state_path)


def test_state_file_rejects_non_https_control_plane_and_unpinned_image(tmp_path):
    state_path = tmp_path / "state.json"
    base = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "control_plane_overlay_url": "http://10.77.0.1:8080",
        "ca_cert_path": str(tmp_path / "ca.pem"),
        "worker_image_digest": "registry/shakerscan:latest",
    }
    state_path.write_text(json.dumps(base), encoding="utf-8")
    state_path.chmod(0o600)
    with pytest.raises(fleet_agent.AgentError, match="HTTPS"):
        fleet_agent.load_state(state_path)

    base["control_plane_overlay_url"] = "https://10.77.0.1:8080"
    state_path.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(fleet_agent.AgentError, match="digest-pinned"):
        fleet_agent.load_state(state_path)


def test_worker_reconciliation_scales_up_from_safe_template():
    client = FakeDocker()
    assert fleet_agent.reconcile_workers(client, node_id=NODE_ID, desired_count=3) == 3
    assert sum(item["State"] == "running" for item in client.containers) == 3
    create_bodies = [body for method, path, body in client.calls if method == "POST" and path.startswith("/containers/create?")]
    assert len(create_bodies) == 2
    assert all(body["Labels"]["com.shakerscan.node_id"] == NODE_ID for body in create_bodies)
    assert all("Privileged" not in body["HostConfig"] for body in create_bodies)


def test_worker_reconciliation_scales_down_and_keeps_templates():
    client = FakeDocker()
    client.containers.extend(
        [client._container("two", 2, "running"), client._container("three", 3, "running")]
    )
    assert fleet_agent.reconcile_workers(client, node_id=NODE_ID, desired_count=1) == 1
    assert sum(item["State"] == "running" for item in client.containers) == 1
    assert len(client.containers) == 3


def test_worker_reconciliation_refuses_scale_up_without_template():
    client = FakeDocker()
    client.containers = []
    with pytest.raises(fleet_agent.AgentError, match="no worker template"):
        fleet_agent.reconcile_workers(client, node_id=NODE_ID, desired_count=1)


def test_worker_compose_contains_only_worker_and_agent_services(tmp_path):
    compose = Path(__file__).resolve().parents[1] / "docker-compose.worker.yml"
    text = compose.read_text(encoding="utf-8")
    assert "  worker:" in text
    assert "  node-agent:" in text
    assert "  api:" not in text
    assert "  ui:" not in text
    assert "  postgres:" not in text
    assert "  redis:" not in text
    assert "depends_on:" in text
    assert "FLEET_WORKER_IMAGE must be a digest-pinned scanner image" in text


def test_worker_entrypoint_rejects_unpinned_image_and_invalid_node(monkeypatch):
    monkeypatch.setenv("FLEET_WORKER_IMAGE_DIGEST", "registry/shakerscan:latest")
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", NODE_ID)
    with pytest.raises(RuntimeError, match="digest-pinned"):
        fleet_worker_entrypoint.validate_runtime()

    monkeypatch.setenv("FLEET_WORKER_IMAGE_DIGEST", "registry/shakerscan@sha256:" + "a" * 64)
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", "not-a-uuid")
    with pytest.raises(RuntimeError, match="UUID"):
        fleet_worker_entrypoint.validate_runtime()


def test_control_plane_compose_defines_overlay_tls_edge():
    root = Path(__file__).resolve().parents[1]
    for filename in ("docker-compose.yml", "docker-compose.release.yml"):
        text = (root / filename).read_text(encoding="utf-8")
        assert "  fleet-edge:" in text
        assert 'profiles: ["fleet"]' in text
        assert "FLEET_EDGE_MODE=true" in text
        assert "FLEET_CA_CERT_PATH=/run/shakerscan-fleet/control/ca.crt" in text
        assert "--ssl-keyfile" in text
        assert "--ssl-certfile" in text
