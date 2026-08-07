import json
import os
import sys
from datetime import datetime, timedelta, timezone
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
    def _container(container_id, number, state, image=None):
        return {
            "Id": container_id,
            "State": state,
            "StartedAt": "2026-08-07T00:00:00Z",
            "ImageName": image or "registry/shakerscan@sha256:" + "a" * 64,
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
                    "Image": item["ImageName"],
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
                "State": {"StartedAt": item["StartedAt"]},
            }
        if method == "POST" and path.startswith("/containers/create?"):
            number = int(body["Labels"]["com.docker.compose.container-number"])
            container_id = f"created-{number}"
            self.containers.append(self._container(container_id, number, "created", body["Image"]))
            return 201, {"Id": container_id}
        if method == "POST" and path.endswith("/start"):
            container_id = path.split("/")[2]
            next(item for item in self.containers if item["Id"] == container_id)["State"] = "running"
            return 204, {}
        if method == "POST" and "/stop" in path:
            container_id = path.split("/")[2]
            next(item for item in self.containers if item["Id"] == container_id)["State"] = "exited"
            return 204, {}
        if method == "POST" and path.startswith("/images/create?"):
            return 200, {}
        if method == "DELETE":
            container_id = path.split("/")[2].split("?")[0]
            self.containers = [item for item in self.containers if item["Id"] != container_id]
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


def test_overlay_state_requires_configured_ca_but_broker_can_use_system_store(tmp_path):
    state_path = tmp_path / "state.json"
    base = {
        "node_id": NODE_ID,
        "node_credential": "node-secret",
        "worker_image_digest": "registry/shakerscan@sha256:" + "a" * 64,
    }
    state_path.write_text(json.dumps({
        **base,
        "control_plane_overlay_url": "https://10.77.0.1:8443",
        "transport": "overlay",
    }), encoding="utf-8")
    state_path.chmod(0o600)
    with pytest.raises(fleet_agent.AgentError, match="fleet CA is not configured"):
        fleet_agent.load_state(state_path)

    state_path.write_text(json.dumps({
        **base,
        "control_plane_url": "https://fleet.example.test",
        "transport": "broker",
        "tls_ca_mode": "system",
    }), encoding="utf-8")
    assert fleet_agent.load_state(state_path)["tls_ca_mode"] == "system"

    local_state = {
        **base,
        "control_plane_url": "https://fleet.example.test",
        "transport": "broker",
        "tls_ca_mode": "system",
        "runtime_image_override": "shakerscan-fleet-local:abc1234",
    }
    state_path.write_text(json.dumps(local_state), encoding="utf-8")
    assert fleet_agent.load_state(state_path)["runtime_image_override"].endswith("abc1234")
    local_state["runtime_image_override"] = "attacker.example/worker:latest"
    state_path.write_text(json.dumps(local_state), encoding="utf-8")
    with pytest.raises(fleet_agent.AgentError, match="local-build image"):
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


def test_observed_worker_image_comes_from_container_not_desired_state():
    client = FakeDocker()
    containers = fleet_agent.worker_containers(client, NODE_ID)
    assert fleet_agent.observed_worker_image(client, containers) == "registry/shakerscan@sha256:" + "a" * 64


def test_run_once_rolls_worker_image_without_stopping_capacity_first(monkeypatch):
    posts = []

    def fake_api(_state, method, _path, payload=None):
        if method == "GET":
            return {
                "desired_worker_count": 1,
                "desired_state_version": 4,
                "applied_state_version": 3,
                "worker_image_digest": "registry/shakerscan@sha256:" + "b" * 64,
                "rollout_in_progress": True,
                "drain": True,
            }
        posts.append(payload)
        return {"id": NODE_ID, "status": "joining"}

    monkeypatch.setattr(fleet_agent, "api_request", fake_api)
    state = {
        "node_id": NODE_ID,
        "worker_image_digest": "registry/shakerscan@sha256:" + "a" * 64,
    }
    client = FakeDocker()
    fleet_agent.run_once(state, client)
    assert posts[0]["applied_state_version"] == 3
    assert posts[0]["active_worker_image_digest"].endswith("b" * 64)
    assert posts[0]["last_error"] is None
    assert posts[0]["rollout_complete"] is False
    create_index = next(i for i, call in enumerate(client.calls) if call[0] == "POST" and call[1].startswith("/containers/create?"))
    stop_index = next(i for i, call in enumerate(client.calls) if call[0] == "POST" and "/stop" in call[1])
    assert create_index < stop_index

    posts.clear()
    fleet_agent.run_once(state, client)
    assert posts[0]["applied_state_version"] == 4
    assert posts[0]["rollout_complete"] is True


def test_run_once_scales_local_build_with_explicit_runtime_override(monkeypatch):
    posts = []
    expected = "registry/shakerscan@sha256:" + "a" * 64
    local_image = "shakerscan-fleet-local:abc1234"

    def fake_api(_state, method, _path, payload=None):
        if method == "GET":
            return {
                "desired_worker_count": 2,
                "desired_state_version": 1,
                "applied_state_version": 0,
                "worker_image_digest": expected,
                "rollout_in_progress": False,
                "drain": False,
            }
        posts.append(payload)
        return {"id": NODE_ID, "status": "healthy"}

    monkeypatch.setattr(fleet_agent, "api_request", fake_api)
    state = {
        "node_id": NODE_ID,
        "worker_image_digest": expected,
        "runtime_image_override": local_image,
    }
    client = FakeDocker()
    client.containers[0]["ImageName"] = local_image
    fleet_agent.run_once(state, client)

    assert len([item for item in client.containers if item["State"] == "running"]) == 2
    assert {item["ImageName"] for item in client.containers} == {local_image}
    assert posts[0]["active_worker_image_digest"] == local_image


def test_drain_workers_keeps_busy_container_running(tmp_path):
    client = FakeDocker()
    client.containers.append(client._container("two", 2, "running"))
    marker_dir = tmp_path / ".fleet-busy"
    marker_dir.mkdir()
    (marker_dir / "one.json").write_text(
        json.dumps({"container_id": "one"}),
        encoding="utf-8",
    )
    busy = fleet_agent.busy_container_ids(tmp_path)
    assert fleet_agent.drain_workers(client, node_id=NODE_ID, busy_ids=busy) == 1
    states = {item["Id"]: item["State"] for item in client.containers}
    assert states == {"one": "running", "two": "exited"}


def test_busy_marker_from_before_container_restart_is_pruned(tmp_path):
    client = FakeDocker()
    client.containers[0]["StartedAt"] = "2026-08-07T00:05:00Z"
    marker_dir = tmp_path / ".fleet-busy"
    marker_dir.mkdir()
    marker = marker_dir / "one.json"
    marker.write_text(
        json.dumps({"container_id": "one", "started_at": "2026-08-07T00:04:00+00:00"}),
        encoding="utf-8",
    )

    busy = fleet_agent.busy_container_ids(tmp_path, client=client, node_id=NODE_ID)

    assert busy == set()
    assert not marker.exists()


def test_rollout_does_not_replace_busy_old_worker():
    client = FakeDocker()
    complete = fleet_agent.rollout_worker_once(
        client,
        node_id=NODE_ID,
        desired_image="registry/shakerscan@sha256:" + "b" * 64,
        desired_count=1,
        busy_ids={"one"},
    )
    assert complete is False
    assert client.containers[0]["State"] == "running"
    assert not any(path.startswith("/containers/create?") for _, path, _ in client.calls)


def test_drain_grace_uses_control_plane_change_time(monkeypatch):
    monkeypatch.setattr(fleet_agent, "DRAIN_GRACE_SECONDS", 45)
    future = datetime.now(timezone.utc) + timedelta(seconds=1)
    old = datetime.now(timezone.utc) - timedelta(seconds=60)
    assert fleet_agent.drain_grace_elapsed({"desired_state_changed_at": future.isoformat()}) is False
    assert fleet_agent.drain_grace_elapsed({"desired_state_changed_at": old.isoformat()}) is True


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
    assert "FLEET_EXPECTED_WORKER_IMAGE_DIGEST is required" in text
    assert "format: raw" in text


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
        assert "network_mode: host" in text
        assert "FLEET_CA_CERT_PATH=/run/shakerscan-fleet/control/ca.crt" in text
        assert "--ssl-keyfile" in text
        assert "--ssl-certfile" in text


def test_control_plane_compose_defines_pinned_opt_in_fleet_gateway():
    root = Path(__file__).resolve().parents[1]
    expected_digest = "sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
    for filename in ("docker-compose.yml", "docker-compose.release.yml"):
        text = (root / filename).read_text(encoding="utf-8")
        assert "  fleet-gateway:" in text
        assert 'profiles: ["fleet-gateway"]' in text
        assert f"caddy:2.11.4-alpine@{expected_digest}" in text
        assert '.shakerscan-fleet/control/Caddyfile:/etc/caddy/Caddyfile:ro' in text
        assert '${FLEET_GATEWAY_BIND_HOST:-0.0.0.0}:80:80' in text
        assert '${FLEET_GATEWAY_BIND_HOST:-0.0.0.0}:443:443' in text
