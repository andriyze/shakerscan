import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fleet_acceptance  # noqa: E402
sys.path.pop(0)


def test_default_api_url_uses_persisted_remote_bind(tmp_path, monkeypatch):
    fake_script = tmp_path / "scripts" / "fleet_acceptance.py"
    fake_script.parent.mkdir()
    fake_script.write_text("", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "SHAKERSCAN_BIND_HOST=100.121.87.22\nSHAKERSCAN_API_PORT=9080\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(fleet_acceptance, "__file__", str(fake_script))
    assert fleet_acceptance._local_api_url() == "http://100.121.87.22:9080"

def test_safe_parallel_endpoints_remain_same_origin_and_bounded():
    endpoints = fleet_acceptance._safe_parallel_endpoints("https://lab.example.test/app", 8)
    assert len(endpoints) == 8
    assert all(item.startswith("https://lab.example.test/") for item in endpoints)
    assert all("#" not in item for item in endpoints)


def test_acceptance_target_must_not_be_the_control_plane():
    for target in (
        "http://100.121.87.22:3000",
        "https://fleet.example.test/app",
        "http://127.0.0.1:3000",
    ):
        try:
            fleet_acceptance._validate_external_acceptance_target(
                target,
                (
                    "http://localhost:8080"
                    if "127.0.0.1" in target
                    else "http://100.121.87.22:8080"
                ),
                "fleet.example.test",
            )
        except fleet_acceptance.AcceptanceError as exc:
            assert "separate authorized test application" in str(exc)
        else:
            raise AssertionError("control-plane target was accepted")

    fleet_acceptance._validate_external_acceptance_target(
        "https://lab.example.test",
        "http://100.121.87.22:8080",
        "fleet.example.test",
    )


def test_node_selection_is_explicit_and_rejects_missing_identity():
    payload = {
        "nodes": [
            {"id": "a", "status": "healthy"},
            {"id": "b", "status": "disabled"},
        ]
    }
    assert [item["id"] for item in fleet_acceptance._select_nodes(payload, [])] == ["a"]
    try:
        fleet_acceptance._select_nodes(payload, ["missing"])
    except fleet_acceptance.AcceptanceError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("missing selected node was accepted")


def test_local_build_acceptance_requires_acknowledgement_and_one_uniform_safe_image():
    nodes = [
        {
            "local_build_active": True,
            "image_current": False,
            "active_worker_image_digest": "shakerscan-fleet-local:abc123",
        },
        {
            "local_build_active": True,
            "image_current": False,
            "active_worker_image_digest": "shakerscan-fleet-local:abc123",
        },
    ]
    assert fleet_acceptance._selected_worker_build_mode(
        nodes, allow_local_build=False
    ) == (False, "local-build-development", ["shakerscan-fleet-local:abc123"])
    assert fleet_acceptance._selected_worker_build_mode(
        nodes, allow_local_build=True
    ) == (True, "local-build-development", ["shakerscan-fleet-local:abc123"])

    nodes[1]["active_worker_image_digest"] = "shakerscan-fleet-local:different"
    assert fleet_acceptance._selected_worker_build_mode(
        nodes, allow_local_build=True
    )[0] is False


def test_full_acceptance_routes_scan_to_shared_remote_transport(monkeypatch):
    submitted = []

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, method, path, payload=None, timeout=None):
            if path == "/health":
                return {"status": "healthy"}
            if path == "/fleet/nodes":
                return {
                    "nodes": [
                        {
                            "id": "node-a",
                            "status": "healthy",
                            "last_heartbeat_at": "now",
                            "capacity": {"cpu_count": 2},
                            "state_current": True,
                            "image_current": True,
                            "active_worker_count": 1,
                            "labels": {"transport": "broker"},
                        },
                        {
                            "id": "node-b",
                            "status": "healthy",
                            "last_heartbeat_at": "now",
                            "capacity": {"cpu_count": 2},
                            "state_current": True,
                            "image_current": True,
                            "active_worker_count": 1,
                            "labels": {"transport": "broker"},
                        },
                    ]
                }
            if path.startswith("/artifacts/storage/health"):
                return {"status": "ok"}
            if path == "/fleet/acceptance/lease-probe":
                return {
                    "reclaimed": True,
                    "delivery_attempts": 2,
                    "heartbeat_ok": True,
                    "first_ack": True,
                    "duplicate_ack": False,
                }
            if method == "POST" and path == "/scans":
                submitted.append(payload)
                return {"scan_id": "scan-id", "parallel": True}
            raise AssertionError((method, path, payload, timeout))

    monkeypatch.setattr(fleet_acceptance, "ApiClient", Client)
    monkeypatch.setattr(fleet_acceptance, "_probe_public_data_stores", lambda _host: {6379: True, 5432: True})
    monkeypatch.setattr(fleet_acceptance, "_poll_scan", lambda *_args: {"status": "completed"})
    monkeypatch.setattr(fleet_acceptance, "_evaluate_scan", lambda *_args: None)
    args = types.SimpleNamespace(
        api_url="https://fleet.example.test",
        operator_token="token",
        node_id=[],
        public_host="fleet.example.test",
        preflight_only=False,
        target="https://lab.example.test",
        authorized=True,
        budget_profile="fast",
        request_budget_mode="default",
        fault_node_ssh=None,
        fault_node_id=None,
        allow_local_build=False,
        timeout=60,
        poll_seconds=1,
    )

    fleet_acceptance.run(args)

    assert submitted[0]["options"]["placement"] == {"node_scope": "remote"}
    assert submitted[0]["budget_profile"] == "fast"
    assert "scan_type" not in submitted[0]
    assert "scan_type" not in submitted[0]["options"]
    assert submitted[0]["options"]["request_budget_mode"] == "default"
    assert submitted[0]["options"]["custom_budget"] == {"request_max": 600}


def test_acceptance_request_budget_stays_below_default_domain_cap():
    assert fleet_acceptance._acceptance_request_max(1) == 100
    assert fleet_acceptance._acceptance_request_max(6) == 600
    assert fleet_acceptance._acceptance_request_max(12) == 900


def test_scan_acceptance_requires_cross_node_context_dedupe_report_and_artifacts():
    parent_id = "11111111-1111-4111-8111-111111111111"
    shards = [
        {
            "id": "a",
            "parent_scan_id": parent_id,
            "status": "completed",
            "executing_node_id": "node-a",
            "execution_context": {"credential_scope": "overlay_shared_store", "worker_id": "a:1"},
        },
        {
            "id": "b",
            "parent_scan_id": parent_id,
            "status": "completed",
            "executing_node_id": "node-b",
            "execution_context": {"credential_scope": "broker_job_lease", "worker_id": "b:1"},
        },
    ]

    class Client:
        def request(self, _method, path):
            if path == f"/scans/{parent_id}":
                return {"shards": shards}
            if path == "/scans/a":
                return {"findings": [{"fingerprint": "one"}]}
            if path == "/scans/b":
                return {"findings": [{"fingerprint": "two"}]}
            if path.endswith("/result"):
                return {"result": {"score": 100}}
            if "/artifacts?" in path:
                return {
                    "artifacts": [{"status": "available", "content_sha256": "a" * 64, "size_bytes": 10}]
                }
            raise AssertionError(path)

    checks = []
    fleet_acceptance._evaluate_scan(Client(), parent_id, {"status": "completed"}, checks)
    assert checks
    assert all(item["pass"] for item in checks)


def test_physical_fault_kills_only_attributed_container(monkeypatch):
    node_id = "11111111-1111-4111-8111-111111111111"
    calls = []
    monkeypatch.setattr(
        fleet_acceptance,
        "_all_shards",
        lambda _client, _parent: [{
            "id": "shard-id",
            "status": "running",
            "executing_node_id": node_id,
            "execution_context": {"worker_id": f"node-worker:abcdef123456"},
        }],
    )

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        return types.SimpleNamespace(returncode=0, stdout="abcdef123456\n", stderr="")

    monkeypatch.setattr(fleet_acceptance.subprocess, "run", fake_run)
    class Client:
        def request(self, method, path, payload=None):
            calls.append([method, path, payload])
            return {"status": "draining"}

    result = fleet_acceptance._inject_physical_worker_loss(
        Client(),
        "parent",
        node_id=node_id,
        ssh_target="root@worker-a.example.test",
    )
    assert result["container_id"] == "abcdef123456"
    assert calls == [
        ["PATCH", f"/fleet/nodes/{node_id}/state", {"drain": True}],
        [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "root@worker-a.example.test", "docker", "kill", "abcdef123456",
        ],
    ]


def test_physical_reclaim_counts_fault_and_recovery_nodes():
    parent_id = "11111111-1111-4111-8111-111111111111"
    shard_id = "22222222-2222-4222-8222-222222222222"
    fault = {"scan_id": shard_id, "node_id": "node-a"}
    shards = [{
        "id": shard_id,
        "status": "completed",
        "executing_node_id": "node-b",
        "execution_context": {
            "credential_scope": "broker_job_lease",
            "worker_id": "broker:node-b:abcdef123456",
        },
    }]

    class Client:
        def request(self, _method, path):
            if path == f"/scans/{parent_id}":
                return {"shards": shards}
            if path == f"/scans/{shard_id}":
                return {"findings": []}
            if path == f"/scans/{shard_id}/queue-delivery":
                return {
                    "status": "completed",
                    "executing_node_id": "node-b",
                    "delivery_attempts": 2,
                    "reclaimed": True,
                }
            if path.endswith("/result"):
                return {"result": {"score": 100}}
            if "/artifacts?" in path:
                return {
                    "artifacts": [{"status": "available", "content_sha256": "a" * 64, "size_bytes": 10}]
                }
            raise AssertionError(path)

    checks = []
    fleet_acceptance._evaluate_scan(Client(), parent_id, {"status": "completed"}, checks, fault)

    by_name = {item["name"]: item for item in checks}
    assert by_name["cross_node_shard_execution"]["pass"] is True
    assert by_name["physical_worker_loss_recovered"]["pass"] is True
