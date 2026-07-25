import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fleet_acceptance  # noqa: E402
sys.path.pop(0)

from tests.test_job_queue import FakeStreams  # noqa: E402


def test_safe_parallel_endpoints_remain_same_origin_and_bounded():
    endpoints = fleet_acceptance._safe_parallel_endpoints("https://lab.example.test/app", 8)
    assert len(endpoints) == 8
    assert all(item.startswith("https://lab.example.test/") for item in endpoints)
    assert all("#" not in item for item in endpoints)


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


def test_live_lease_probe_reclaims_and_acknowledges_once(monkeypatch):
    class ReclaimingStreams(FakeStreams):
        def xautoclaim(self, name, group, consumer, min_idle_time, start_id, count):
            for state in self.pending.values():
                state["stale"] = True
            return super().xautoclaim(name, group, consumer, min_idle_time, start_id, count)

        def delete(self, *names):
            for name in names:
                self.streams.pop(name, None)
                self.legacy.pop(name, None)

    fake = ReclaimingStreams()
    monkeypatch.setitem(sys.modules, "redis", types.SimpleNamespace(from_url=lambda *_a, **_k: fake))
    monkeypatch.setattr(fleet_acceptance.time, "sleep", lambda _seconds: None)
    result = fleet_acceptance._lease_failure_probe("redis://acceptance.invalid")
    assert result["reclaimed"] is True
    assert result["delivery_attempts"] == 2
    assert result["heartbeat_ok"] is True
    assert result["first_ack"] is True
    assert result["duplicate_ack"] is False


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
