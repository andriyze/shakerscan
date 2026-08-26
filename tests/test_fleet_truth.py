"""Worker-fleet truth tests (docs proposed-next-steps §3).

The /workers response, scanner.sh status, and the benchmark fleet gate must all
agree about how many workers are real and which run stale code. compute_fleet_summary
is the single pure source of truth they share.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *a, **k):
            pass

        def add_middleware(self, *a, **k):
            return None

        def _decorator(self, *a, **k):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = type("_HTTPExc", (Exception,), {})
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod

    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type(
        "_Resp", (), {"__init__": lambda self, content=None, status_code=200, headers=None: None}
    )
    responses_mod.JSONResponse = responses_mod.Response
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402
from fleet_routes import router as fleet_router_module  # noqa: E402


def _w(name, current, fp="abc", status="running"):
    return {"name": name, "status": status, "build_current": current, "build_fingerprint": fp}


def test_uniform_fleet_is_safe():
    workers = [_w("w1", True), _w("w2", True), _w("w3", True)]
    s = api_module.compute_fleet_summary(workers)
    assert s["count"] == 3
    assert s["current_count"] == 3
    assert s["stale_count"] == 0
    assert s["pending_count"] == 0
    assert s["fleet_uniform"] is True
    assert s["distinct_fingerprints"] == ["abc"]
    assert s["stale_workers"] == []


def test_mixed_fleet_is_not_uniform():
    # 5 current + 11 stale on a different fingerprint == the live failure we hit.
    workers = [_w(f"new{i}", True, "new") for i in range(5)]
    workers += [_w(f"old{i}", False, "old") for i in range(11)]
    s = api_module.compute_fleet_summary(workers)
    assert s["count"] == 16
    assert s["current_count"] == 5
    assert s["stale_count"] == 11
    assert s["fleet_uniform"] is False
    assert set(s["distinct_fingerprints"]) == {"new", "old"}
    assert len(s["stale_workers"]) == 11


def test_pending_worker_blocks_uniformity():
    # A just-restarted worker that has not registered a fingerprint yet.
    workers = [_w("w1", True), _w("w2", None)]
    s = api_module.compute_fleet_summary(workers)
    assert s["pending_count"] == 1
    assert s["fleet_uniform"] is False


def test_non_running_excluded_from_counts():
    workers = [_w("w1", True), _w("dead", False, status="exited")]
    s = api_module.compute_fleet_summary(workers)
    assert s["count"] == 1  # only running counted
    assert s["current_count"] == 1
    # stale_workers still lists the exited stale container for visibility
    assert "dead" in s["stale_workers"]


def test_empty_fleet_not_uniform():
    s = api_module.compute_fleet_summary([])
    assert s["count"] == 0
    assert s["fleet_uniform"] is False


def test_fleet_feature_state_hides_uninitialized_linux_fleet(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HOST_PLATFORM", "linux")
    monkeypatch.delenv("FLEET_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("FLEET_WORKER_IMAGE_DIGEST", raising=False)

    assert api_module.fleet_feature_state() == {
        "enabled": False,
        "configured": False,
        "supported": True,
        "status": "disabled",
        "host_platform": "linux",
        "reason": "Fleet mode has not been initialized on this control plane.",
    }


def test_fleet_feature_state_marks_macos_unsupported(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HOST_PLATFORM", "macos")
    monkeypatch.setenv("FLEET_OPERATOR_TOKEN", "x" * 32)
    monkeypatch.setenv("FLEET_WORKER_IMAGE_DIGEST", "scanner@example")

    state = api_module.fleet_feature_state()

    assert state["enabled"] is False
    assert state["configured"] is True
    assert state["supported"] is False
    assert state["status"] == "unsupported"
    assert state["host_platform"] == "macos"


def test_fleet_feature_state_enables_initialized_linux_control_plane(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HOST_PLATFORM", "linux")
    monkeypatch.setenv("FLEET_OPERATOR_TOKEN", "x" * 32)
    monkeypatch.setenv("FLEET_WORKER_IMAGE_DIGEST", "scanner@example")

    state = api_module.fleet_feature_state()

    assert state["enabled"] is True
    assert state["configured"] is True
    assert state["supported"] is True
    assert state["status"] == "enabled"
    assert state["reason"] is None


def test_execution_capacity_separates_local_remote_and_unavailable_nodes():
    local = {"count": 2, "current_count": 1}
    nodes = [
        {
            "status": "healthy",
            "drain": False,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 3,
        },
        {
            "status": "stale",
            "drain": False,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 4,
        },
        {
            "status": "healthy",
            "drain": True,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 2,
        },
        {
            "status": "disabled",
            "active_worker_count": 9,
        },
    ]

    capacity = api_module.compute_execution_capacity(local, nodes)

    assert capacity == {
        "local_running": 2,
        "local_available": 1,
        "remote_running": 9,
        "remote_available": 3,
        "total_running": 11,
        "total_available": 4,
        "remote_nodes": 3,
        "remote_nodes_available": 1,
        "remote_inventory_available": True,
    }


def test_local_build_remote_node_is_schedulable_but_not_image_current():
    node = {
        "status": "healthy",
        "drain": False,
        "rollout_in_progress": False,
        "state_current": True,
        "image_current": False,
        "local_build_active": True,
        "active_worker_count": 2,
    }

    assert fleet_router_module._fleet_node_is_schedulable(node) is True
    assert api_module.compute_execution_capacity(
        {"count": 1, "current_count": 1},
        [node],
    )["total_available"] == 3


def test_broker_concurrency_uses_remote_workers_not_control_plane_capacity():
    nodes = [
        {
            "status": "healthy",
            "drain": False,
            "rollout_in_progress": False,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 2,
            "labels": {"transport": "broker"},
        },
        {
            "status": "healthy",
            "drain": False,
            "rollout_in_progress": False,
            "state_current": True,
            "image_current": False,
            "local_build_active": True,
            "active_worker_count": 3,
            "labels": {"transport": "broker"},
        },
        {
            "status": "healthy",
            "drain": False,
            "rollout_in_progress": False,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 7,
            "labels": {"transport": "overlay"},
        },
        {
            "status": "healthy",
            "drain": True,
            "rollout_in_progress": False,
            "state_current": True,
            "image_current": True,
            "active_worker_count": 11,
            "labels": {"transport": "broker"},
        },
    ]

    assert fleet_router_module._compute_broker_active_scan_cap(nodes) == 5
    assert fleet_router_module._compute_broker_active_scan_cap(nodes, override="3") == 3
    assert fleet_router_module._compute_broker_active_scan_cap(nodes, override="20") == 5
    assert fleet_router_module._compute_broker_active_scan_cap([], override="20") == 1


def test_unexplained_image_drift_remote_node_is_not_schedulable():
    node = {
        "status": "healthy",
        "drain": False,
        "rollout_in_progress": False,
        "state_current": True,
        "image_current": False,
        "local_build_active": False,
        "active_worker_count": 2,
    }

    assert fleet_router_module._fleet_node_is_schedulable(node) is False


def test_worker_freshness_snapshot_marks_running_pending_as_unsafe(monkeypatch):
    labels = {
        "com.docker.compose.project": "shakerscan",
        "com.docker.compose.service": "worker",
    }
    containers = [
        {"Id": "aaa111", "Names": ["/shakerscan-worker-1"], "State": "running", "Labels": labels},
        {"Id": "bbb222", "Names": ["/shakerscan-worker-2"], "State": "running", "Labels": labels},
        {"Id": "ccc333", "Names": ["/shakerscan-worker-3"], "State": "running", "Labels": labels},
        {"Id": "ddd444", "Names": ["/shakerscan-worker-old"], "State": "exited", "Labels": labels},
    ]

    class _Redis:
        def hgetall(self, key):
            assert key == "shakerscan:worker_build"
            return {
                b"aaa": b'{"build_fingerprint":"fp-current","scanner_version":"v1"}',
                b"ccc": b'{"build_fingerprint":"fp-old","scanner_version":"v1"}',
                b"ddd": b'{"build_fingerprint":"fp-old","scanner_version":"v1"}',
            }

    monkeypatch.setattr(api_module, "docker_socket_request", lambda *a, **k: (200, containers))
    monkeypatch.setattr(api_module, "_local_compose_project_best_effort", lambda: "shakerscan")
    monkeypatch.setattr(api_module, "get_redis", lambda: _Redis())
    monkeypatch.setattr(api_module, "expected_build_fingerprint", lambda: "fp-current")
    monkeypatch.setattr(api_module, "current_scanner_version", lambda: "v1")

    snap = api_module._worker_freshness_snapshot()

    assert snap["available"] is True
    assert snap["fleet_size"] == 4
    assert snap["running"] == 3
    assert snap["current_count"] == 1
    assert snap["stale_count"] == 1
    assert snap["stale_names"] == ["shakerscan-worker-3"]
    assert snap["pending_count"] == 1
    assert snap["pending_names"] == ["shakerscan-worker-2"]


def test_worker_freshness_snapshot_excludes_colocated_fleet_workers(monkeypatch):
    containers = [
        {
            "Id": "aaa111",
            "Names": ["/shakerscan-worker-1"],
            "State": "running",
            "Labels": {
                "com.docker.compose.project": "shakerscan",
                "com.docker.compose.service": "worker",
            },
        },
        {
            "Id": "fleet111",
            "Names": ["/shakerscan-fleet-deadbeef-worker-1"],
            "State": "running",
            "Labels": {
                "com.docker.compose.project": "shakerscan-fleet-deadbeef",
                "com.docker.compose.service": "worker",
            },
        },
    ]

    class _Redis:
        def hgetall(self, key):
            assert key == "shakerscan:worker_build"
            return {
                b"aaa": b'{"build_fingerprint":"fp-current","scanner_version":"v1"}',
                b"fleet": b'{"build_fingerprint":"fp-other","scanner_version":"v0"}',
            }

    monkeypatch.setattr(api_module, "docker_socket_request", lambda *a, **k: (200, containers))
    monkeypatch.setattr(api_module, "get_redis", lambda: _Redis())
    monkeypatch.setattr(api_module, "expected_build_fingerprint", lambda: "fp-current")
    monkeypatch.setattr(api_module, "current_scanner_version", lambda: "v1")
    monkeypatch.setattr(api_module, "_local_compose_project_best_effort", lambda: "shakerscan")

    snap = api_module._worker_freshness_snapshot()

    assert snap["fleet_size"] == 1
    assert snap["running"] == 1
    assert snap["current_count"] == 1
    assert snap["stale_count"] == 0
    assert snap["pending_count"] == 0
