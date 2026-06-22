"""Worker-fleet truth tests (docs proposed-next-steps §3).

The /workers response, scanner.sh status, and the benchmark fleet gate must all
agree about how many workers are real and which run stale code. compute_fleet_summary
is the single pure source of truth they share.
"""

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

sys.modules.setdefault("asyncpg", types.SimpleNamespace())
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

        get = post = patch = put = delete = on_event = _decorator

    fastapi_mod.FastAPI = _FakeFastAPI
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
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402


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


def test_worker_freshness_snapshot_marks_running_pending_as_unsafe(monkeypatch):
    containers = [
        {"Id": "aaa111", "Names": ["/shakerscan-worker-1"], "State": "running"},
        {"Id": "bbb222", "Names": ["/shakerscan-worker-2"], "State": "running"},
        {"Id": "ccc333", "Names": ["/shakerscan-worker-3"], "State": "running"},
        {"Id": "ddd444", "Names": ["/shakerscan-worker-old"], "State": "exited"},
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
    monkeypatch.setattr(api_module, "get_redis", lambda: _Redis())
    monkeypatch.setattr(api_module, "expected_build_fingerprint", lambda: "fp-current")
    monkeypatch.setattr(api_module, "current_scanner_version", lambda: "v1")

    snap = api_module._worker_freshness_snapshot()

    assert snap["available"] is True
    assert snap["fleet_size"] == 4
    assert snap["running"] == 3
    assert snap["stale_count"] == 1
    assert snap["stale_names"] == ["shakerscan-worker-3"]
    assert snap["pending_count"] == 1
    assert snap["pending_names"] == ["shakerscan-worker-2"]
