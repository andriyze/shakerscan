import asyncio
import inspect
import json
import os
import sys
import threading
import time
import types
from pathlib import Path

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))
import broker_worker  # noqa: E402
sys.path.pop(0)


NODE_ID = "11111111-1111-4111-8111-111111111111"


def test_broker_state_requires_owner_only_https_but_not_data_store_credentials(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "node_id": NODE_ID,
        "node_credential": "ssn_secret",
        "control_plane_url": "https://fleet.example.test",
        "transport": "broker",
    }), encoding="utf-8")
    state_path.chmod(0o600)
    state = broker_worker.load_state(state_path)
    assert "REDIS_URL" not in state
    assert "DATABASE_URL" not in state

    state_path.chmod(0o644)
    with pytest.raises(broker_worker.BrokerWorkerError, match="owner-only"):
        broker_worker.load_state(state_path)


def test_broker_state_rejects_non_https_control_plane(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "node_id": NODE_ID,
        "node_credential": "ssn_secret",
        "control_plane_url": "http://fleet.example.test",
        "transport": "broker",
    }), encoding="utf-8")
    state_path.chmod(0o600)
    with pytest.raises(broker_worker.BrokerWorkerError, match="HTTPS"):
        broker_worker.load_state(state_path)


def test_worker_runtime_identity_includes_unique_container(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "abcdef1234567890")
    monkeypatch.setenv("WORKER_ID", "node-1-broker")

    assert broker_worker.worker_runtime_identity() == "node-1-broker:abcdef123456"
    assert broker_worker.worker_runtime_identity("node-1-broker:abcdef123456") == "node-1-broker:abcdef123456"


def test_broker_state_has_explicit_ca_modes_and_clear_errors(tmp_path):
    state_path = tmp_path / "state.json"
    base = {
        "node_id": NODE_ID,
        "node_credential": "ssn_secret",
        "control_plane_url": "https://fleet.example.test",
        "transport": "broker",
    }
    state_path.write_text(json.dumps({**base, "tls_ca_mode": "file"}), encoding="utf-8")
    state_path.chmod(0o600)
    with pytest.raises(broker_worker.BrokerWorkerError, match="requires ca_cert_path"):
        broker_worker.load_state(state_path)

    state_path.write_text(json.dumps({**base, "tls_ca_mode": "system"}), encoding="utf-8")
    assert broker_worker.load_state(state_path)["tls_ca_mode"] == "system"


def test_broker_artifact_centralization_rewrites_only_results_files(tmp_path, monkeypatch):
    results = tmp_path / "results"
    results.mkdir()
    screenshot = results / "shot.png"
    screenshot.write_bytes(b"png")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(broker_worker, "RESULTS_DIR", results)

    uploads = []

    async def fake_to_thread(_func, *_args, **kwargs):
        path = kwargs["path"]
        uploads.append(kwargs)
        return {"url": "/scans/scan/artifacts/one", "content_sha256": "ignored"}

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)
    result = asyncio.run(broker_worker.centralize_result_artifacts(
        {},
        lease_id="lease",
        lease_token="token",
        result={"screenshot": str(screenshot), "outside": str(outside)},
    ))
    assert result["screenshot"] == "/scans/scan/artifacts/one"
    assert result["outside"] == str(outside)
    assert len(uploads) == 1


def test_broker_compose_has_no_redis_or_postgres_configuration():
    compose = Path(__file__).resolve().parents[1] / "docker-compose.broker-worker.yml"
    text = compose.read_text(encoding="utf-8")
    assert "broker_worker.py" in text
    assert "REDIS_URL" not in text
    assert "DATABASE_URL" not in text
    assert "postgres:" not in text
    assert "redis:" not in text


def test_broker_execution_uses_https_checkpoint_upload_not_local_database_manifest():
    source = inspect.getsource(broker_worker.execute_lease)

    assert "persist_checkpoint_artifacts=False" in source
    assert 'artifact_type="checkpoint"' in source


def test_broker_heartbeat_survives_a_blocked_scanner_event_loop(tmp_path, monkeypatch):
    calls = []
    cancelled = []
    done = threading.Event()
    live = {"phase": "model_intake", "progress": 5, "log_lines": ["acquiring"]}
    lock = threading.Lock()
    failures = []

    def fake_request(_state, method, path, payload, **_kwargs):
        calls.append((method, path, payload))
        return {"cancel_requested": False}

    monkeypatch.setattr(broker_worker, "api_request", fake_request)
    monkeypatch.setattr(broker_worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(broker_worker, "_signal_scanner_cancel_file", cancelled.append)
    thread = threading.Thread(
        target=broker_worker._heartbeat_lease_until_done,
        kwargs={
            "state": {},
            "node_id": NODE_ID,
            "lease_id": "lease-id",
            "lease_token": "lease-token",
            "scan_id": "scan-id",
            "heartbeat_interval": 0.01,
            "done": done,
            "live": live,
            "live_lock": lock,
            "lease_failed": failures,
        },
    )
    thread.start()

    # Model Intake and parser work can block the asyncio thread. A native heartbeat
    # thread must continue renewing authority during that interval.
    time.sleep(0.045)
    done.set()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert len(calls) >= 2
    assert calls[0][2]["phase"] == "model_intake"
    assert calls[0][2]["log_lines"] == ["acquiring"]
    assert calls[1][2]["log_lines"] == []
    assert failures == []
    assert cancelled == []


def test_broker_heartbeat_retries_transient_5xx_and_preserves_logs(tmp_path, monkeypatch):
    calls = []
    cancelled = []
    done = threading.Event()
    live = {"phase": "scan", "progress": 20, "log_lines": ["still working"]}
    failures = []

    def fake_request(_state, _method, _path, payload, **_kwargs):
        calls.append(payload)
        if len(calls) == 1:
            raise broker_worker.BrokerHTTPError(503, "maintenance")
        done.set()
        return {"cancel_requested": False}

    monkeypatch.setattr(broker_worker, "api_request", fake_request)
    monkeypatch.setattr(broker_worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(broker_worker, "_signal_scanner_cancel_file", cancelled.append)

    broker_worker._heartbeat_lease_until_done(
        {}, node_id=NODE_ID, lease_id="lease", lease_token="token", scan_id="scan",
        heartbeat_interval=0.005, failure_grace_seconds=0.1, request_timeout=1,
        done=done, live=live, live_lock=threading.Lock(), lease_failed=failures,
    )

    assert len(calls) == 2
    assert calls[1]["log_lines"] == ["still working"]
    assert failures == []
    assert cancelled == []


def test_broker_heartbeat_fails_closed_on_lost_authority(tmp_path, monkeypatch):
    cancelled = []
    failures = []

    def rejected(*_args, **_kwargs):
        raise broker_worker.BrokerHTTPError(409, "lease no longer active")

    monkeypatch.setattr(broker_worker, "api_request", rejected)
    monkeypatch.setattr(broker_worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(broker_worker, "_signal_scanner_cancel_file", cancelled.append)

    broker_worker._heartbeat_lease_until_done(
        {}, node_id=NODE_ID, lease_id="lease", lease_token="token", scan_id="scan",
        heartbeat_interval=0.001, failure_grace_seconds=1, request_timeout=1,
        done=threading.Event(), live={}, live_lock=threading.Lock(), lease_failed=failures,
    )

    assert len(failures) == 1
    assert failures[0].startswith("terminal:")
    assert cancelled == [str(tmp_path / "scan_cancel")]


def test_broker_heartbeat_honors_control_plane_cancel(tmp_path, monkeypatch):
    cancelled = []
    done = threading.Event()
    calls = {"count": 0}

    def cancel_requested(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] > 1:
            done.set()
            return {"cancel_requested": False}
        return {"cancel_requested": True}

    monkeypatch.setattr(broker_worker, "api_request", cancel_requested)
    monkeypatch.setattr(broker_worker, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(broker_worker, "_signal_scanner_cancel_file", cancelled.append)

    broker_worker._heartbeat_lease_until_done(
        {}, node_id=NODE_ID, lease_id="lease", lease_token="token", scan_id="scan",
        heartbeat_interval=0.001, failure_grace_seconds=1, request_timeout=1,
        done=done, live={}, live_lock=threading.Lock(), lease_failed=[],
    )

    assert cancelled == [str(tmp_path / "scan_cancel")]
