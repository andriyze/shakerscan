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
from scan.action_plan import ScanAction, ScanActionPlan  # noqa: E402
from scan.continuation import ScanPlanRevision, root_scan_plan_revision  # noqa: E402
import broker_worker  # noqa: E402
sys.path.pop(0)


NODE_ID = "11111111-1111-4111-8111-111111111111"


def _canonical_broker_scan_lease():
    target_binding = {
        "target_id": "target-1",
        "target_kind": "web",
        "canonical_host": "app.example.test",
        "allowed_origins": ["https://app.example.test"],
        "allowed_addresses": ["192.0.2.10"],
        "allowed_root_domains": ["example.test"],
        "environment": "unknown",
        "scope_receipt_id": "scope-1",
    }
    target_digest = broker_worker.hashlib.sha256(json.dumps(
        target_binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    runtime = {
        "http_requests": 20,
        "state_changing_requests": 0,
        "browser_actions": 4,
        "tcp_ports_attempted": 1,
        "hosts_attempted": 10,
        "tool_wall_seconds": 30,
    }
    job = {
        "options": {
            "scan_execution_plan_digest": "a" * 64,
            "_canonical_target_binding": target_binding,
        },
    }
    lease = {
        "scan_execution": {
            "schema_version": "broker-scan-execution-reservation/v1",
            "reservation_id": "22222222-2222-4222-8222-222222222222",
            "action_id": "deterministic_scan.execute",
            "action_digest": "b" * 64,
            "execution_plan_digest": "a" * 64,
            "target_binding_digest": target_digest,
            "runtime_budget": runtime,
            "requested_budget": {
                name: amount
                for name, amount in runtime.items()
                if amount > 0
            },
        },
    }
    return job, lease, runtime


def _canonical_broker_action_lease():
    scan_id = "33333333-3333-4333-8333-333333333333"
    target_binding = {
        "target_id": "target-1",
        "target_kind": "web",
        "canonical_host": "app.example.test",
        "allowed_origins": ["https://app.example.test"],
        "allowed_addresses": ["192.0.2.10"],
        "allowed_root_domains": ["example.test"],
        "environment": "unknown",
        "scope_receipt_id": "scope-1",
    }
    target_digest = broker_worker.hashlib.sha256(json.dumps(
        target_binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()
    action = ScanAction(
        action_id="baseline.http",
        stage="deterministic_baseline",
        ordinal=0,
        capability_name="http.request",
        capability_args={"method": "GET", "path": "/", "follow_redirects": False},
        target_binding_digest=target_digest,
        input_binding_digest="c" * 64,
        requested_budget={"http_requests": 1, "tool_wall_seconds": 5},
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": {},
            "adapter_name": "native.http",
            "adapter_version": "1",
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema="http-observation/v1",
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=target_digest,
        actions=(action,),
    )
    job = {
        "scan_id": scan_id,
        "options": {
            "scan_execution_plan_digest": "a" * 64,
            "_canonical_target_binding": target_binding,
        },
    }
    lease = {
        "scan_execution": None,
        "scan_action_plan": plan.canonical_dict(),
        "scan_action_plan_revision": root_scan_plan_revision(
            plan
        ).canonical_dict(),
        "action_worker_id": "broker:node-1:container-a",
    }
    return job, lease, plan


def test_broker_scan_requires_and_validates_durable_runtime_hold():
    job, lease, runtime = _canonical_broker_scan_lease()

    assert broker_worker._broker_scan_runtime_budget(job, lease) == runtime

    with pytest.raises(broker_worker.BrokerWorkerError, match="missing durable"):
        broker_worker._broker_scan_runtime_budget(job, {})

    changed = json.loads(json.dumps(lease))
    changed["scan_execution"]["runtime_budget"]["http_requests"] = 21
    with pytest.raises(broker_worker.BrokerWorkerError, match="does not match"):
        broker_worker._broker_scan_runtime_budget(job, changed)


def test_noncanonical_broker_job_rejects_injected_scan_authority():
    _job, lease, _runtime = _canonical_broker_scan_lease()
    with pytest.raises(broker_worker.BrokerWorkerError, match="non-canonical"):
        broker_worker._broker_scan_runtime_budget({"options": {}}, lease)


def test_broker_scan_requires_complete_immutable_action_plan():
    job, lease, plan = _canonical_broker_action_lease()

    parsed, revision, worker_id = broker_worker._broker_scan_action_plan(
        job, lease,
    )

    assert parsed.plan_digest == plan.plan_digest
    assert revision.plan_digest == plan.plan_digest
    assert worker_id == "broker:node-1:container-a"

    changed = json.loads(json.dumps(lease))
    changed["scan_action_plan"]["actions"][0]["capability_args"]["path"] = "/admin"
    with pytest.raises(broker_worker.BrokerWorkerError, match="invalid"):
        broker_worker._broker_scan_action_plan(job, changed)

    changed = json.loads(json.dumps(lease))
    changed["scan_execution"] = _canonical_broker_scan_lease()[1]["scan_execution"]
    with pytest.raises(broker_worker.BrokerWorkerError, match="deprecated monolithic"):
        broker_worker._broker_scan_action_plan(job, changed)


def test_broker_worker_opens_only_lease_bound_private_scan_inputs():
    pytest.importorskip("cryptography")
    from runtime.sealed_inputs import generate_sealed_input_keypair, seal_private_input

    _job, lease, plan = _canonical_broker_action_lease()
    worker_id = lease["action_worker_id"]
    lease.update({
        "lease_id": "lease-private-1",
        "lease_expires_at": "2099-08-23T20:00:00+00:00",
    })
    private_key, public_key = generate_sealed_input_keypair()
    authority = broker_worker._private_input_authority(lease, plan, worker_id)
    payload = {
        "schema_version": "broker-private-scan-input/v1",
        **authority,
        "options": {"auth_header": "Bearer canary-secret"},
        "replay_plans": {},
    }
    lease["private_scan_inputs"] = seal_private_input(
        payload,
        recipient_public_key=public_key,
        authority=authority,
    )

    opened = broker_worker._open_broker_private_scan_inputs(
        lease,
        plan=plan,
        worker_id=worker_id,
        private_input_key=private_key,
    )

    assert opened.options["auth_header"] == "Bearer canary-secret"
    changed = dict(lease)
    changed["lease_id"] = "lease-private-2"
    with pytest.raises(broker_worker.BrokerWorkerError, match="invalid"):
        broker_worker._open_broker_private_scan_inputs(
            changed,
            plan=plan,
            worker_id=worker_id,
            private_input_key=private_key,
        )

def test_broker_action_plan_requests_and_executes_control_plane_continuation(monkeypatch):
    job, lease, parent = _canonical_broker_action_lease()
    job.update({
        "target": "https://app.example.test",
        "job_id": "job-continuation",
    })
    job["options"].update({
        "scan_continuation_allocation_digest": "d" * 64,
        "scan_execution_plan": {
            "policy": {
                "active_testing": True,
                "allow_state_changing_http": False,
                "network_discovery": False,
                "subdomain_discovery": False,
                "include_families": ["xss"],
                "exclude_families": [],
                "scope_receipt_id": "scope-1",
                "approval_receipt_id": None,
            },
        },
    })
    finalizer = ScanAction(
        action_id="finalize.report",
        stage="finalize_evidence",
        ordinal=1,
        capability_name="scan.execute",
        capability_args={"report_only": True},
        target_binding_digest=parent.target_binding_digest,
        input_binding_digest="e" * 64,
        requested_budget={"tool_wall_seconds": 1},
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": {},
            "adapter_name": "scanner.report",
            "adapter_version": "1",
        },
        dependencies=(parent.actions[0].action_id,),
        required=True,
        supporting=False,
        output_schema="scan-report/v1",
    )
    amended = ScanActionPlan(
        scan_id=parent.scan_id,
        execution_plan_digest=parent.execution_plan_digest,
        target_binding_digest=parent.target_binding_digest,
        actions=(*parent.actions, finalizer),
    )
    revision = ScanPlanRevision(
        scan_id=amended.scan_id,
        revision=1,
        plan_digest=amended.plan_digest,
        parent_plan_digest=parent.plan_digest,
        continuation_allocation_digest="d" * 64,
        discovery_result_digest="e" * 64,
        work_manifest_references=({
            "schema_version": "scan-work-manifest-reference/v1",
            "manifest_id": "44444444-4444-4444-8444-444444444444",
            "kind": "candidate",
            "content_schema": "candidate-manifest/v1",
            "manifest_digest": "f" * 64,
            "entry_count": 1,
            "status": "complete",
        },),
        continuation_plan_digest="c" * 64,
    )
    calls = []

    def fake_api_request(_state, method, path, payload, **_kwargs):
        calls.append((method, path, payload))
        return {
            "plan": amended.canonical_dict(),
            "plan_revision": revision.canonical_dict(),
            "options": {"candidate_manifest_ref": {"kind": "candidate"}},
            "allocation_digest": "d" * 64,
        }

    class Backend:
        def __init__(self, **kwargs):
            self.plan = kwargs["plan"]

        async def load_observations(self, action_id):
            assert action_id == "finalize.report"
            return ({
                "kind": "scan_report",
                "report": {
                    "result": {},
                    "canonical_action_execution": {
                        "status_matrix": {"finalize.report": "success"},
                    },
                },
            },)

    class Dispatcher:
        def __init__(self, **kwargs):
            self.policy = kwargs["policy"]

    class Executor:
        def __init__(self, **_kwargs):
            pass

    runs = []

    class Orchestrator:
        def __init__(self, **kwargs):
            self.backend = kwargs["backend"]

        async def run(self, plan):
            runs.append(plan.plan_digest)
            if plan.plan_digest == parent.plan_digest:
                return types.SimpleNamespace(
                    action_results={
                        parent.actions[0].action_id: types.SimpleNamespace(
                            status=types.SimpleNamespace(value="success"),
                        ),
                    },
                    status_matrix={parent.actions[0].action_id: "success"},
                )
            return types.SimpleNamespace(
                action_results={
                    "finalize.report": types.SimpleNamespace(
                        status=types.SimpleNamespace(value="success"),
                        observation_manifest_ref=object(),
                    ),
                },
                status_matrix={"finalize.report": "success"},
            )

    monkeypatch.setattr(broker_worker, "api_request", fake_api_request)
    monkeypatch.setattr(broker_worker, "BrokerScanExecutionBackend", Backend)
    monkeypatch.setattr(
        broker_worker, "DatabaseNeutralScanActionDispatcher", Dispatcher,
    )
    monkeypatch.setattr(broker_worker, "ReceiptScanActionExecutor", Executor)
    monkeypatch.setattr(broker_worker, "ScanOrchestrator", Orchestrator)

    report = asyncio.run(broker_worker._execute_broker_action_plan(
        {"node_id": NODE_ID},
        {"lease_id": "lease-1", "lease_token": "token-1"},
        job,
        plan=parent,
        plan_revision=root_scan_plan_revision(parent),
        worker_id="broker:node-1:container-a",
    ))

    assert runs == [parent.plan_digest, amended.plan_digest]
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/continuation")
    assert calls[0][2]["plan_digest"] == parent.plan_digest
    assert report["canonical_action_execution"]["status_matrix"] == {
        "finalize.report": "success",
    }


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


def test_broker_compose_uses_native_admission_without_data_store_configuration():
    compose = Path(__file__).resolve().parents[1] / "docker-compose.broker-worker.yml"
    text = compose.read_text(encoding="utf-8")
    assert 'command: ["python3", "/app/broker_worker.py"]' in text
    assert "broker_worker_v2.py" not in text
    assert "REDIS_URL" not in text
    assert "DATABASE_URL" not in text
    assert "postgres:" not in text
    assert "redis:" not in text


def test_broker_execution_has_no_legacy_local_checkpoint_path():
    source = inspect.getsource(broker_worker.execute_lease)

    assert "_execute_broker_action_plan" in source
    assert "persist_checkpoint_artifacts=False" not in source
    assert 'artifact_type="checkpoint"' not in source


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
