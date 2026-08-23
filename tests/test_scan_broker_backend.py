from __future__ import annotations

import asyncio
import uuid

import pytest

from runtime.receipts import CapabilityReceipt
from runtime.observation_manifests import ObservationManifestReference
from scan.action_plan import ScanAction, ScanActionPlan
from scan.broker_backend import (
    BrokerActionHTTPError,
    BrokerScanExecutionBackend,
)
from scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.execution_backend import ActionAlreadyTerminal, ActionLeaseLost
from scan.work_manifests import build_endpoint_manifest


def _plan(*, manifest_ref=None, scan_id=None) -> ScanActionPlan:
    target_digest = "1" * 64
    action = ScanAction(
        action_id="baseline.http",
        stage="baseline",
        ordinal=0,
        capability_name="http.request",
        capability_args={
            "method": "HEAD",
            "path": "/",
            **({"endpoint_manifest_ref": manifest_ref} if manifest_ref else {}),
        },
        target_binding_digest=target_digest,
        input_binding_digest="2" * 64,
        requested_budget={"http_requests": 1, "tool_wall_seconds": 5},
        placement={
            "adapter_name": "native.http",
            "adapter_version": "1",
            "eligible_backends": ["local", "broker"],
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema="http-observation/v1",
    )
    return ScanActionPlan(
        scan_id=str(scan_id or uuid.uuid4()),
        execution_plan_digest="3" * 64,
        target_binding_digest=target_digest,
        actions=(action,),
    )


def _endpoint_manifest(scan_id: str):
    return build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest="1" * 64,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test",
                "port": 443, "normalized_path": "/health", "concrete_path": "/health",
                "query_keys": [], "source": "seed",
            }],
        },
        source_action_ids=("discover.web_probe",),
    )


def _result(action: ScanAction, receipt: CapabilityReceipt) -> CapabilityResultReference:
    return CapabilityResultReference(
        action_id=action.action_id,
        action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name=receipt.adapter_name,
        adapter_version=receipt.adapter_version,
        output_schema=action.output_schema,
        status=CapabilityResultStatus.SUCCESS,
        partial=False,
        timed_out=False,
        reason_code=None,
        receipt_ref=CapabilityReceiptReference(
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.receipt_hash,
        ),
        observation_manifest_ref=ObservationManifestReference(
            manifest_id=str(uuid.uuid4()),
            sha256="4" * 64,
            count=0,
            size_bytes=0,
            object_key="scan/test/observations.json",
            manifest_digest="5" * 64,
        ),
        budget_reserved=receipt.budget_reserved,
        budget_consumed=receipt.budget_consumed,
    )


def test_broker_backend_round_trips_one_strict_action_lease_and_receipt():
    plan = _plan()
    action = plan.actions[0]
    worker_id = "broker:node-1:container-a"
    calls = []
    receipt_holder = {}

    async def request(method, path, payload):
        calls.append((method, path, payload))
        if path.endswith("/lease"):
            from scan.execution_backend import ActionLease
            return {"action_lease": ActionLease(
                lease_id=str(uuid.uuid4()), lease_token="x" * 32,
                scan_id=plan.scan_id, plan_digest=plan.plan_digest,
                execution_plan_digest=plan.execution_plan_digest,
                target_binding_digest=plan.target_binding_digest,
                action=action, backend="broker", worker_id=worker_id,
                lease_seconds=60, attempt=1,
            ).remote_payload()}
        if path.endswith("/heartbeat"):
            return {"status": "running"}
        if path.endswith("/result"):
            received = CapabilityReceipt.from_dict(payload["receipt"])
            receipt_holder["receipt"] = received
            return {"result": _result(action, received).canonical_dict()}
        if path.endswith("/status"):
            return {"result": None}
        if path.endswith("/observations"):
            return {"observations": [{"kind": "http_observation"}]}
        return {"cancel_requested": False}

    backend = BrokerScanExecutionBackend(
        plan=plan, worker_id=worker_id, job_lease_token="j" * 32,
        base_path="/fleet/broker/nodes/node/leases/job",
        request=request,
    )
    lease = asyncio.run(backend.acquire_action(action))
    asyncio.run(backend.heartbeat(lease))
    now = "2026-08-23T12:00:00+00:00"
    receipt = CapabilityReceipt(
        capability_name=action.capability_name,
        adapter_name="native.http", adapter_version="1",
        target_id="target-1", scan_id=plan.scan_id, worker_id=worker_id,
        status="success", input_digest=action.action_digest,
        parser_version="http-observation/v1", started_at=now, finished_at=now,
        budget_reserved=action.requested_budget,
        budget_consumed={"http_requests": 1, "tool_wall_seconds": 1},
    )
    stored = asyncio.run(backend.settle(lease, receipt))
    observations = asyncio.run(backend.load_observations(action.action_id))

    assert stored.status is CapabilityResultStatus.SUCCESS
    assert observations == ({"kind": "http_observation"},)
    assert receipt_holder["receipt"].receipt_hash == receipt.receipt_hash
    assert all(call[2]["plan_digest"] == plan.plan_digest for call in calls)
    assert all(call[2]["action_digest"] == action.action_digest for call in calls)


def test_broker_backend_maps_terminal_and_lost_authority():
    plan = _plan()
    action = plan.actions[0]

    async def terminal(_method, _path, _payload):
        raise BrokerActionHTTPError(208, "already terminal")

    backend = BrokerScanExecutionBackend(
        plan=plan, worker_id="broker:worker", job_lease_token="j" * 32,
        base_path="/broker/job", request=terminal,
    )
    with pytest.raises(ActionAlreadyTerminal):
        asyncio.run(backend.acquire_action(action))

    from scan.execution_backend import ActionLease
    lease = ActionLease(
        lease_id=str(uuid.uuid4()), lease_token="x" * 32,
        scan_id=plan.scan_id, plan_digest=plan.plan_digest,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        action=action, backend="broker", worker_id="broker:worker",
        lease_seconds=60, attempt=1,
    )

    async def lost(_method, _path, _payload):
        raise BrokerActionHTTPError(409, "lost")

    lost_backend = BrokerScanExecutionBackend(
        plan=plan, worker_id="broker:worker", job_lease_token="j" * 32,
        base_path="/broker/job", request=lost,
    )
    with pytest.raises(ActionLeaseLost):
        asyncio.run(lost_backend.heartbeat(lease))


def test_broker_backend_rejects_substituted_remote_action():
    plan = _plan()
    action = plan.actions[0]

    async def substituted(_method, _path, _payload):
        from scan.execution_backend import ActionLease
        changed = ScanAction(
            **{
                **action.digest_material(),
                "capability_args": {"method": "GET", "path": "/admin"},
            }
        )
        return {"action_lease": ActionLease(
            lease_id=str(uuid.uuid4()), lease_token="x" * 32,
            scan_id=plan.scan_id, plan_digest=plan.plan_digest,
            execution_plan_digest=plan.execution_plan_digest,
            target_binding_digest=plan.target_binding_digest,
            action=changed, backend="broker", worker_id="broker:worker",
            lease_seconds=60, attempt=1,
        ).remote_payload()}

    backend = BrokerScanExecutionBackend(
        plan=plan, worker_id="broker:worker", job_lease_token="j" * 32,
        base_path="/broker/job", request=substituted,
    )
    with pytest.raises(Exception, match="differs"):
        asyncio.run(backend.acquire_action(action))


def test_broker_backend_fetches_only_digest_bound_work_manifest():
    scan_id = str(uuid.uuid4())
    manifest = _endpoint_manifest(scan_id)
    plan = _plan(
        scan_id=scan_id,
        manifest_ref=manifest.reference().canonical_dict(),
    )
    action = plan.actions[0]
    requested = []

    async def request(_method, path, payload):
        assert path.endswith("/work-manifest")
        requested.append(payload["manifest_ref"])
        return {"manifest": manifest.canonical_dict()}

    backend = BrokerScanExecutionBackend(
        plan=plan, worker_id="broker:worker", job_lease_token="j" * 32,
        base_path="/broker/job", request=request,
    )
    loaded = asyncio.run(backend.load_work_manifest(
        action.action_id, manifest.reference(),
    ))

    assert loaded == manifest
    assert requested == [manifest.reference().canonical_dict()]


def test_broker_backend_rejects_substituted_work_manifest():
    plan = _plan()
    expected = _endpoint_manifest(plan.scan_id)
    replacement = build_endpoint_manifest(
        scan_id=plan.scan_id,
        target_binding_digest=plan.target_binding_digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete",
            "reason": None, "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test",
                "port": 443, "normalized_path": "/admin", "concrete_path": "/admin",
                "query_keys": [], "source": "seed",
            }],
        },
        source_action_ids=("discover.web_probe",),
    )

    async def substituted(_method, _path, _payload):
        return {"manifest": replacement.canonical_dict()}

    backend = BrokerScanExecutionBackend(
        plan=plan, worker_id="broker:worker", job_lease_token="j" * 32,
        base_path="/broker/job", request=substituted,
    )
    with pytest.raises(Exception, match="differs"):
        asyncio.run(backend.load_work_manifest("baseline.http", expected.reference()))
