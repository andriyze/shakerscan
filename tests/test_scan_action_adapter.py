from __future__ import annotations

import asyncio
import json
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import PreparedExecution, ScanPolicy, TargetBinding
import scan.action_adapter as action_adapter_module
from runtime.observation_manifests import ObservationManifestReference
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.execution_backend import ActionLease


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


def _action(
    action_id: str,
    capability: str,
    ordinal: int,
    *,
    dependencies=(),
) -> ScanAction:
    spec = CAPABILITY_REGISTRY.require(capability)
    return ScanAction(
        action_id=action_id,
        stage="finalize_evidence" if action_id == "finalize.report" else "resolve_inputs",
        ordinal=ordinal,
        capability_name=capability,
        capability_args={"report_only": True} if action_id == "finalize.report" else {},
        target_binding_digest=TARGET.digest,
        input_binding_digest=str(ordinal + 1) * 64,
        requested_budget=dict(spec.budget_cost),
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=tuple(dependencies),
        required=True,
        supporting=False,
        output_schema=spec.output_schema,
    )


class Backend:
    def __init__(self, results=None, observations=None):
        self.results = dict(results or {})
        self.observations = dict(observations or {})

    async def load_result(self, action_id):
        return self.results.get(action_id)

    async def load_observations(self, action_id):
        return tuple(self.observations.get(action_id) or ())


def _dispatcher(plan, backend, *, target=TARGET):
    async def process_runner(*_args, **_kwargs):
        raise AssertionError("process runner must not be used")

    return DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/",
        options={},
        target=target,
        policy=ScanPolicy(),
        scan_id=plan.scan_id,
        job_id="job-1",
        worker_id="broker:worker-1",
        plan=plan,
        backend=backend,
        process_runner=process_runner,
        cancelled=lambda: False,
    )


def _lease(plan, action):
    return ActionLease(
        lease_id=str(uuid.uuid4()),
        lease_token="x" * 32,
        scan_id=plan.scan_id,
        plan_digest=plan.plan_digest,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        action=action,
        backend="broker",
        worker_id="broker:worker-1",
        lease_seconds=60,
        attempt=1,
    )


def test_database_neutral_dispatcher_never_treats_profile_reference_as_secret():
    action = _action("inputs.auth_primary", "auth.session.establish", 0)
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    dispatcher = _dispatcher(plan, Backend())

    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "skipped"
    assert receipt.budget_consumed == {
        name: 0 for name in action.requested_budget
    }
    assert receipt.errors == ("not_applicable",)


async def _noop():
    return None


def test_database_neutral_finalizer_reads_only_durable_results_and_observations():
    baseline = _action("baseline.http", "http.request", 0)
    final = _action("finalize.report", "scan.execute", 1, dependencies=(baseline.action_id,))
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(baseline, final),
    )
    manifest = ObservationManifestReference(
        manifest_id=str(uuid.uuid4()),
        sha256="b" * 64,
        count=1,
        size_bytes=10,
        object_key="scan/test/baseline.json",
        manifest_digest="c" * 64,
    )
    result = CapabilityResultReference(
        action_id=baseline.action_id,
        action_digest=baseline.action_digest,
        capability_name=baseline.capability_name,
        adapter_name=str(baseline.placement["adapter_name"]),
        adapter_version=str(baseline.placement["adapter_version"]),
        output_schema=baseline.output_schema,
        status=CapabilityResultStatus.SUCCESS,
        partial=False,
        timed_out=False,
        reason_code=None,
        receipt_ref=CapabilityReceiptReference(
            receipt_id=str(uuid.uuid4()), receipt_hash="d" * 64,
        ),
        observation_manifest_ref=manifest,
        budget_reserved=baseline.requested_budget,
        budget_consumed={name: 0 for name in baseline.requested_budget},
    )
    backend = Backend(
        results={baseline.action_id: result},
        observations={baseline.action_id: ({"kind": "http_observation"},)},
    )
    dispatcher = _dispatcher(plan, backend)

    receipt = asyncio.run(dispatcher(final, _lease(plan, final), _noop))

    assert receipt.status == "success"
    assert receipt.observations[0]["kind"] == "scan_report"
    assert receipt.redacted_execution["target_traffic"] is False


def test_database_neutral_http_receipt_drops_body_and_redacts_urls(monkeypatch):
    action = _action("baseline.http", "http.request", 0)
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )

    async def execute_bound(*_args, **_kwargs):
        return {
            "ok": True,
            "request": {"method": "GET", "path": "/reset/token/abc123?key=secret"},
            "response": {
                "status": 200,
                "body_sample": "Bearer should-never-enter-durable-evidence",
                "selected_json": {"access_token": "also-secret"},
                "selected_headers": {
                    "authorization": "Bearer should-never-enter-durable-evidence",
                },
                "final_url": "https://app.example.test/reset?token=also-secret",
            },
            "redirect_chain": [],
            "hops_followed": 0,
        }

    monkeypatch.setattr(
        action_adapter_module, "execute_bound_http_request", execute_bound,
    )
    dispatcher = _dispatcher(plan, Backend())
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    serialized = json.dumps(receipt.public_dict(), sort_keys=True)

    assert receipt.status == "success"
    assert "should-never-enter-durable-evidence" not in serialized
    assert "also-secret" not in serialized
    assert receipt.observations[0]["response"]["body_sample"] == ""
    assert receipt.observations[0]["response"]["selected_json"] == {}
    assert "<redacted>" in serialized


def test_database_neutral_network_action_limits_commands_to_reserved_hosts(monkeypatch):
    target = TargetBinding(
        target_id=TARGET.target_id,
        target_kind=TARGET.target_kind,
        canonical_host=TARGET.canonical_host,
        allowed_origins=TARGET.allowed_origins,
        allowed_addresses=("192.0.2.10", "192.0.2.11", "192.0.2.12"),
        allowed_root_domains=TARGET.allowed_root_domains,
    )
    spec = CAPABILITY_REGISTRY.require("ports.discover")
    action = ScanAction(
        action_id="discover.ports",
        stage="discover_network",
        ordinal=0,
        capability_name=spec.name,
        capability_args={},
        target_binding_digest=target.digest,
        input_binding_digest="e" * 64,
        requested_budget={
            "hosts_attempted": 1,
            "tcp_ports_attempted": 4,
            "tool_wall_seconds": 5,
        },
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=(),
        required=True,
        supporting=True,
        output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(
        scan_id=str(uuid.uuid4()),
        execution_plan_digest="a" * 64,
        target_binding_digest=target.digest,
        actions=(action,),
    )
    captured = {}

    class Factory:
        capability_name = spec.name
        adapter_name = spec.adapter
        adapter_version = spec.adapter_version
        parser_version = spec.output_schema

        def prepare(self, *, target, args, policy):
            del policy
            captured["addresses"] = target.allowed_addresses
            captured["ports"] = tuple(args["ports"])
            return PreparedExecution(
                capability_name=spec.name,
                adapter_name=spec.adapter,
                adapter_version=spec.adapter_version,
                commands=(),
                estimated_budget={
                    "hosts_attempted": len(target.allowed_addresses),
                    "tcp_ports_attempted": len(args["ports"]),
                    "tool_wall_seconds": 5,
                },
                input_digest="f" * 64,
                redacted_execution={},
                parser_version=spec.output_schema,
            )

    class ExecutionAdapter:
        manages_cancellation = False

        def __init__(self, *, prepared, parser, **_kwargs):
            del parser
            self.capability_name = prepared.capability_name
            self.adapter_name = prepared.adapter_name
            self.adapter_version = prepared.adapter_version

        async def execute(self, **_kwargs):
            return CapabilityAdapterResult(
                status="success",
                actual_budget={
                    "hosts_attempted": 1,
                    "tcp_ports_attempted": 4,
                    "tool_wall_seconds": 1,
                },
                execution_started=True,
                parser_version=spec.output_schema,
            )

    monkeypatch.setattr(action_adapter_module, "network_capability_adapter", lambda _name: Factory())
    monkeypatch.setattr(action_adapter_module, "NetworkExecutionAdapter", ExecutionAdapter)
    dispatcher = _dispatcher(plan, Backend(), target=target)
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert receipt.status == "success"
    assert captured["addresses"] == ("192.0.2.10",)
    assert len(captured["ports"]) == 4
