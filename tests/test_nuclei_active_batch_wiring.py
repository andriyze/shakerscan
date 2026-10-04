"""End-to-end wiring of the active Nuclei batch adapter.

Drives ``DatabaseNeutralScanActionDispatcher._external_batch`` for a
``templates.active_batch`` action over a one-endpoint manifest, with the real
selection resolver pointed at the copied-bundle fixtures. Proves that the
authorization state decides which templates the per-attempt scanner process is
actually given, and that the mutation budget is reserved/settled accordingly.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import uuid

import pytest

from hunt.capability_executor import CapabilityAdapterResult
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
import scan.action_adapter as action_adapter_module
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.execution_backend import ActionLease
from scan.work_manifests import (
    build_canonical_nuclei_template_manifest,
    build_endpoint_manifest,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates"

TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
)


class _Backend:
    def __init__(self, manifests):
        self.manifests = dict(manifests)
        self.attempts: dict = {}

    async def load_work_manifest(self, _action_id, reference):
        return self.manifests[reference.manifest_id]

    async def load_batch_attempts(self, action_id):
        return tuple(self.attempts.get(action_id, {}).values())

    async def checkpoint_batch_attempt(self, action_id, attempt):
        self.attempts.setdefault(action_id, {})[attempt["attempt_id"]] = dict(attempt)


def _plan_and_action(*, requested_budget):
    scan_id = str(uuid.uuid4())
    endpoints = build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2",
            "status": "complete",
            "reason": None,
            "endpoints": [{
                "method": "GET", "scheme": "https", "host": "app.example.test",
                "port": 443, "normalized_path": "/", "concrete_path": "/",
                "query_keys": [], "source": "web.crawl",
            }],
        },
        source_action_ids=("discover.web_crawl",),
    )
    templates = build_canonical_nuclei_template_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
    )
    spec = CAPABILITY_REGISTRY.require("templates.active_batch")
    action = ScanAction(
        action_id="active.templates",
        stage="deterministic_active",
        ordinal=0,
        capability_name="templates.active_batch",
        capability_args={
            "target_manifest_ref": endpoints.reference().canonical_dict(),
            "template_manifest_ref": templates.reference().canonical_dict(),
            "slice": {"start": 0, "count": 1},
            "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_proof_contract_required",
        },
        target_binding_digest=TARGET.digest,
        input_binding_digest="1" * 64,
        requested_budget=dict(requested_budget),
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter,
            "adapter_version": spec.adapter_version,
        },
        dependencies=(),
        required=True,
        supporting=False,
        output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(
        scan_id=scan_id,
        execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest,
        actions=(action,),
    )
    backend = _Backend({
        endpoints.manifest_id: endpoints,
        templates.manifest_id: templates,
    })
    return plan, action, backend


def _lease(plan, action):
    return ActionLease(
        lease_id=str(uuid.uuid4()), lease_token="x" * 32, scan_id=plan.scan_id,
        plan_digest=plan.plan_digest, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest, action=action,
        backend="broker", worker_id="broker:worker-1", lease_seconds=60, attempt=1,
    )


async def _noop():
    return None


def _drive(monkeypatch, *, policy, requested_budget, templates_dir=str(FIXTURES)):
    plan, action, backend = _plan_and_action(requested_budget=requested_budget)
    captured: dict = {}

    async def execute(_self, context, adapter, **_kwargs):
        captured["scanner_options"] = dict(adapter._process_payload["scanner_options"])
        captured["requested_budget"] = dict(context.requested_budget)
        settled = {name: int(amount) for name, amount in context.requested_budget.items()}
        if "state_changing_requests" in settled:
            # Simulate a run that sent every reserved request; the real adapter
            # settles the mutation dimension from this same conservative basis.
            settled["state_changing_requests"] = settled["http_requests"]
        return CapabilityAdapterResult(
            status="success",
            actual_budget=settled,
            observations=({"kind": "template_match", "template_id": "x"},),
            execution_started=True,
            parser_version="nuclei-jsonl/v1",
        )

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    monkeypatch.setattr(
        action_adapter_module, "nuclei_templates_directory", lambda: templates_dir,
    )

    async def process_runner(*_a, **_k):
        raise AssertionError("process runner must not be used")

    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/",
        options={},
        target=TARGET,
        policy=policy,
        scan_id=plan.scan_id,
        job_id="job-1",
        worker_id="broker:worker-1",
        plan=plan,
        backend=backend,
        process_runner=process_runner,
        cancelled=lambda: False,
    )
    receipt = asyncio.run(dispatcher(action, _lease(plan, action), _noop))
    return receipt, captured


def test_unauthorized_active_batch_runs_only_get_templates(monkeypatch):
    receipt, captured = _drive(
        monkeypatch,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        requested_budget={"http_requests": 120, "tool_wall_seconds": 45},
    )
    assert receipt.status == "success"
    options = captured["scanner_options"]
    assert options["template_profile"] == "active"
    ids = options["template_ids"].split(",")
    assert ids == ["squid-analysis-report-generator"]
    assert "django-debug-exposure" not in ids       # method: POST
    assert "bloofoxcms-default-login" not in ids     # raw-request POST
    assert "put-method-enabled" not in ids           # intrusive
    assert options["nuclei_active_state_changing"] is False
    assert "state_changing_requests" not in captured["requested_budget"]
    assert receipt.budget_consumed.get("state_changing_requests", 0) == 0


def test_authorized_active_batch_runs_post_templates_and_settles_mutations(monkeypatch):
    receipt, captured = _drive(
        monkeypatch,
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
        requested_budget={
            "http_requests": 120,
            "state_changing_requests": 120,
            "tool_wall_seconds": 45,
        },
    )
    assert receipt.status == "success"
    options = captured["scanner_options"]
    ids = set(options["template_ids"].split(","))
    assert {"django-debug-exposure", "bloofoxcms-default-login"} <= ids  # POST now runs
    assert "put-method-enabled" not in ids                               # intrusive stays out
    assert options["nuclei_active_state_changing"] is True
    sub_budget = captured["requested_budget"]
    assert sub_budget.get("state_changing_requests", 0) > 0
    assert sub_budget["state_changing_requests"] == sub_budget["http_requests"]
    assert receipt.budget_consumed["state_changing_requests"] > 0


def test_active_batch_fails_closed_when_index_unavailable(monkeypatch, tmp_path):
    receipt, _captured = _drive(
        monkeypatch,
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
        requested_budget={
            "http_requests": 120,
            "state_changing_requests": 120,
            "tool_wall_seconds": 45,
        },
        templates_dir=str(tmp_path),  # no http/ subtree -> index cannot be built
    )
    assert receipt.status == "skipped"
    assert "nuclei_template_index_unavailable" in receipt.errors
