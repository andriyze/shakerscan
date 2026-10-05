"""Legacy durable single Nuclei actions obey method authority and saved holds."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import uuid

import pytest

import agent_tools
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import ScanPolicy, TargetBinding
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanAction, ScanActionPlan
from scan.execution_backend import ActionLease
from scan.nuclei_template_index import clear_index_cache
from scan.work_manifests import build_canonical_nuclei_template_manifest


FIXTURES = Path(__file__).parent / "fixtures" / "nuclei_templates"
TARGET = TargetBinding(
    target_id="target-1", target_kind="web", canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
)


@pytest.fixture(autouse=True)
def _fresh_index_cache():
    clear_index_cache()
    yield
    clear_index_cache()


def _drive(monkeypatch, *, authorized, mutation_hold=None, templates_dir=FIXTURES):
    monkeypatch.setenv("NUCLEI_TEMPLATES", str(templates_dir))
    scan_id = str(uuid.uuid4())
    templates = build_canonical_nuclei_template_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
    )
    spec = CAPABILITY_REGISTRY.require("templates.scan")
    budget = {"http_requests": 4_000, "tool_wall_seconds": 300}
    if mutation_hold is not None:
        budget["state_changing_requests"] = mutation_hold
    action = ScanAction(
        action_id="active.templates", stage="deterministic_active", ordinal=0,
        capability_name=spec.name,
        capability_args={"template_manifest_ref": templates.reference().canonical_dict()},
        target_binding_digest=TARGET.digest, input_binding_digest="1" * 64,
        requested_budget=budget,
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local", "broker"],
            "requirements": dict(spec.placement_requirements),
            "adapter_name": spec.adapter, "adapter_version": spec.adapter_version,
        },
        dependencies=(), required=True, supporting=False, output_schema=spec.output_schema,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(action,),
    )

    class Backend:
        async def load_work_manifest(self, _action_id, _reference):
            return templates

    captured = {}

    async def process_runner(payload, *, heartbeat):
        await heartbeat()
        captured.update(payload)
        process_plan = agent_tools.build_enforced_scanner_plan(
            "nuclei", payload["execution_target"], payload["scanner_options"],
            reserved_budget=payload["_reserved_budget"],
        )
        captured["process_plan"] = process_plan
        # No process or network is launched. Exercise the real adapter's exact
        # traffic settlement and its enforcement validation after plan building.
        return {
            "status": "success", "elapsed_seconds": 1,
            "typed_output": {"records": [], "errors": []},
            "settlement": {"mode": "exact", "actual": 7},
            "process_enforcement": process_plan.enforcement_receipt(),
        }

    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url="https://app.example.test/", options={}, target=TARGET,
        policy=ScanPolicy(
            active_testing=True, approval_receipt_id="approval-1",
            allow_state_changing_http=authorized,
        ),
        scan_id=scan_id, job_id="job-1", worker_id="broker:worker-1",
        plan=plan, backend=Backend(), process_runner=process_runner, cancelled=lambda: False,
    )
    lease = ActionLease(
        lease_id=str(uuid.uuid4()), lease_token="x" * 32, scan_id=scan_id,
        plan_digest=plan.plan_digest, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=TARGET.digest, action=action, backend="broker",
        worker_id="broker:worker-1", lease_seconds=60, attempt=1,
    )
    receipt = asyncio.run(dispatcher(action, lease, lambda: asyncio.sleep(0)))
    return receipt, captured, action


@pytest.mark.parametrize("authorized,mutation_hold", [
    (False, None), (False, 100), (True, None), (True, 0),
])
def test_legacy_nuclei_without_authority_or_hold_runs_only_get(
    monkeypatch, authorized, mutation_hold,
):
    receipt, captured, action = _drive(
        monkeypatch, authorized=authorized, mutation_hold=mutation_hold,
    )
    assert receipt.status == "success"
    options = captured["scanner_options"]
    assert options["template_ids"] == "squid-analysis-report-generator"
    assert options["nuclei_active_state_changing"] is False
    assert "tags" not in options
    assert "-id" in captured["process_plan"].argv
    assert "-tags" not in captured["process_plan"].argv
    assert receipt.budget_consumed.get("state_changing_requests", 0) == 0
    assert dict(receipt.budget_reserved) == dict(action.requested_budget)


def test_authorized_legacy_nuclei_preserves_post_and_caps_traffic_to_mutation_hold(monkeypatch):
    receipt, captured, action = _drive(monkeypatch, authorized=True, mutation_hold=100)
    assert receipt.status == "success"
    options = captured["scanner_options"]
    assert set(options["template_ids"].split(",")) == {
        "squid-analysis-report-generator", "django-debug-exposure", "bloofoxcms-default-login",
    }
    assert options["nuclei_active_state_changing"] is True
    assert "put-method-enabled" not in options["template_ids"]
    assert captured["_reserved_budget"]["http_requests"] == 100
    assert captured["_reserved_budget"]["state_changing_requests"] == 100
    assert captured["process_plan"].hard_budget_dict["http_requests"] == 100
    assert captured["process_plan"].hard_budget_dict["state_changing_requests"] == 100
    assert receipt.budget_consumed["http_requests"] == 7
    assert receipt.budget_consumed["state_changing_requests"] == 7
    # The durable hold remains historical; unused capacity is released at settlement.
    assert dict(receipt.budget_reserved) == dict(action.requested_budget)
    assert action.requested_budget["http_requests"] == 4_000


def test_legacy_nuclei_missing_index_records_gap_without_launch(monkeypatch, tmp_path):
    receipt, captured, _action = _drive(
        monkeypatch, authorized=True, mutation_hold=100, templates_dir=tmp_path,
    )
    assert receipt.status == "skipped"
    assert "nuclei_template_index_unavailable" in receipt.errors
    assert captured == {}


def test_legacy_nuclei_post_only_pack_without_mutation_hold_records_gap(monkeypatch, tmp_path):
    destination = tmp_path / "http" / "django-debug-exposure.yaml"
    destination.parent.mkdir()
    source = next(FIXTURES.rglob("django-debug-exposure.yaml"))
    shutil.copyfile(source, destination)
    receipt, captured, _action = _drive(
        monkeypatch, authorized=True, templates_dir=tmp_path,
    )
    assert receipt.status == "skipped"
    assert "no_eligible_nuclei_templates" in receipt.errors
    assert captured == {}
