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


def _plan_and_action(*, requested_budget, paths=("/",)):
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
                "port": 443, "normalized_path": path, "concrete_path": path,
                "query_keys": [], "source": "web.crawl",
            } for path in paths],
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
            "slice": {"start": 0, "count": len(paths)},
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


def _drive(monkeypatch, *, policy, requested_budget, templates_dir=str(FIXTURES), paths=("/",)):
    plan, action, backend = _plan_and_action(requested_budget=requested_budget, paths=paths)
    captured: dict = {"calls": [], "backend": backend}

    async def execute(_self, context, adapter, **_kwargs):
        captured["scanner_options"] = dict(adapter._process_payload["scanner_options"])
        captured["calls"].append(dict(adapter._process_payload["scanner_options"]))
        captured.setdefault("targets", []).append(adapter._process_payload["execution_target"])
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
    assert "tomcat-default-login" not in ids         # a default login, sent by GET
    assert options["nuclei_active_state_changing"] is False
    assert "state_changing_requests" not in captured["requested_budget"]
    assert receipt.budget_consumed.get("state_changing_requests", 0) == 0
    # The receipt says what the selection held back and why.
    assert receipt.redacted_execution["template_selection"] == {
        "matched": 6, "selected": 1, "get_only": 1, "state_changing": 3, "default_login": 2,
        "exploit_class": 0, "includes_state_changing": False, "intrusive_excluded": 1, "never_requested_excluded": 1,
    }


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
    assert "tomcat-default-login" in ids                                 # and the GET login
    assert "put-method-enabled" not in ids                               # intrusive stays out
    assert options["nuclei_active_state_changing"] is True
    assert receipt.redacted_execution["template_selection"]["selected"] == 4
    assert receipt.redacted_execution["template_selection"]["default_login"] == 2
    assert receipt.redacted_execution["template_selection"]["includes_state_changing"] is True
    sub_budget = captured["requested_budget"]
    assert sub_budget.get("state_changing_requests", 0) > 0
    assert sub_budget["state_changing_requests"] == sub_budget["http_requests"]
    assert receipt.budget_consumed["state_changing_requests"] > 0


def test_active_batch_with_mutation_permission_but_zero_saved_hold_runs_get_templates(monkeypatch):
    receipt, captured = _drive(
        monkeypatch,
        policy=ScanPolicy(
            active_testing=True, allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
        requested_budget={
            "http_requests": 120, "state_changing_requests": 0, "tool_wall_seconds": 45,
        },
    )
    assert receipt.status == "success"
    options = captured["scanner_options"]
    assert options["template_ids"] == "squid-analysis-report-generator"
    assert options["nuclei_active_state_changing"] is False
    assert receipt.budget_consumed.get("state_changing_requests", 0) == 0


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


AUTHORIZED = ScanPolicy(active_testing=True, allow_state_changing_http=True, approval_receipt_id="approval-1")
HOLD = {"http_requests": 120, "state_changing_requests": 120, "tool_wall_seconds": 45}


def test_endpoint_attempts_rotate_through_the_whole_active_allowlist(monkeypatch):
    # Every attempt used to get the full allowlist and, cut off by its wall, ran the same
    # first tenth of it on every endpoint. With windows of one template, one endpoint per
    # template runs a different template each and together they cover the allowlist once.
    from scan import nuclei_execution
    full_receipt, full = _drive(monkeypatch, policy=AUTHORIZED, requested_budget=HOLD)
    allowlist = full["scanner_options"]["template_ids"].split(",")
    assert full_receipt.status == "success" and len(allowlist) >= 3
    monkeypatch.setattr(nuclei_execution, "ACTIVE_TEMPLATE_WINDOW_SIZE", 1)
    paths = tuple(f"/{index}" for index in range(len(allowlist)))
    receipt, captured = _drive(monkeypatch, policy=AUTHORIZED, requested_budget=HOLD, paths=paths)
    assert receipt.status == "success"
    windows = [call["template_ids"].split(",") for call in captured["calls"]]
    assert len(windows) == len(allowlist)
    assert sorted(item for window in windows for item in window) == sorted(allowlist)
    assert all(window for window in windows) and len({tuple(w) for w in windows}) == len(allowlist)
    recorded = sorted(item["template_window"]["index"]
                      for item in captured["backend"].attempts["active.templates"].values())
    assert recorded == list(range(len(allowlist)))


def test_template_window_partitions_deterministically():
    from scan.nuclei_execution import active_template_window
    ids = ",".join(f"t{index:03d}" for index in range(250))
    windows = [active_template_window(ids, ordinal, size=90) for ordinal in range(6)]
    assert {window.count for window in windows} == {3}
    assert [window.index for window in windows] == [0, 1, 2, 0, 1, 2]
    covered = [item for window in windows[:3] for item in window.template_ids.split(",")]
    assert sorted(covered) == ids.split(",") and len(set(covered)) == 250
    assert windows[0] == windows[3]
    assert max(window.templates for window in windows) <= 90
    assert active_template_window("one", 7).template_ids == "one"
    with pytest.raises(ValueError):
        active_template_window("", 0)
    with pytest.raises(ValueError):
        active_template_window("a,b", -1)


def test_a_bundle_of_default_logins_alone_records_why_nothing_ran(monkeypatch, tmp_path):
    # Without the state-changing permission a GET default login is held back; the gap
    # receipt names the reason and the count.
    destination = tmp_path / "http" / "tomcat-default-login.yaml"
    destination.parent.mkdir()
    destination.write_bytes(next(FIXTURES.rglob("tomcat-default-login.yaml")).read_bytes())
    receipt, captured = _drive(
        monkeypatch,
        policy=ScanPolicy(active_testing=True, approval_receipt_id="approval-1"),
        requested_budget={"http_requests": 120, "tool_wall_seconds": 45},
        templates_dir=str(tmp_path),
    )
    assert receipt.status == "skipped"
    assert "no_eligible_nuclei_templates" in receipt.errors
    assert "scanner_options" not in captured
    selection = receipt.redacted_execution["template_selection"]
    assert selection["selected"] == 0 and selection["default_login"] == 1
