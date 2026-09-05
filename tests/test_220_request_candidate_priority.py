from __future__ import annotations

import uuid

from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.execution import ScanExecutionPlan
from api.scan.work_manifests import ScanWorkManifestReference

SCAN_ID = "71000000-0000-4000-8000-000000000001"
SCOPE_ID = "71000000-0000-4000-8000-000000000002"
APPROVAL_ID = "71000000-0000-4000-8000-000000000003"


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-rc",
        target_kind="web",
        canonical_host="fixtures",
        allowed_origins=("http://fixtures:8000",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("fixtures",),
        scope_receipt_id=SCOPE_ID,
    )


def _ref(kind: str, digest: str, count: int = 1) -> dict:
    schemas = {
        "candidate": "candidate-manifest/v1",
        "request": "request-manifest/v2",
        "request_candidate": "request-candidate-manifest/v2",
    }
    return ScanWorkManifestReference(
        manifest_id=str(uuid.uuid5(uuid.NAMESPACE_URL, kind + digest)),
        kind=kind,
        content_schema=schemas[kind],
        manifest_digest=digest * 64,
        entry_count=count,
        status="complete",
    ).canonical_dict()


def _plan(family: str, *, max_state_changing_requests: int = 10):
    # Mirror the deliberately tight RC D2/D3 mutation ceiling. The selected family
    # must spend this authority on the exact imported request before generic breadth.
    budget = ScanBudget(
        max_duration_seconds=600,
        max_http_requests=2000,
        max_endpoints=40,
        max_browser_actions=20,
        max_tcp_ports=20,
        max_tool_wall_seconds=600,
        max_workers=1,
        max_state_changing_requests=max_state_changing_requests,
        max_hosts=40,
    )
    execution = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=True,
            allow_state_changing_http=True,
            include_families=("recon", family),
            scope_receipt_id=SCOPE_ID,
            approval_receipt_id=APPROVAL_ID,
        ),
        budget_profile="balanced",
        budget=budget,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        request_collection_refs=({
            "collection_id": "collection-rc",
            "selection_id": "selection-rc",
            "binding_id": "binding-rc",
            "version": 1,
            "selection_digest": "a" * 64,
            "active": True,
            "max_requests": 1,
            "replay_policy": "confirmed_active",
        },),
        request_manifest_refs={"a" * 64: _ref("request", "b")},
        candidate_manifest_ref=_ref("candidate", "c"),
        request_candidate_manifest_ref=_ref("request_candidate", "d"),
        action_scope="endpoint",
    )
    return budget, plan


def test_exact_xss_request_is_selected_family_minimum() -> None:
    budget, plan = _plan("xss")
    by_id = {action.action_id: action for action in plan.actions}

    assert by_id["verify.request_xss"].required is True
    assert by_id["verify.xss"].required is False

    allocation = allocate_scan_action_plan(plan, budget)
    admitted = {action.action_id: action for action in allocation.plan.actions}
    assert admitted["verify.request_xss"].admission_status == "planned"
    assert admitted["verify.request_xss"].requested_budget["state_changing_requests"] >= 2


def test_exact_sqli_verification_survives_tight_rc_mutation_ceiling() -> None:
    budget, plan = _plan("sqli")
    by_id = {action.action_id: action for action in plan.actions}

    assert by_id["verify.request_sqli"].required is True
    assert by_id["prove.request_sqli"].required is False
    assert by_id["verify.sqli"].required is False
    assert by_id["prove.sqli"].required is False

    allocation = allocate_scan_action_plan(plan, budget)
    admitted = {action.action_id: action for action in allocation.plan.actions}
    assert admitted["verify.request_sqli"].admission_status == "planned"
    assert admitted["prove.request_sqli"].admission_status == "skipped"
    assert admitted["prove.request_sqli"].reason_code == "insufficient_plan_budget"


def test_exact_sqli_proof_runs_when_mutation_authority_is_available() -> None:
    budget, plan = _plan("sqli", max_state_changing_requests=20)
    by_id = {action.action_id: action for action in plan.actions}

    assert by_id["verify.request_sqli"].required is True
    assert by_id["prove.request_sqli"].required is False

    allocation = allocate_scan_action_plan(plan, budget)
    admitted = {action.action_id: action for action in allocation.plan.actions}
    assert admitted["verify.request_sqli"].admission_status == "planned"
    assert admitted["prove.request_sqli"].admission_status == "planned"
