from __future__ import annotations

from types import SimpleNamespace

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.continuation import (
    ContinuationBudgetCeiling,
    ScanContinuationAllocation,
    ScanContinuationError,
    build_discovery_continuation_manifests,
    merge_scan_action_continuation,
)
from api.scan.contracts import resolve_scan_contract
from api.scan.work_manifests import (
    build_candidate_manifest,
    build_canonical_nuclei_template_manifest,
    build_endpoint_manifest,
)


SCAN_ID = "70000000-0000-4000-8000-000000000001"


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-continuation",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.30",),
        allowed_root_domains=("example.test",),
    )


def _surface():
    return {
        "schema_version": "endpoint-manifest/v1",
        "status": "complete",
        "reason": None,
        "endpoints": [{
            "method": "GET",
            "scheme": "https",
            "host": "app.example.test",
            "port": 443,
            "normalized_path": "/search",
            "concrete_path": "/search",
            "query_keys": ["q"],
            "content_fingerprint": None,
            "source": "web.crawl",
            "sensitive_path_redacted": False,
        }],
    }


def _plans():
    target = _target()
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True, "include_families": ["xss"]},
    )
    parent_raw = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        defer_manifest_actions=True,
        include_finalizer=False,
    )
    parent_allocation = allocate_scan_action_plan(
        parent_raw,
        contract.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
    )
    parent = parent_allocation.plan
    allocation = ScanContinuationAllocation(
        scan_id=SCAN_ID,
        parent_plan_digest=parent.plan_digest,
        execution_plan_digest=parent.execution_plan_digest,
        target_binding_digest=parent.target_binding_digest,
        parent_action_ids=tuple(action.action_id for action in parent.actions),
        budget_ceiling=parent_allocation.residual_scan_execute_budget,
        max_endpoint_entries=contract.budget.max_endpoints,
        max_candidate_entries=min(20_000, contract.budget.max_http_requests),
        required_capabilities=("xss.verify",),
    )
    endpoints = build_endpoint_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=target.digest,
        surface_manifest=_surface(),
        source_action_ids=("discover.web_crawl",),
    )
    candidates = build_candidate_manifest(
        endpoints,
        source_action_ids=("discover.web_crawl",),
        maximum=100,
    )
    templates = build_canonical_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=target.digest,
    )
    continuation_raw = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        action_scope="endpoint",
        endpoint_manifest_ref=endpoints.reference().canonical_dict(),
        candidate_manifest_ref=candidates.reference().canonical_dict(),
        template_manifest_ref=templates.reference().canonical_dict(),
    )
    continuation = allocate_scan_action_plan(
        continuation_raw,
        ContinuationBudgetCeiling(allocation.budget_ceiling),
    ).plan
    return parent, continuation, allocation


def test_admission_plan_can_stop_before_manifest_bound_actions():
    parent, _continuation, allocation = _plans()

    assert parent.actions
    assert "finalize.report" not in {action.action_id for action in parent.actions}
    assert not {
        "templates.scan", "xss.verify", "sqli.verify", "authz.verify",
    } & {action.capability_name for action in parent.actions}
    assert allocation.parent_action_ids == tuple(
        action.action_id for action in parent.actions
    )
    assert ScanContinuationAllocation.from_dict(
        allocation.canonical_dict()
    ) == allocation


def test_continuation_append_preserves_parent_and_binds_one_finalizer():
    parent, continuation, allocation = _plans()

    amended = merge_scan_action_continuation(
        parent_plan=parent,
        continuation_plan=continuation,
        allocation=allocation,
    )

    assert amended.actions[:len(parent.actions)] == parent.actions
    assert amended.actions[-1].action_id == "finalize.report"
    assert amended.actions[-1].dependencies == tuple(
        action.action_id for action in amended.actions[:-1]
    )
    assert any(
        action.capability_name == "xss.verify"
        and action.capability_args["candidate_manifest_ref"]["manifest_digest"]
        for action in amended.actions
    )


def test_continuation_cannot_exceed_its_upfront_budget_ceiling():
    parent, continuation, allocation = _plans()
    too_small = ScanContinuationAllocation(
        **{
            **allocation.digest_material(),
            "budget_ceiling": {
                name: 0 for name in allocation.budget_ceiling
            },
        }
    )

    try:
        merge_scan_action_continuation(
            parent_plan=parent,
            continuation_plan=continuation,
            allocation=too_small,
        )
    except ScanContinuationError as exc:
        assert "upfront allocation" in str(exc)
    else:
        raise AssertionError("over-budget continuation was accepted")


def test_discovery_receipts_compile_reproducible_endpoint_and_candidate_work():
    parent, _continuation, allocation = _plans()
    results = {
        action.action_id: SimpleNamespace(
            status=SimpleNamespace(value="success"),
            reason_code=None,
        )
        for action in parent.actions
    }
    crawl = (
        {
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://app.example.test/items?id=7",
        },
        {
            "kind": "discovered_route",
            "method": "GET",
            "url": "https://app.example.test/search?q=hello",
        },
    )

    first = build_discovery_continuation_manifests(
        allocation=allocation,
        target_url="https://app.example.test",
        target=_target(),
        options={},
        action_results=results,
        observations={"discover.web_crawl": crawl},
    )
    second = build_discovery_continuation_manifests(
        allocation=allocation,
        target_url="https://app.example.test",
        target=_target(),
        options={},
        action_results=results,
        observations={"discover.web_crawl": tuple(reversed(crawl))},
    )

    assert {item["canonical_path"] for item in first[0].entries} >= {
        "/", "/items", "/search",
    }
    assert {item["parameter_name"] for item in first[1].entries} == {"id", "q"}
    assert first[0].manifest_digest == second[0].manifest_digest
    assert first[1].manifest_digest == second[1].manifest_digest
