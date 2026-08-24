from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from api.runtime.models import TargetBinding
from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.continuation import (
    ContinuationBudgetCeiling,
    SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1,
    ScanContinuationAllocation,
    ScanContinuationError,
    ScanPlanRevision,
    amended_scan_plan_revision,
    build_discovery_continuation_manifests,
    merge_scan_action_continuation,
)
from api.scan.capability_result import CapabilityResultStatus
from api.scan.contracts import resolve_scan_contract
from api.scan.work_manifests import (
    ScanWorkManifestReference,
    build_candidate_manifest,
    build_canonical_nuclei_template_manifest,
    build_endpoint_manifest,
    unique_work_manifest_reference_dicts,
)
from tests.test_scan_orchestrator import _result


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
        allowed_capabilities=("xss.verify",),
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


def test_v1_continuation_allocation_remains_readable_for_inflight_scans():
    parent, continuation, allocation = _plans()
    legacy = ScanContinuationAllocation(
        scan_id=allocation.scan_id,
        parent_plan_digest=allocation.parent_plan_digest,
        execution_plan_digest=allocation.execution_plan_digest,
        target_binding_digest=allocation.target_binding_digest,
        parent_action_ids=allocation.parent_action_ids,
        budget_ceiling=allocation.budget_ceiling,
        max_endpoint_entries=allocation.max_endpoint_entries,
        max_candidate_entries=allocation.max_candidate_entries,
        required_capabilities=allocation.required_capabilities,
        schema_version=SCAN_CONTINUATION_ALLOCATION_SCHEMA_V1,
    )

    restored = ScanContinuationAllocation.from_dict(legacy.canonical_dict())

    assert restored == legacy
    assert "xss.verify" in restored.allowed_capabilities
    assert merge_scan_action_continuation(
        parent_plan=parent,
        continuation_plan=continuation,
        allocation=restored,
    ).actions[-1].action_id == "finalize.report"


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


def test_plan_revision_chain_is_reproducible_and_binds_discovery_receipts():
    parent, continuation, allocation = _plans()
    amended = merge_scan_action_continuation(
        parent_plan=parent,
        continuation_plan=continuation,
        allocation=allocation,
    )
    results = {
        action.action_id: _result(
            action,
            status=CapabilityResultStatus.SUCCESS,
            namespace="revision-a",
        )
        for action in parent.actions
    }
    refs = unique_work_manifest_reference_dicts(
        action.capability_args for action in continuation.actions
    )

    first = amended_scan_plan_revision(
        parent_plan=parent,
        continuation_plan=continuation,
        amended_plan=amended,
        allocation=allocation,
        discovery_results=results,
        work_manifest_references=refs,
    )
    shuffled = amended_scan_plan_revision(
        parent_plan=parent,
        continuation_plan=continuation,
        amended_plan=amended,
        allocation=allocation,
        discovery_results=dict(reversed(tuple(results.items()))),
        work_manifest_references=tuple(reversed(refs)),
    )
    changed_results = dict(results)
    changed_action = parent.actions[0]
    changed_results[changed_action.action_id] = _result(
        changed_action,
        status=CapabilityResultStatus.SUCCESS,
        namespace="revision-b",
    )
    changed = amended_scan_plan_revision(
        parent_plan=parent,
        continuation_plan=continuation,
        amended_plan=amended,
        allocation=allocation,
        discovery_results=changed_results,
        work_manifest_references=refs,
    )

    assert first == shuffled
    assert first.revision_digest != changed.revision_digest
    assert first.continuation_plan_digest == continuation.plan_digest
    assert ScanPlanRevision.from_dict(first.canonical_dict()) == first


def test_continuation_request_verifier_binds_parent_collection_replay():
    target = _target()
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
            "include_families": ["xss"],
        },
        approval_receipt_id="approval-1",
    )
    collection = ({
        "collection_id": "collection-a",
        "selection_id": "selection-a",
        "binding_id": "binding-a",
        "version": 1,
        "selection_digest": "a" * 64,
        "active": True,
        "max_requests": 1,
    },)
    request_ref = ScanWorkManifestReference(
        manifest_id="70000000-0000-4000-8000-000000000080",
        kind="request",
        content_schema="request-manifest/v1",
        manifest_digest="b" * 64,
        entry_count=1,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="70000000-0000-4000-8000-000000000081",
        kind="request_candidate",
        content_schema="request-candidate-manifest/v1",
        manifest_digest="c" * 64,
        entry_count=1,
        status="complete",
    ).canonical_dict()
    parent_raw = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        request_collection_refs=collection,
        request_manifest_refs={"a" * 64: request_ref},
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
        required_capabilities=("xss.request_verify",),
        allowed_capabilities=("xss.request_verify", "xss.verify"),
    )
    continuation_raw = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        request_collection_refs=collection,
        request_manifest_refs={"a" * 64: request_ref},
        request_candidate_manifest_ref=candidate_ref,
        action_scope="endpoint",
        action_budgets={"inputs.collection_00": {}},
    )
    continuation = allocate_scan_action_plan(
        continuation_raw,
        ContinuationBudgetCeiling(allocation.budget_ceiling),
    ).plan

    amended = merge_scan_action_continuation(
        parent_plan=parent,
        continuation_plan=continuation,
        allocation=allocation,
    )
    verifier = next(
        action for action in amended.actions
        if action.capability_name == "xss.request_verify"
    )

    assert verifier.dependencies == ("inputs.collection_00",)
    assert sum(
        action.action_id == "inputs.collection_00" for action in amended.actions
    ) == 1


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


def test_continuation_cannot_add_a_capability_family():
    parent, continuation, allocation = _plans()
    no_families = ScanContinuationAllocation(
        **{
            **allocation.digest_material(),
            "required_capabilities": [],
            "allowed_capabilities": [],
        }
    )

    with pytest.raises(ScanContinuationError, match="outside its allocation"):
        merge_scan_action_continuation(
            parent_plan=parent,
            continuation_plan=continuation,
            allocation=no_families,
        )


def test_continuation_cannot_change_existing_private_input_authority():
    target = _target()
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={
            "active_testing": True,
            "allow_state_changing_http": True,
            "include_families": ["xss"],
        },
        approval_receipt_id="approval-1",
    )
    collection = ({
        "collection_id": "collection-a",
        "selection_id": "selection-a",
        "binding_id": "binding-a",
        "version": 1,
        "selection_digest": "a" * 64,
        "active": True,
        "max_requests": 1,
    },)
    request_ref = ScanWorkManifestReference(
        manifest_id="70000000-0000-4000-8000-000000000090",
        kind="request",
        content_schema="request-manifest/v1",
        manifest_digest="d" * 64,
        entry_count=1,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="70000000-0000-4000-8000-000000000091",
        kind="request_candidate",
        content_schema="request-candidate-manifest/v1",
        manifest_digest="f" * 64,
        entry_count=1,
        status="complete",
    ).canonical_dict()
    parent_raw = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        request_collection_refs=collection,
        request_manifest_refs={"a" * 64: request_ref},
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
        max_candidate_entries=contract.budget.max_http_requests,
        allowed_capabilities=("xss.verify",),
    )
    continuation = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=contract.execution_plan,
        target_binding=target,
        request_collection_refs=collection,
        request_manifest_refs={"a" * 64: request_ref},
        request_candidate_manifest_ref=candidate_ref,
        action_scope="endpoint",
        action_budgets={"inputs.collection_00": {}},
    )
    changed = tuple(
        replace(
            action,
            capability_args={
                **dict(action.capability_args),
                "request_collection_ref": {
                    **dict(action.capability_args["request_collection_ref"]),
                    "selection_digest": "e" * 64,
                },
            },
            action_digest=None,
        )
        if action.action_id == "inputs.collection_00" else action
        for action in continuation.actions
    )
    tampered = type(continuation)(
        scan_id=continuation.scan_id,
        execution_plan_digest=continuation.execution_plan_digest,
        target_binding_digest=continuation.target_binding_digest,
        actions=changed,
    )

    with pytest.raises(ScanContinuationError, match="changed credential or collection"):
        merge_scan_action_continuation(
            parent_plan=parent,
            continuation_plan=tampered,
            allocation=allocation,
        )


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
