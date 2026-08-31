from __future__ import annotations

import uuid

import pytest

from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.action_plan import (
    ScanActionPlacementError,
    ScanActionPlanCompiler,
    ScanActionPlanError,
    credential_profile_action_refs,
    request_collection_action_refs,
)
from api.scan.budget_allocator import allocate_scan_action_plan
from api.scan.work_manifests import (
    ScanWorkManifestReference,
    build_canonical_passive_nuclei_template_manifest,
    build_canonical_scan_nuclei_template_manifest,
)
from api.scan.execution import ScanExecutionPlan


SCAN_ID = str(uuid.UUID("10000000-0000-0000-0000-000000000001"))


def _budget() -> ScanBudget:
    return ScanBudget(1_200, 20_000, 2_000, 200, 5_000, 900, 4)


def _target() -> TargetBinding:
    return TargetBinding(
        target_id=str(uuid.UUID("10000000-0000-0000-0000-000000000002")),
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test", "http://app.example.test"),
        allowed_addresses=("192.0.2.10", "2001:db8::10"),
        allowed_root_domains=("example.test",),
        scope_receipt_id=str(uuid.UUID("10000000-0000-0000-0000-000000000003")),
    )


def _execution(
    *, include=(), exclude=(), active=True, network=False, subdomains=False,
    state=False,
):
    return ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            allow_state_changing_http=state,
            network_discovery=network,
            subdomain_discovery=subdomains,
            include_families=tuple(include),
            exclude_families=tuple(exclude),
            scope_receipt_id=_target().scope_receipt_id,
            approval_receipt_id=(
                str(uuid.UUID("10000000-0000-0000-0000-000000000004"))
                if active else None
            ),
        ),
        budget_profile="balanced",
        budget=_budget(),
    )


def _request_manifest_ref(manifest_id: str, digest: str, count: int = 1):
    return ScanWorkManifestReference(
        manifest_id=manifest_id,
        kind="request",
        content_schema="request-manifest/v2",
        manifest_digest=digest,
        entry_count=count,
        status="complete",
    ).canonical_dict()


def _request_candidate_manifest_ref(count: int = 1):
    return ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000090",
        kind="request_candidate",
        content_schema="request-candidate-manifest/v2",
        manifest_digest="9" * 64,
        entry_count=count,
        status="complete",
    ).canonical_dict()


def test_full_plan_does_not_schedule_unreviewed_external_intelligence():
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("recon",), active=False),
        target_binding=_target(),
    )

    assert "infrastructure.inspect" not in {
        action.capability_name for action in plan.actions
    }


def test_large_manifest_compiles_to_bounded_batch_graph():
    endpoint_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000083",
        kind="endpoint",
        content_schema="endpoint-manifest/v2",
        manifest_digest="c" * 64,
        entry_count=1526,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000084",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="d" * 64,
        entry_count=1526,
        status="complete",
    ).canonical_dict()
    templates = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
        include_active=True,
    ).reference().canonical_dict()
    base = _execution(include=(
        "xss", "sqli", "nuclei_passive", "nuclei_active",
    ))
    execution = ScanExecutionPlan(
        policy=base.policy,
        budget_profile="thorough",
        budget=base.budget,
    )

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        template_manifest_ref=templates,
        action_scope="endpoint",
    )
    batches = [
        action for action in plan.actions
        if action.capability_name.endswith("_batch")
    ]

    assert len(plan.actions) < 100
    assert {action.capability_name for action in batches} == {
        "templates.passive_batch", "templates.active_batch",
        "xss.verify_batch", "xss.browser_prove_batch",
        "sqli.verify_batch", "sqli.prove_batch",
    }
    assert all(1 <= action.capability_args["slice"]["count"] <= 50 for action in batches)
    assert sum(action.required for action in batches if action.capability_name == "xss.verify_batch") == 2
    assert sum(action.required for action in batches if action.capability_name == "sqli.verify_batch") == 2


def test_compiler_adds_exact_request_batches_with_class_aware_mutation_budget():
    compiler = ScanActionPlanCompiler()
    disabled = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss", "sqli"), state=False),
        target_binding=_target(),
        request_candidate_manifest_ref=_request_candidate_manifest_ref(),
    )
    disabled_actions = [
        action for action in disabled.actions
        if action.capability_name in {
            "xss.request_verify_batch", "sqli.request_verify_batch",
        }
    ]
    assert len(disabled_actions) == 2
    assert all("state_changing_requests" not in action.requested_budget for action in disabled_actions)

    enabled = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss", "sqli"), state=True),
        target_binding=_target(),
        request_candidate_manifest_ref=_request_candidate_manifest_ref(2),
    )
    request_actions = [
        action for action in enabled.actions
        if action.capability_name in {
            "xss.request_verify_batch", "sqli.request_verify_batch",
        }
    ]

    assert [action.capability_name for action in request_actions] == [
        "xss.request_verify_batch", "sqli.request_verify_batch",
    ]
    assert all(action.requested_budget["http_requests"] == 4 for action in request_actions)
    assert all(
        action.requested_budget["state_changing_requests"] == 4
        for action in request_actions
    )
    assert all(
        action.capability_args["request_candidate_manifest_ref"]
        == _request_candidate_manifest_ref(2)
        for action in request_actions
    )


def test_parallel_family_scope_narrows_actions_and_is_digest_bound():
    endpoint_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000081",
        kind="endpoint",
        content_schema="endpoint-manifest/v2",
        manifest_digest="a" * 64,
        entry_count=2,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000082",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="b" * 64,
        entry_count=2,
        status="complete",
    ).canonical_dict()
    compiler = ScanActionPlanCompiler()
    execution = _execution(include=("xss", "sqli"), exclude=("recon",))

    xss = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        action_scope="endpoint",
        family_scope=("xss",),
    )
    sqli = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        action_scope="endpoint",
        family_scope=("sqli",),
    )

    assert any(action.capability_name == "xss.verify_batch" for action in xss.actions)
    assert not any(action.capability_name == "sqli.verify_batch" for action in xss.actions)
    assert any(action.capability_name == "sqli.verify_batch" for action in sqli.actions)
    assert not any(action.capability_name == "xss.verify_batch" for action in sqli.actions)
    assert xss.plan_digest != sqli.plan_digest
    assert xss.actions[0].input_binding_digest != sqli.actions[0].input_binding_digest


def test_parallel_family_scope_cannot_widen_parent_policy():
    with pytest.raises(ScanActionPlanError, match="cannot widen"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(include=("xss",), exclude=("sqli",)),
            target_binding=_target(),
            action_scope="endpoint",
            family_scope=("sqli",),
        )


def test_endpoint_request_verifiers_depend_on_collection_replay_inputs():
    collection = ({
        "collection_id": "collection-a",
        "selection_id": "selection-a",
        "binding_id": "binding-a",
        "version": 1,
        "selection_digest": "a" * 64,
        "active": True,
        "max_requests": 1,
    },)
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(
            include=("xss", "sqli"), state=True,
        ),
        target_binding=_target(),
        request_collection_refs=collection,
        request_manifest_refs={
            "a" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000082", "3" * 64,
            ),
        },
        request_candidate_manifest_ref=_request_candidate_manifest_ref(1),
        action_scope="endpoint",
        action_budgets={"inputs.collection_00": {}},
    )
    by_id = {action.action_id: action for action in plan.actions}

    assert by_id["inputs.collection_00"].requested_budget == {}
    assert by_id["verify.request_xss"].dependencies == (
        "inputs.collection_00",
    )
    assert by_id["verify.request_sqli"].dependencies == (
        "inputs.collection_00",
    )


def test_endpoint_request_verification_rejects_missing_private_replay_inputs():
    with pytest.raises(
        ScanActionPlanError,
        match="requires immutable collection replay inputs",
    ):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(include=("xss",), state=True),
            target_binding=_target(),
            request_candidate_manifest_ref=_request_candidate_manifest_ref(),
            action_scope="endpoint",
        )


def test_compiler_closes_focused_xss_prerequisites_without_unrequested_families():
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",), exclude=("recon",)),
        target_binding=_target(),
        candidate_manifest_ref={},
    )
    by_id = {action.action_id: action for action in plan.actions}

    assert "discover.web_probe" in by_id
    assert "discover.web_crawl" in by_id
    assert by_id["discover.web_crawl"].required is True
    assert by_id["discover.web_crawl"].supporting is True
    assert by_id["verify.xss"].dependencies == (
        "discover.web_probe", "discover.web_crawl",
    )
    assert "verify.sqli" not in by_id
    assert "active.templates" not in by_id
    assert "discover.web_content" not in by_id
    assert by_id["baseline.http_redirect"].requested_budget["http_requests"] == 2
    assert by_id["baseline.tls"].capability_args == {
        "origins_ref": "frozen_https_origins",
        "origin_count": 1,
        "addresses_ref": "frozen_addresses",
        "address_count": 2,
    }
    assert by_id["baseline.tls"].requested_budget == {
        "tcp_ports_attempted": 8,
        "tool_wall_seconds": 30,
    }
    assert plan.actions[-1].action_id == "finalize.report"
    assert plan.actions[-1].capability_name == "scan.finalize"
    assert plan.actions[-1].placement["adapter_name"] == "scanner.report"
    assert set(plan.actions[-1].dependencies) == set(by_id) - {"finalize.report"}


def test_passive_scan_compiles_bounded_read_only_surface_discovery():
    template_manifest = build_canonical_passive_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(active=False),
        target_binding=_target(),
        template_manifest_ref=template_manifest.reference().canonical_dict(),
    )
    by_id = {action.action_id: action for action in plan.actions}

    assert {"discover.web_probe", "discover.web_crawl", "discover.web_content"} <= set(
        by_id
    )
    assert "active.templates" not in by_id
    assert by_id["passive.templates"].capability_name == (
        "templates.passive_batch"
    )
    assert by_id["passive.templates"].dependencies == ()
    assert by_id["passive.templates"].capability_args["target_ref"] == (
        "canonical_origin"
    )
    assert "verify.xss" not in by_id
    assert "verify.sqli" not in by_id
    assert by_id["discover.web_crawl"].capability_args["read_only"] is True
    for action_id in (
        "discover.web_probe", "discover.web_crawl", "discover.web_content",
    ):
        spec = CAPABILITY_REGISTRY.require(by_id[action_id].capability_name)
        assert spec.risk_tier in {"read_only", "passive"}
        assert spec.required_approval is None
        assert by_id[action_id].requested_budget.get("state_changing_requests", 0) == 0


def test_compiler_requires_and_binds_one_complete_nuclei_template_manifest():
    with pytest.raises(ScanActionPlanError, match="immutable template manifest"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(include=("nuclei_active",)),
            target_binding=_target(),
        )

    manifest = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
        include_active=True,
    )
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("nuclei_active",)),
        target_binding=_target(),
        template_manifest_ref=manifest.reference().canonical_dict(),
    )
    action = next(
        item for item in plan.actions if item.capability_name == "templates.active_batch"
    )
    assert action.capability_args["template_manifest_ref"] == (
        manifest.reference().canonical_dict()
    )


def test_compiler_binds_opaque_inputs_and_is_independent_of_reference_order():
    credentials = (
        {"profile_id": "secondary-id", "version": 2, "digest": "d" * 64, "lane": "secondary", "auth_kind": "form_login"},
        {"profile_id": "primary-id", "version": 4, "digest": "e" * 64, "lane": "primary", "auth_kind": "form_login"},
    )
    collections = (
        {
            "collection_id": "collection-b", "selection_id": "selection-b",
            "binding_id": "binding-b", "version": 1,
            "selection_digest": "f" * 64,
        },
        {
            "collection_id": "collection-a", "selection_id": "selection-a",
            "binding_id": "binding-a", "version": 3,
            "selection_digest": "a" * 64,
        },
    )
    compiler = ScanActionPlanCompiler()
    first = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",)),
        target_binding=_target(),
        credential_profile_refs=credentials,
        request_collection_refs=collections,
        request_manifest_refs={
            "f" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000080", "1" * 64,
            ),
            "a" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000081", "2" * 64,
            ),
        },
        authority_refs={"approval_receipt_digest": "b" * 64},
    )
    second = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",)),
        target_binding=_target(),
        credential_profile_refs=tuple(reversed(credentials)),
        request_collection_refs=tuple(reversed(collections)),
        request_manifest_refs={
            "a" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000081", "2" * 64,
            ),
            "f" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000080", "1" * 64,
            ),
        },
        authority_refs={"approval_receipt_digest": "b" * 64},
    )

    assert first == second
    assert first.plan_digest == second.plan_digest
    assert {action.action_id for action in first.actions} >= {
        "inputs.auth_primary", "inputs.auth_secondary", "verify.authz",
        "inputs.collection_00", "inputs.collection_01",
    }
    assert all(len(action.input_binding_digest) == 64 for action in first.actions)
    serialized = str(first.canonical_dict())
    assert "password" not in serialized
    assert "Bearer" not in serialized


def test_compiler_fails_closed_on_missing_placement_or_untrusted_reference_fields():
    all_capabilities = {spec.name for spec in CAPABILITY_REGISTRY.list()}
    passive_templates = build_canonical_passive_nuclei_template_manifest(
        scan_id=SCAN_ID,
        target_binding_digest=_target().digest,
    )
    with pytest.raises(ScanActionPlacementError, match="web.probe"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(active=False),
            target_binding=_target(),
            template_manifest_ref=(
                passive_templates.reference().canonical_dict()
            ),
            available_placement_capabilities=all_capabilities - {"web.probe"},
        )

    wrong_kind = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000099",
        kind="template",
        content_schema="template-manifest/v1",
        manifest_digest="a" * 64,
        entry_count=1,
        status="complete",
    )
    with pytest.raises(ScanActionPlanError, match="wrong kind"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(active=False),
            target_binding=_target(),
            endpoint_manifest_ref=wrong_kind.canonical_dict(),
        )

    with pytest.raises(ScanActionPlanError, match="reference fields"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(active=False),
            target_binding=_target(),
            credential_profile_refs=({
                "profile_id": "profile", "version": 1, "digest": "a" * 64,
                "lane": "primary", "password": "must-not-enter-plan",
            },),
        )

    with pytest.raises(ScanActionPlanError, match="exactly cover"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(active=False),
            target_binding=_target(),
            request_collection_refs=({
                "collection_id": "collection-1",
                "selection_id": "selection-1",
                "binding_id": "binding-1",
                "version": 1,
                "selection_digest": "a" * 64,
                "active": False,
            },),
        )


def test_compiler_includes_explicit_network_and_subdomain_dependencies():
    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(
            include=("recon",), network=True, subdomains=True,
        ),
        target_binding=_target(),
    )
    by_id = {action.action_id: action for action in plan.actions}
    assert by_id["discover.subdomains"].required is True
    assert by_id["discover.ports"].required is True
    assert by_id["discover.services"].dependencies == ("discover.ports",)
    assert by_id["discover.services"].supporting is True


def test_shard_action_scopes_assign_global_and_endpoint_work_without_duplicates():
    endpoint_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000090",
        kind="endpoint",
        content_schema="endpoint-manifest/v2",
        manifest_digest="9" * 64,
        entry_count=4,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000091",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="8" * 64,
        entry_count=4,
        status="complete",
    ).canonical_dict()
    credentials = ({
        "profile_id": "primary-id",
        "version": 2,
        "digest": "7" * 64,
        "lane": "primary",
        "auth_kind": "form_login",
    },)

    endpoint = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",), exclude=("recon",)),
        target_binding=_target(),
        credential_profile_refs=credentials,
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        shard_authority={"options_digest": "6" * 64},
        action_scope="endpoint",
    )
    endpoint_by_id = {action.action_id: action for action in endpoint.actions}
    # Assert the work the shard owns, not how many actions it took to express it:
    # a slice is sized to what its reservation funds, so the same candidates may
    # arrive as several occurrences of the same logical verifier.
    assert {
        action.capability_name for action in endpoint.actions
    } == {
        "auth.session.establish", "xss.verify_batch",
        "xss.browser_prove_batch", "scan.finalize",
    }
    assert {"inputs.auth_primary", "prove.xss", "finalize.report"} <= set(endpoint_by_id)
    xss_actions = [
        action for action in endpoint.actions
        if action.capability_name == "xss.verify_batch"
    ]
    assert all(
        action.dependencies == ("inputs.auth_primary",)
        for action in xss_actions
    )
    # Every candidate is covered exactly once across the slices: no gap, no
    # duplicate, which is the property this test exists to hold.
    covered: list[int] = []
    for action in xss_actions:
        window = action.capability_args["slice"]
        covered.extend(
            range(int(window["start"]), int(window["start"]) + int(window["count"]))
        )
    assert covered == sorted(covered)
    assert len(covered) == len(set(covered)), "a candidate was sliced twice"
    assert set(covered) == set(range(4)), f"candidates covered: {sorted(set(covered))}"
    assert all(
        action.capability_args["candidate_manifest_ref"] == candidate_ref
        and action.capability_args["endpoint_manifest_ref"] == endpoint_ref
        for action in xss_actions
    )

    discovery = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",)),
        target_binding=_target(),
        credential_profile_refs=credentials,
        action_scope="discovery",
        shard_authority={"options_digest": "5" * 64},
    )
    discovery_ids = {action.action_id for action in discovery.actions}
    assert "discover.web_probe" in discovery_ids
    assert "discover.web_crawl" in discovery_ids
    assert "baseline.http" not in discovery_ids
    assert "verify.xss" not in discovery_ids


def test_explicit_xss_family_compiles_its_minimum_executable_quota():
    endpoint_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000092",
        kind="endpoint",
        content_schema="endpoint-manifest/v2",
        manifest_digest="7" * 64,
        entry_count=100,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000093",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="6" * 64,
        entry_count=100,
        status="complete",
    ).canonical_dict()

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",), exclude=("recon",)),
        target_binding=_target(),
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        action_scope="full",
    )
    actions = [
        action for action in plan.actions if action.capability_name == "xss.verify_batch"
    ]

    assert len(actions) >= 1
    # The quota is how many candidates the family can execute, not how many one
    # slice declares. A slice is now sized to what its own reservation funds, so
    # the same quota is met across more batches instead of being promised in one
    # oversized slice the budget could never pay for.
    planned = sum(
        int(action.capability_args["slice"]["count"]) for action in actions
    )
    assert planned >= 20, f"xss planned only {planned} candidates"
    assert all(
        int(action.capability_args["slice"]["count"]) <= 3 for action in actions
    ), "a balanced XSS slice must stay within what its reservation funds"
    allocation = allocate_scan_action_plan(plan, _budget())
    allocated_actions = [
        action for action in allocation.plan.actions
        if action.capability_name == "xss.verify_batch"
        and action.admission_status == "planned"
    ]
    assert len(allocated_actions) >= 1
    assert all(
        action.admission_status == "planned"
        for action in allocation.plan.actions
        if action.required
    )


def test_resolved_family_allowlist_removes_all_unselected_xss_actions():
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000094",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="5" * 64,
        entry_count=100,
        status="complete",
    ).canonical_dict()
    execution = _execution(include=("sqli",), exclude=("xss", "recon"))

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=execution,
        target_binding=_target(),
        candidate_manifest_ref=candidate_ref,
        action_scope="full",
    )

    assert not any(action.capability_name.startswith("xss.") for action in plan.actions)
    assert any(action.capability_name == "sqli.verify_batch" for action in plan.actions)


def test_explicit_verifier_remains_visible_when_candidate_manifest_is_empty():
    endpoint_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000094",
        kind="endpoint",
        content_schema="endpoint-manifest/v2",
        manifest_digest="5" * 64,
        entry_count=1,
        status="complete",
    ).canonical_dict()
    candidate_ref = ScanWorkManifestReference(
        manifest_id="10000000-0000-4000-8000-000000000095",
        kind="candidate",
        content_schema="candidate-manifest/v1",
        manifest_digest="4" * 64,
        entry_count=0,
        status="complete",
    ).canonical_dict()

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("xss",), exclude=("recon",)),
        target_binding=_target(),
        endpoint_manifest_ref=endpoint_ref,
        candidate_manifest_ref=candidate_ref,
        action_scope="endpoint",
    )
    verifier = next(
        action for action in plan.actions
        if action.capability_name == "xss.verify_batch"
    )

    assert verifier.required is True
    assert verifier.capability_args["slice"] == {"start": 0, "count": 1}
    assert verifier.capability_args["candidate_manifest_ref"] == candidate_ref


def test_admitted_private_inputs_reduce_to_versioned_content_free_plan_refs():
    credentials = credential_profile_action_refs(({
        "profile_id": "profile-1",
        "profile_version": 3,
        "scan_lane": "primary",
        "target_kind": "web",
        "auth_kind": "bearer_token",
        "secret_values_visible": False,
    },))
    collections = request_collection_action_refs(({
        "collection_id": "collection-1",
        "selection_id": "selection-1",
        "binding_id": "binding-1",
        "selection_digest": "a" * 64,
        "replay_policy": "confirmed_active",
        "selected_requests": 8,
        "selector": {"max_requests": 20},
    },))

    assert credentials == ({
        "profile_id": "profile-1",
        "version": 3,
        "digest": credentials[0]["digest"],
        "lane": "primary",
        "auth_kind": "bearer_token",
    },)
    assert len(credentials[0]["digest"]) == 64
    assert collections == ({
        "collection_id": "collection-1",
        "selection_id": "selection-1",
        "binding_id": "binding-1",
        "version": 1,
        "selection_digest": "a" * 64,
        "active": True,
        "replay_policy": "confirmed_active",
        "max_requests": 8,
    },)

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",), state=True),
        target_binding=_target(),
        credential_profile_refs=credentials,
        request_collection_refs=collections,
        request_manifest_refs={
            "a" * 64: _request_manifest_ref(
                "10000000-0000-4000-8000-000000000082", "3" * 64,
                count=8,
            ),
        },
    )
    replay = next(
        action for action in plan.actions
        if action.capability_name == "collections.replay_active"
    )
    assert replay.capability_args["request_collection_ref"] == collections[0]
    assert replay.capability_args["request_manifest_ref"]["entry_count"] == 8
    assert all(
        action.capability_name != "auth.session.establish"
        for action in plan.actions
    )
    assert replay.requested_budget["http_requests"] == 8
    assert replay.requested_budget["state_changing_requests"] == 8


@pytest.mark.parametrize(
    ("submitted_kind", "canonical_kind"),
    [
        ("custom_headers", "custom_headers"),
        ("query_parameter", "query_parameter"),
        ("multi_header", "custom_headers"),
        ("query_param", "query_parameter"),
    ],
)
def test_credential_action_refs_use_the_canonical_runtime_vocabulary(
    submitted_kind, canonical_kind,
):
    reference = credential_profile_action_refs(({
        "profile_id": "profile-1",
        "profile_version": 3,
        "scan_lane": "primary",
        "target_kind": "web",
        "auth_kind": submitted_kind,
    },))[0]

    assert reference["auth_kind"] == canonical_kind


def test_every_budget_profile_compiles_an_explicitly_requested_active_family():
    """A profile's published batch minimum must be reservable at admission.

    The candidate manifest does not exist when the plan is first compiled -- its
    entries arrive through the discovery continuation. total_batches was derived
    from that empty manifest and so capped the batch count at one, while
    thorough publishes a minimum of two XSS batches. Every thorough scan that
    explicitly requested XSS therefore failed to compile with "required batch
    action verify.xss exceeds plan graph capacity", which is what the benchmark
    fixture asks for, so no thorough benchmark could ever run.
    """
    from api.scan.contracts import resolve_scan_contract

    binding = TargetBinding(
        target_id="t1",
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    approval = "11111111-1111-4111-8111-111111111111"
    policy = {
        "preset": "custom",
        "active_testing": True,
        "include_families": ["recon", "xss", "sqli"],
        "exclude_families": [
            "nuclei_passive", "nuclei_active", "bola",
            "sensitive_exposure", "nosqli", "authz_surface",
        ],
    }
    batches_by_profile = {}
    for profile in ("fast", "balanced", "thorough"):
        contract = resolve_scan_contract(
            budget_profile=profile, policy=policy, approval_receipt_id=approval,
        )
        plan = ScanActionPlanCompiler().compile(
            scan_id=str(uuid.UUID("10000000-0000-4000-8000-000000000001")),
            execution_plan=contract.execution_plan,
            target_binding=binding,
        )
        batches_by_profile[profile] = sum(
            1 for action in plan.actions if action.capability_name == "xss.verify_batch"
        )
        assert any(
            action.capability_name == "sqli.verify_batch" for action in plan.actions
        ), f"{profile} compiled no SQLi verification for an explicit sqli request"

    assert batches_by_profile["fast"] >= 1
    assert batches_by_profile["balanced"] >= 1
    # thorough publishes a higher minimum and must actually get it.
    assert batches_by_profile["thorough"] >= 2, batches_by_profile


def test_a_small_candidate_manifest_does_not_fail_a_required_family():
    """A profile minimum is an intent, not a floor that fails on little work.

    thorough publishes a two-batch XSS minimum. The continuation compiles with
    the REAL candidate manifest, so any target yielding fewer candidates than
    two batches raised "required batch action verify.xss exceeds plan graph
    capacity" and failed the whole scan -- which is why no thorough scan against
    a modest target such as Juice Shop could complete.
    """
    from api.scan.contracts import resolve_scan_contract
    from api.scan.work_manifests import (
        WORK_MANIFEST_CONTENT_SCHEMAS, ScanWorkManifestReference,
    )

    binding = TargetBinding(
        target_id="t1",
        target_kind="web",
        canonical_host="example.test",
        allowed_origins=("https://example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )
    contract = resolve_scan_contract(
        budget_profile="thorough",
        policy={
            "preset": "custom",
            "active_testing": True,
            "include_families": ["recon", "xss", "sqli"],
        },
        approval_receipt_id="11111111-1111-4111-8111-111111111111",
    )
    for entry_count in (1, 3, 10, 60, 200):
        reference = ScanWorkManifestReference(
            manifest_id="00000000-0000-4000-8000-0000000000aa",
            kind="candidate",
            content_schema=WORK_MANIFEST_CONTENT_SCHEMAS["candidate"],
            manifest_digest="a" * 64,
            entry_count=entry_count,
            status="complete",
        ).canonical_dict()
        plan = ScanActionPlanCompiler().compile(
            scan_id=str(uuid.UUID("10000000-0000-4000-8000-000000000001")),
            execution_plan=contract.execution_plan,
            target_binding=binding,
            candidate_manifest_ref=reference,
        )
        batches = [
            action for action in plan.actions
            if action.capability_name == "xss.verify_batch"
        ]
        assert batches, f"{entry_count} candidates compiled no XSS verification"
        # The family still runs; it simply gets the batches its work needs.
        # A slice is sized to what its own reservation funds, so the batch count
        # follows that size rather than the old, unfundable 50.
        slice_size = max(
            int(action.capability_args["slice"]["count"]) for action in batches
        )
        assert slice_size <= 8
        assert len(batches) <= max(1, (entry_count + slice_size - 1) // slice_size) + 1
