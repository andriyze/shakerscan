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
    assert plan.actions[-1].action_id == "finalize.report"
    assert set(plan.actions[-1].dependencies) == set(by_id) - {"finalize.report"}


def test_compiler_binds_opaque_inputs_and_is_independent_of_reference_order():
    credentials = (
        {"profile_id": "secondary-id", "version": 2, "digest": "d" * 64, "lane": "secondary"},
        {"profile_id": "primary-id", "version": 4, "digest": "e" * 64, "lane": "primary"},
    )
    collections = (
        {"collection_id": "collection-b", "version": 1, "selection_digest": "f" * 64},
        {"collection_id": "collection-a", "version": 3, "selection_digest": "a" * 64},
    )
    compiler = ScanActionPlanCompiler()
    first = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",)),
        target_binding=_target(),
        credential_profile_refs=credentials,
        request_collection_refs=collections,
        authority_refs={"approval_receipt_digest": "b" * 64},
    )
    second = compiler.compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",)),
        target_binding=_target(),
        credential_profile_refs=tuple(reversed(credentials)),
        request_collection_refs=tuple(reversed(collections)),
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
    with pytest.raises(ScanActionPlacementError, match="web.probe"):
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID,
            execution_plan=_execution(active=False),
            target_binding=_target(),
            available_placement_capabilities=all_capabilities - {"web.probe"},
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
    },)
    assert len(credentials[0]["digest"]) == 64
    assert collections == ({
        "collection_id": "collection-1",
        "version": 1,
        "selection_digest": "a" * 64,
        "active": True,
        "max_requests": 8,
    },)

    plan = ScanActionPlanCompiler().compile(
        scan_id=SCAN_ID,
        execution_plan=_execution(include=("bola",), state=True),
        target_binding=_target(),
        credential_profile_refs=credentials,
        request_collection_refs=collections,
    )
    replay = next(
        action for action in plan.actions
        if action.capability_name == "collections.replay_active"
    )
    assert replay.requested_budget["http_requests"] == 8
    assert replay.requested_budget["state_changing_requests"] == 8
