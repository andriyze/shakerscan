"""Canonical admission action compilation, shared by public and internal Scan routes."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

try:
    import agent_tools
    from runtime.models import TargetBinding
except ModuleNotFoundError:
    from .. import agent_tools
    from ..runtime.models import TargetBinding
from .action_plan import (
    ScanActionPlan, ScanActionPlanCompiler, credential_profile_action_refs,
    request_collection_action_refs,
)
from .budget_allocator import (
    allocate_scan_action_plan, ScanBudgetAllocationError, MANDATORY_ACTION_IDS,
)
from .contracts import (
    ResolvedScanContract, SCAN_V2_FAMILY_NAMES, scan_family_capabilities,
    scan_family_required_capability,
)
from .continuation import (
    ScanContinuationAllocation, scan_submission_hold_budget,
    policy_constrained_hold_budget,
)
from .external_process import fit_reservation_scaled_profile


def _compile_allocated_scan_action_plan(
    *,
    scan_id: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
    credential_refs: Sequence[Mapping[str, Any]] = (),
    browser_login_profile_refs: Sequence[Mapping[str, Any]] = (),
    request_collection_refs: Sequence[Mapping[str, Any]] = (),
    request_manifest_refs: Mapping[str, Mapping[str, Any]] | None = None,
    endpoint_manifest_ref: Mapping[str, Any] | None = None,
    candidate_manifest_ref: Mapping[str, Any] | None = None,
    request_candidate_manifest_ref: Mapping[str, Any] | None = None,
    template_manifest_ref: Mapping[str, Any] | None = None,
):
    raw_plan = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=scan_contract.execution_plan,
        target_binding=target_binding,
        credential_profile_refs=credential_profile_action_refs(credential_refs),
        browser_login_profile_refs=browser_login_profile_refs,
        request_collection_refs=request_collection_action_refs(
            request_collection_refs
        ),
        request_manifest_refs=request_manifest_refs,
        endpoint_manifest_ref=endpoint_manifest_ref,
        candidate_manifest_ref=candidate_manifest_ref,
        request_candidate_manifest_ref=request_candidate_manifest_ref,
        template_manifest_ref=template_manifest_ref,
    )
    return allocate_scan_action_plan(
        raw_plan, scan_contract.budget,
    ).plan


def _compile_scan_admission_action_authority(
    *,
    scan_id: str,
    scan_contract: ResolvedScanContract,
    target_binding: TargetBinding,
    credential_refs: Sequence[Mapping[str, Any]] = (),
    browser_login_profile_refs: Sequence[Mapping[str, Any]] = (),
    request_collection_refs: Sequence[Mapping[str, Any]] = (),
    request_manifest_refs: Mapping[str, Mapping[str, Any]] | None = None,
    endpoint_manifest_ref: Mapping[str, Any] | None = None,
    candidate_manifest_ref: Mapping[str, Any] | None = None,
    request_candidate_manifest_ref: Mapping[str, Any] | None = None,
    template_manifest_ref: Mapping[str, Any] | None = None,
) -> tuple[ScanActionPlan, ScanContinuationAllocation | None]:
    """Compile admission traffic and freeze all residual active-test authority."""
    if not scan_contract.policy.active_testing:
        return (
            _compile_allocated_scan_action_plan(
                scan_id=scan_id,
                scan_contract=scan_contract,
                target_binding=target_binding,
                credential_refs=credential_refs,
                browser_login_profile_refs=browser_login_profile_refs,
                request_collection_refs=request_collection_refs,
                request_manifest_refs=request_manifest_refs,
                endpoint_manifest_ref=endpoint_manifest_ref,
                candidate_manifest_ref=candidate_manifest_ref,
                request_candidate_manifest_ref=request_candidate_manifest_ref,
                template_manifest_ref=template_manifest_ref,
            ),
            None,
        )

    # Derive continuation authority from the canonical family registry.
    included = set(scan_contract.policy.include_families)
    excluded = set(scan_contract.policy.exclude_families)
    required_capabilities = tuple(
        scan_family_required_capability(family)
        for family in SCAN_V2_FAMILY_NAMES
        if family in included and family not in excluded
        and scan_family_required_capability(family) is not None
    )
    allowed_capabilities = {
        capability
        for family in SCAN_V2_FAMILY_NAMES
        if family not in excluded and (not included or family in included)
        for capability in scan_family_capabilities(family)
    }
    required_holds = (*required_capabilities, "scan.finalize")

    raw_parent = ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=scan_contract.execution_plan,
        target_binding=target_binding,
        credential_profile_refs=credential_profile_action_refs(credential_refs),
        browser_login_profile_refs=browser_login_profile_refs,
        request_collection_refs=request_collection_action_refs(
            request_collection_refs
        ),
        request_manifest_refs=request_manifest_refs,
        endpoint_manifest_ref=endpoint_manifest_ref,
        candidate_manifest_ref=candidate_manifest_ref,
        request_candidate_manifest_ref=request_candidate_manifest_ref,
        template_manifest_ref=template_manifest_ref,
        defer_manifest_actions=True,
        include_finalizer=False,
    )

    ledger_limits = scan_contract.budget.ledger_limits()
    # Room that mandatory parent-admission traffic MUST run in -- an operator's
    # request-collection replay, a required credential login, the baseline probes --
    # is not available to hold back for the deferred continuation. Subtract it before
    # sizing the hold so a required admission action is never starved by the hold kept
    # for a later verifier (which itself degrades gracefully to a smaller reviewed tier).
    required_admission_cost: dict[str, int] = {}
    for action in raw_parent.actions:
        if action.required or action.action_id in MANDATORY_ACTION_IDS:
            for name, amount in action.requested_budget.items():
                required_admission_cost[name] = (
                    required_admission_cost.get(name, 0) + int(amount)
                )

    # Hold room for the LARGEST single required capability, capped at what this profile
    # owns AFTER mandatory admission traffic -- not the sum of them all. See
    # scan_submission_hold_budget for why the per-capability cap matters.
    reserved_hold = scan_submission_hold_budget(
        agent_tools.CAPABILITY_REGISTRY, required_holds,
        allow_state_changing_http=scan_contract.policy.allow_state_changing_http,
        limits=ledger_limits,
    )
    reserved_budget = {
        name: min(
            amount,
            max(0, ledger_limits.get(name, 0) - required_admission_cost.get(name, 0)),
        )
        for name, amount in reserved_hold.items()
    }
    parent_allocation = allocate_scan_action_plan(
        raw_parent,
        scan_contract.budget,
        assign_residual_to_finalizer=False,
        require_finalizer=False,
        reserved_budget=reserved_budget,
    )
    remaining = dict(parent_allocation.residual_scan_execute_budget)
    for capability_name in required_holds:
        hold_budget = policy_constrained_hold_budget(
            agent_tools.CAPABILITY_REGISTRY, capability_name,
            allow_state_changing_http=scan_contract.policy.allow_state_changing_http,
        )
        # A required verifier whose full registry cost exceeds this profile still runs
        # if a reviewed scaled tier fits the residual -- the same graceful degradation
        # the allocator performs mid-plan. Reject only when not even that tier fits, so
        # a bounded active scan (small state_changing ceiling) is not refused for a
        # verifier that can execute its query-only tier.
        effective_hold = fit_reservation_scaled_profile(
            capability_name, requested=hold_budget, available=remaining,
        ) or hold_budget
        shortages = {
            name: amount - remaining.get(name, 0)
            for name, amount in effective_hold.items()
            if amount > remaining.get(name, 0)
        }
        if shortages:
            raise ScanBudgetAllocationError(capability_name, shortages)

    parent_plan = parent_allocation.plan
    continuation = ScanContinuationAllocation(
        scan_id=scan_id,
        parent_plan_digest=str(parent_plan.plan_digest),
        execution_plan_digest=parent_plan.execution_plan_digest,
        target_binding_digest=parent_plan.target_binding_digest,
        parent_action_ids=tuple(
            action.action_id for action in parent_plan.actions
        ),
        budget_ceiling=parent_allocation.residual_scan_execute_budget,
        max_endpoint_entries=scan_contract.budget.max_endpoints,
        max_candidate_entries=max(
            1,
            min(
                20_000,
                scan_contract.budget.max_http_requests,
                scan_contract.budget.max_endpoints * 64,
            ),
        ),
        required_capabilities=required_capabilities,
        allowed_capabilities=tuple(sorted(allowed_capabilities)),
    )
    return parent_plan, continuation
