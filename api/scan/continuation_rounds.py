"""Bounded, append-only Scan continuation rounds.

The root plan is admitted on worst-case reservations. Once its actions settle, each
continuation round re-plans the discovered work from every lane's first unplanned index,
admits it against the cumulatively reconciled residual, and appends it as one immutable,
digest-bound revision. Rounds stop when the residual can no longer fund a fast-tier batch
or the round bound is reached; the finalizer is then appended as its own terminal
revision, so a Scan that spent all of its rounds still produces a report.

Everything here is worker-neutral: the worker supplies the pool, the dispatcher, the
manifest loader, and the round runner, and keeps its own process-level concerns.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable, Mapping

from .action_plan import (
    ScanAction,
    ScanActionPlan,
    ScanActionPlanCompiler,
    credential_profile_action_refs,
    interactive_auth_input_action_ids,
    request_collection_action_refs,
)
from .action_store import PostgresScanActionStore
from .budget_allocator import allocate_scan_action_plan
from .capability_execution import ScanCapabilityContractError
from .capability_result import CapabilityResultReference
from .continuation import (
    MAX_SCAN_CONTINUATION_ROUNDS,
    ContinuationBudgetCeiling,
    ScanContinuationAllocation,
    ScanContinuationError,
    ScanPlanRevision,
    amended_scan_plan_revision,
    build_discovery_continuation_manifests,
    continuation_manifest_offsets,
    merge_scan_action_continuation,
    reconciled_continuation_ceiling,
)
from .manifest_store import PostgresScanManifestStore
from .work_manifests import (
    ScanWorkManifest,
    ScanWorkManifestKind,
    ScanWorkManifestReference,
    build_request_candidate_manifest,
    unique_work_manifest_reference_dicts,
)

# One graph slot is always retained for the finalizer, including during work-only rounds.
_PLAN_ACTION_BOUND = 511
_INPUT_ACTION_PREFIXES = ("inputs.auth_", "inputs.collection_")
_CANCELLED_MESSAGE = "Cancelled by user"


@dataclass(frozen=True)
class ContinuationRuntime:
    """What one worker lends the round machinery: storage, the dispatcher, and event sinks."""

    db_pool: Any
    dispatcher: Any
    execution_plan: Any
    load_request_manifests: Callable[..., Awaitable[tuple[ScanWorkManifest, ...]]]
    record_event: Callable[[str], None]
    # Store constructors are injected so the worker's own names stay the seam its
    # tests and fault harnesses replace.
    manifest_store_factory: Callable[[], Any] = PostgresScanManifestStore
    action_store_factory: Callable[[], Any] = PostgresScanActionStore


async def load_continuation_request_manifests(
    *,
    db_pool: Any,
    scan_id: str,
    target_binding_digest: str,
    options: Mapping[str, Any],
    on_missing: Callable[[], None],
    manifest_store_factory: Callable[[], Any] = PostgresScanManifestStore,
) -> tuple[ScanWorkManifest, ...]:
    raw_refs = options.get("request_manifest_refs")
    if not isinstance(raw_refs, Mapping):
        return ()
    references: list[ScanWorkManifestReference] = []
    for raw in raw_refs.values():
        if not isinstance(raw, Mapping):
            continue
        reference = ScanWorkManifestReference.from_dict(raw)
        if reference.kind is not ScanWorkManifestKind.REQUEST:
            raise ScanCapabilityContractError(
                "continuation request manifest has the wrong kind"
            )
        references.append(reference)
    manifests: list[ScanWorkManifest] = []
    async with db_pool.acquire() as conn:
        store = manifest_store_factory()
        for reference in references:
            manifest = await store.load(
                conn,
                manifest_id=reference.manifest_id,
                scan_id=scan_id,
                expected_kind=reference.kind,
                expected_digest=reference.manifest_digest,
                expected_target_binding_digest=target_binding_digest,
            )
            if manifest is None or manifest.reference() != reference:
                on_missing()
                raise ScanCapabilityContractError(
                    "continuation request manifest is unavailable"
                )
            manifests.append(manifest)
    return tuple(manifests)


def select_continuation_actions(
    allocated_plan: ScanActionPlan,
    *,
    parent_action_count: int,
    include_finalizer: bool,
    finalize_only: bool,
) -> ScanActionPlan | None:
    """Keep only the admitted work of one round as an independently valid plan.

    Optional actions whose dependencies were skipped are omitted rather than appended as
    terminal noise. Returns ``None`` when a work round admitted nothing, which is the
    round loop's stop signal.
    """
    selected: list[ScanAction] = []
    selected_ids: set[str] = set()
    append_slots = max(0, _PLAN_ACTION_BOUND - parent_action_count)
    appended_work = 0
    for action in allocated_plan.actions:
        if action.action_id.startswith(_INPUT_ACTION_PREFIXES):
            selected.append(action)
            selected_ids.add(action.action_id)
            continue
        if action.action_id == "finalize.report":
            continue
        if finalize_only or action.admission_status != "planned":
            continue
        if any(dependency not in selected_ids for dependency in action.dependencies):
            continue
        if appended_work >= append_slots:
            continue
        selected.append(action)
        selected_ids.add(action.action_id)
        appended_work += 1
    if not finalize_only and appended_work == 0:
        return None
    if include_finalizer:
        finalizer = next(
            action for action in allocated_plan.actions
            if action.action_id == "finalize.report"
        )
        selected.append(replace(
            finalizer,
            dependencies=tuple(action.action_id for action in selected),
            action_digest=None,
        ))
    return ScanActionPlan(
        scan_id=allocated_plan.scan_id,
        execution_plan_digest=allocated_plan.execution_plan_digest,
        target_binding_digest=allocated_plan.target_binding_digest,
        actions=tuple(
            replace(action, ordinal=index, action_digest=None)
            for index, action in enumerate(selected)
        ),
    )


def _manifest_reference_values(
    endpoints: ScanWorkManifest,
    candidates: ScanWorkManifest,
    request_manifests: tuple[ScanWorkManifest, ...],
    request_candidates: ScanWorkManifest | None,
    template_ref: Any,
) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = [
        endpoints.reference().canonical_dict(),
        candidates.reference().canonical_dict(),
        *(manifest.reference().canonical_dict() for manifest in request_manifests),
    ]
    if request_candidates is not None:
        values.append(request_candidates.reference().canonical_dict())
    if isinstance(template_ref, Mapping):
        values.append(dict(template_ref))
    return values


def _continuation_option_patch(
    endpoints: ScanWorkManifest,
    candidates: ScanWorkManifest,
    request_candidates: ScanWorkManifest | None,
    amended: ScanActionPlan,
    revision: ScanPlanRevision,
) -> dict[str, Any]:
    return {
        "endpoint_manifest_id": str(endpoints.manifest_id),
        "endpoint_manifest_ref": endpoints.reference().canonical_dict(),
        "candidate_manifest_ref": candidates.reference().canonical_dict(),
        "request_candidate_manifest_ref": (
            request_candidates.reference().canonical_dict()
            if request_candidates is not None and request_candidates.entries
            else None
        ),
        "scan_continuation_plan_digest": amended.plan_digest,
        "scan_plan_revision": revision.canonical_dict(),
    }


@dataclass(frozen=True)
class PreparedContinuation:
    plan: ScanActionPlan
    revision: ScanPlanRevision
    manifests: tuple[ScanWorkManifest, ...]
    options: dict[str, Any]


def compile_continuation_round(
    *, parent_plan: ScanActionPlan, allocation: ScanContinuationAllocation,
    parent_results: Mapping[str, CapabilityResultReference], execution_plan: Any,
    target: Any, target_url: str, options: Mapping[str, Any],
    observations: Mapping[str, Any], request_manifests: tuple[ScanWorkManifest, ...],
    revision_number: int, include_finalizer: bool, finalize_only: bool,
) -> PreparedContinuation | None:
    """The one pure round compiler used by both local and broker persistence paths.

    Only root discovery observations define the immutable worklists. Every settled
    action contributes to cumulative consumption; later rounds never get a new budget.
    """
    if not 1 <= revision_number <= MAX_SCAN_CONTINUATION_ROUNDS + 1:
        raise ScanContinuationError("continuation revision is outside its bound")
    if finalize_only and not include_finalizer:
        raise ScanContinuationError("a finalizer-only revision must include the finalizer")
    if any(action.action_id == "finalize.report" for action in parent_plan.actions):
        raise ScanContinuationError("cannot append work after the finalizer")
    if not set(action.action_id for action in parent_plan.actions) <= set(parent_results):
        raise ScanContinuationError("continuation is missing a terminal parent action receipt")
    if any(result.status.value == "cancelled" for result in parent_results.values()):
        raise ScanContinuationError("cancelled Scan cannot continue")
    root_results = {key: parent_results[key] for key in allocation.parent_action_ids}
    observations = {key: observations.get(key, ()) for key in allocation.parent_action_ids}
    endpoints, candidates = build_discovery_continuation_manifests(
        allocation=allocation,
        target_url=target_url,
        target=target,
        options=options,
        action_results=root_results,
        observations=observations,
        request_manifests=request_manifests,
    )
    request_candidates = (
        build_request_candidate_manifest(
            request_manifests,
            source_action_ids=tuple(dict.fromkeys(
                action_id
                for manifest in request_manifests
                for action_id in manifest.source_action_ids
            )),
            maximum=max(
                1,
                min(2_000, allocation.budget_ceiling.get(
                    "state_changing_requests", 0,
                )),
            ),
        )
        if request_manifests else None
    )
    credential_refs = [
        dict(item)
        for item in options.get("credential_profile_refs") or ()
        if isinstance(item, Mapping)
    ]
    collection_refs = [
        dict(item)
        for item in options.get("request_collections") or ()
        if isinstance(item, Mapping)
    ]
    request_refs = options.get("request_manifest_refs")
    template_ref = options.get("template_manifest_ref")
    # Derived from the compiler's own rule: only an interactive credential gets
    # an inputs.auth_* action, so allocating one per credential named actions
    # that were never created and the plan was rejected outright.
    zero_cost_existing_inputs = {
        action_id: {}
        for action_id in interactive_auth_input_action_ids(credential_refs)
    }
    zero_cost_existing_inputs.update({
        f"inputs.collection_{index:02d}": {}
        for index, _item in enumerate(collection_refs)
    })
    continuation_raw = ScanActionPlanCompiler().compile(
        scan_id=parent_plan.scan_id,
        execution_plan=execution_plan,
        target_binding=target,
        credential_profile_refs=credential_profile_action_refs(credential_refs),
        request_collection_refs=request_collection_action_refs(collection_refs),
        request_manifest_refs=(
            {
                str(key): dict(value)
                for key, value in request_refs.items()
                if isinstance(value, Mapping)
            }
            if isinstance(request_refs, Mapping) else None
        ),
        endpoint_manifest_ref=endpoints.reference().canonical_dict(),
        candidate_manifest_ref=candidates.reference().canonical_dict(),
        request_candidate_manifest_ref=(
            request_candidates.reference().canonical_dict()
            if request_candidates is not None and request_candidates.entries
            else None
        ),
        template_manifest_ref=(
            dict(template_ref) if isinstance(template_ref, Mapping) else None
        ),
        action_scope="endpoint",
        action_budgets=zero_cost_existing_inputs,
        # Every work revision receives a unique action namespace. The terminal
        # revision reuses the last round's namespace only while compiling the
        # finalizer reservation; no round's work is appended twice.
        continuation_round=min(revision_number, MAX_SCAN_CONTINUATION_ROUNDS),
        manifest_offsets=continuation_manifest_offsets(parent_plan),
        # The first continuation satisfies explicit family floors. Later rounds
        # are opportunistic breadth and must stop cleanly when the residual can
        # no longer fund a fast-tier batch.
        require_family_minimums=revision_number == 1,
    )
    allocated_plan = allocate_scan_action_plan(
        continuation_raw,
        # Admit against what the settled actions actually left, not the
        # worst-case residual frozen at submission (see reconciled_continuation_ceiling).
        ContinuationBudgetCeiling(
            reconciled_continuation_ceiling(allocation, parent_results),
        ),
    ).plan
    continuation_plan = select_continuation_actions(
        allocated_plan,
        parent_action_count=len(parent_plan.actions),
        include_finalizer=include_finalizer,
        finalize_only=finalize_only,
    )
    if continuation_plan is None:
        return None
    amended = merge_scan_action_continuation(
        parent_plan=parent_plan,
        continuation_plan=continuation_plan,
        allocation=allocation,
        parent_results=parent_results,
        include_finalizer=include_finalizer,
    )
    revision = amended_scan_plan_revision(
        parent_plan=parent_plan,
        continuation_plan=continuation_plan,
        amended_plan=amended,
        allocation=allocation,
        discovery_results=parent_results,
        work_manifest_references=unique_work_manifest_reference_dicts(
            _manifest_reference_values(
                endpoints, candidates, request_manifests, request_candidates, template_ref,
            )
        ),
        revision=revision_number,
    )
    option_patch = _continuation_option_patch(
        endpoints, candidates, request_candidates, amended, revision,
    )
    return PreparedContinuation(
        plan=amended, revision=revision,
        manifests=(endpoints, candidates, *((request_candidates,) if request_candidates is not None else ())),
        options=option_patch,
    )


def compile_next_continuation(**kwargs: Any) -> PreparedContinuation:
    """Admit one work round or exactly one terminal revision at exhaustion/the bound."""
    prepared = None
    if kwargs["revision_number"] <= MAX_SCAN_CONTINUATION_ROUNDS:
        prepared = compile_continuation_round(**kwargs, include_finalizer=False, finalize_only=False)
    if prepared is None:
        prepared = compile_continuation_round(**kwargs, include_finalizer=True, finalize_only=True)
    if prepared is None:
        raise ScanContinuationError("terminal Scan continuation produced no finalizer")
    return prepared


async def materialize_local_scan_continuation(
    runtime: ContinuationRuntime, *, parent_plan: ScanActionPlan,
    allocation: ScanContinuationAllocation,
    parent_results: Mapping[str, CapabilityResultReference],
    revision_number: int = 1, include_finalizer: bool = True, finalize_only: bool = False,
) -> tuple[ScanActionPlan, ScanPlanRevision] | None:
    """Compile with the shared planner and persist one local continuation transaction."""
    dispatcher = runtime.dispatcher
    observations = {
        action_id: await dispatcher._observations(action_id)
        for action_id in allocation.parent_action_ids
    }
    request_manifests = await runtime.load_request_manifests(
        scan_id=dispatcher.scan_id, target_binding_digest=dispatcher.target.digest,
        options=dispatcher.options,
    )
    prepared = compile_continuation_round(
        parent_plan=parent_plan, allocation=allocation, parent_results=parent_results,
        execution_plan=runtime.execution_plan, target=dispatcher.target,
        target_url=dispatcher.target_url, options=dispatcher.options,
        observations=observations, request_manifests=request_manifests,
        revision_number=revision_number, include_finalizer=include_finalizer,
        finalize_only=finalize_only,
    )
    if prepared is None:
        return None
    async with runtime.db_pool.acquire() as conn:
        async with conn.transaction():
            store = runtime.manifest_store_factory()
            for manifest in prepared.manifests:
                await store.persist(conn, manifest=manifest)
            await runtime.action_store_factory().amend_plan(
                conn, parent_plan=parent_plan, amended_plan=prepared.plan,
                allocation=allocation, revision=prepared.revision,
            )
            await conn.execute(
                """
                UPDATE scans SET options=options || $2::jsonb
                WHERE id=$1 AND status NOT IN ('cancelled','cancelling')
                """,
                uuid.UUID(dispatcher.scan_id), json.dumps(prepared.options),
            )
    dispatcher.options.update(prepared.options)
    runtime.record_event("continuation_compiled")
    return prepared.plan, prepared.revision


def _cancelled(orchestration: Any) -> bool:
    return any(
        result.status.value == "cancelled"
        for result in orchestration.action_results.values()
    )


def round_progress_window(
    revision_number: int,
    *,
    floor: int = 40,
    ceiling: int = 90,
    max_rounds: int = MAX_SCAN_CONTINUATION_ROUNDS,
) -> tuple[int, int]:
    """The progress span one work round reports, so eight rounds fill floor..ceiling evenly."""
    span = ceiling - floor
    return (
        floor + ((revision_number - 1) * span // max_rounds),
        floor + (revision_number * span // max_rounds),
    )


async def run_continuation_rounds(
    *,
    plan: ScanActionPlan,
    plan_revision: ScanPlanRevision | None,
    initial_results: Mapping[str, CapabilityResultReference],
    materialize: Callable[..., Awaitable[tuple[ScanActionPlan, ScanPlanRevision] | None]],
    run_round: Callable[..., Awaitable[Any]],
    max_rounds: int = MAX_SCAN_CONTINUATION_ROUNDS,
) -> tuple[ScanActionPlan, ScanPlanRevision, Any]:
    """Append and run work revisions until the residual is spent, then the terminal finalizer.

    ``materialize(parent_plan=, parent_results=, revision_number=, include_finalizer=,
    finalize_only=)`` compiles and persists one revision or returns ``None`` when nothing
    was admitted. ``run_round(plan, revision, progress_start=, progress_end=)`` executes an
    amended plan and returns the orchestration whose ``action_results`` settle it. A
    cancelled action in any round stops the Scan with the worker's cancellation signal.
    """
    all_results: dict[str, CapabilityResultReference] = dict(initial_results)
    next_revision = int(plan_revision.revision) + 1 if plan_revision is not None else 1
    orchestration: Any = None
    # Append one digest-bound work revision at a time. Recompilation starts each manifest
    # lane at its first unplanned index and admits only what the cumulatively reconciled
    # residual can still fund.
    while next_revision <= max_rounds:
        materialized = await materialize(
            parent_plan=plan,
            parent_results=all_results,
            revision_number=next_revision,
            include_finalizer=False,
            finalize_only=False,
        )
        if materialized is None:
            break
        plan, plan_revision = materialized
        progress_start, progress_end = round_progress_window(
            next_revision, max_rounds=max_rounds,
        )
        orchestration = await run_round(
            plan, plan_revision,
            progress_start=progress_start, progress_end=progress_end,
        )
        all_results.update(orchestration.action_results)
        if _cancelled(orchestration):
            raise ValueError(_CANCELLED_MESSAGE)
        next_revision += 1
    # Finalization is its own immutable revision: a terminal report survives even when
    # every work round was consumed, and an early finalizer can never invalidate a
    # later amendment.
    finalized = await materialize(
        parent_plan=plan,
        parent_results=all_results,
        revision_number=next_revision,
        include_finalizer=True,
        finalize_only=True,
    )
    if finalized is None:
        raise ScanContinuationError("terminal Scan continuation produced no finalizer")
    plan, plan_revision = finalized
    orchestration = await run_round(
        plan, plan_revision, progress_start=90, progress_end=95,
    )
    return plan, plan_revision, orchestration


__all__ = [
    "ContinuationRuntime",
    "PreparedContinuation",
    "compile_continuation_round",
    "compile_next_continuation",
    "load_continuation_request_manifests",
    "materialize_local_scan_continuation",
    "round_progress_window",
    "run_continuation_rounds",
    "select_continuation_actions",
]
