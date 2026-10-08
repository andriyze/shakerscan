"""A wall-killed SQLi extension is continued, and the chain reads as its newest outcome.

SQLi verification resumes by technique stage (``scan/sqli_stages``), so extending an extension
continues a candidate instead of repeating it (soak N3, 2026-10-07). The round compiler plans
the next link at the lane share inside the reconciled ceiling; the finalizer and the execution
explanation read the newest link in place of the slice and every link before it.
"""

from __future__ import annotations

from api.scan.verification_extension import EXTENDS_ARG


def _sqli_round_fixture():
    from api.scan.action_plan import ScanActionPlanCompiler
    from api.scan.budget_allocator import allocate_scan_action_plan
    from api.scan.continuation import ScanContinuationAllocation
    from api.scan.contracts import resolve_scan_contract
    from api.scan.work_manifests import build_canonical_scan_nuclei_template_manifest
    from tests.test_scan_continuation import SCAN_ID, _target

    target = _target()
    contract = resolve_scan_contract(
        budget_profile="balanced",
        policy={"active_testing": True, "preset": "passive", "include_families": ["sqli"]},
    )
    parent_allocation = allocate_scan_action_plan(
        ScanActionPlanCompiler().compile(
            scan_id=SCAN_ID, execution_plan=contract.execution_plan, target_binding=target,
            defer_manifest_actions=True, include_finalizer=False,
        ),
        contract.budget, assign_residual_to_finalizer=False, require_finalizer=False,
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
        required_capabilities=("templates.passive_batch", "sqli.verify_batch"),
        # Mirrors admission: the passive preset's read-only exposure checks are allowed work.
        allowed_capabilities=(
            "templates.passive_batch", "sqli.verify_batch", "sqli.prove_batch",
            "exposure.verify_batch",
        ),
    )
    template = build_canonical_scan_nuclei_template_manifest(
        scan_id=SCAN_ID, target_binding_digest=target.digest, include_active=False,
    )
    return dict(
        parent_plan=parent, allocation=allocation, parent_results={},
        execution_plan=contract.execution_plan, target=target,
        target_url="https://app.example.test", observations={}, request_manifests=(),
        options={"template_manifest_ref": template.reference().canonical_dict(), "custom_endpoints": [
            f"GET /route_{index}?q=1" for index in range(4)
        ]},
    )


def test_the_round_compiler_continues_a_sqli_extension_in_the_next_round():
    from dataclasses import replace

    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.continuation import reconciled_continuation_ceiling
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_continuation_rounds import _settle_round_fixture
    from tests.test_scan_orchestrator import _result

    fixture = _sqli_round_fixture()
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    fixture["parent_plan"] = first.plan

    def starve(action):
        sent = max(1, action.requested_budget["http_requests"] // 10)
        fixture["parent_results"][action.action_id] = replace(
            _result(action, status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT),
            budget_consumed={
                name: (
                    action.requested_budget[name] if name == "tool_wall_seconds"
                    else min(sent, action.requested_budget[name])
                )
                for name in action.requested_budget
            },
            result_digest=None,
        )

    verify = next(action for action in first.plan.actions if action.action_id == "verify.sqli.r01")
    starve(verify)
    _settle_round_fixture(fixture)
    second = compile_next_continuation(**fixture, revision_number=2)
    fixture["parent_plan"] = second.plan
    extension = next(
        action for action in second.plan.actions if action.action_id == "verify.sqli.r01.ext.r02"
    )
    starve(extension)
    _settle_round_fixture(fixture)

    third = compile_next_continuation(**fixture, revision_number=3)

    appended = third.plan.actions[len(second.plan.actions):]
    chained = next(
        action for action in appended if action.action_id == "verify.sqli.r01.ext.r02.ext.r03"
    )
    assert chained.capability_args[EXTENDS_ARG] == "verify.sqli.r01.ext.r02"
    assert chained.required is False
    assert chained.requested_budget["tool_wall_seconds"] <= extension.requested_budget["tool_wall_seconds"]
    ceiling = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    for name, limit in ceiling.items():
        assert sum(action.requested_budget.get(name, 0) for action in appended) <= limit


def test_the_finalizer_reads_the_newest_extension_of_a_chain():
    from dataclasses import replace

    from api.scan.action_plan import ScanActionPlan as Plan
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as orchestrator_action, _result as settle

    slice_args = {"slice": {"start": 0, "count": 1}, "manifest_entries": 1}
    ids = ("verify.sqli.r01", "verify.sqli.r01.ext.r02", "verify.sqli.r01.ext.r02.ext.r03")
    actions = []
    for ordinal, action_id in enumerate(ids):
        actions.append(replace(
            orchestrator_action(action_id, ordinal, capability_name="sqli.verify_batch"),
            capability_args={**slice_args, **({EXTENDS_ARG: ids[ordinal - 1]} if ordinal else {})},
            output_schema="sqlmap-batch/v1", required=ordinal == 0, action_digest=None,
        ))
    final = orchestrator_action("finalize.report", 3, dependencies=ids)
    plan = Plan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(*actions, final),
    )
    timed_out = dict(status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT)
    results = {
        ids[0]: settle(actions[0], **timed_out),
        ids[1]: settle(actions[1], **timed_out),
        ids[2]: settle(actions[2], status=CapabilityResultStatus.SUCCESS),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results, observations={},
    )

    assert "timed_out" not in report["coverage"]["grade_reliability"]["reasons"]
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "sqli")
    assert family["batch_actions"] == 1


def test_the_explanation_reads_the_newest_extension_of_a_chain():
    from api.scan.explanation import build_scan_execution_explanation
    from tests.test_scan_explanation import SCAN_ID, _plan as explanation_plan, _rows

    plan = explanation_plan()
    baseline, _middle, final = plan["actions"]
    chain = ("verify.sqli.r01", "verify.sqli.r01.ext.r02", "verify.sqli.r01.ext.r02.ext.r03")
    plan["actions"] = [
        {
            **baseline, "action_id": action_id, "capability_name": "sqli.verify_batch",
            "action_digest": str(index + 6) * 64, "ordinal": index, "required": index == 0,
            "capability_args": {
                "slice": {"start": 0, "count": 1},
                **({EXTENDS_ARG: chain[index - 1]} if index else {}),
            },
        }
        for index, action_id in enumerate(chain)
    ] + [{**final, "ordinal": 3}]
    rows = _rows()
    template = rows[0]
    rows = [
        {**template, "action_id": chain[0], "ordinal": 0, "status": "timed_out", "reason_code": "timed_out"},
        {"action_id": chain[1], "ordinal": 1, "status": "timed_out", "reason_code": "timed_out"},
        {"action_id": chain[2], "ordinal": 2, "status": "success"},
    ]

    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID, scan_status="completed", plan_payload=plan, action_rows=rows,
    )
    assert "timed_out" not in explanation["coverage"]["grade_reliability"]["reasons"]
