"""A verifier slice a slow target wall-killed is carried into the next round, sized by latency.

Soak scan 2c637857 (Balanced, standard active, honey AI endpoints answering in ~3.7 s):
both `verify.sqli` slices hit their fixed 420-second wall after sending 112 and 111 of
their 800 requests, so SQLi stayed unverified while half of the Scan's tool wall was never
allocated. The attempt is itself the latency measurement; the next continuation round
plans one optional extension of the slice whose holds are scaled by it, bounded by the
lane's wall share and the reconciled residual, and the finalizer reads the extension's
outcome in place of the slice it extends.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from api.scan.verification_extension import (
    EXTENDS_ARG,
    extension_scale,
    plan_verification_extensions,
)

BALANCED = {"http_requests": 20_000, "state_changing_requests": 2_000, "tool_wall_seconds": 3_600}
ROOMY = {"http_requests": 14_000, "state_changing_requests": 1_700, "tool_wall_seconds": 2_300}
SOAK_RESERVED = {"http_requests": 800, "state_changing_requests": 480, "tool_wall_seconds": 420}
SOAK_CONSUMED = {"http_requests": 112, "state_changing_requests": 112, "tool_wall_seconds": 420}


def _action(action_id, capability, *, args=None, dependencies=(), stage="verify_candidates"):
    return SimpleNamespace(
        action_id=action_id, capability_name=capability, stage=stage,
        capability_args=dict(args or {
            "slice": {"start": 0, "count": 1}, "continuation_work_key": "verify.sqli",
            "candidate_manifest_ref": {"kind": "candidate"},
        }),
        dependencies=tuple(dependencies), requested_budget=dict(SOAK_RESERVED),
    )


def _settled(status, *, reserved=SOAK_RESERVED, consumed=SOAK_CONSUMED):
    return SimpleNamespace(
        status=SimpleNamespace(value=status),
        budget_reserved=dict(reserved), budget_consumed=dict(consumed),
    )


def _plan(*actions):
    return SimpleNamespace(actions=tuple(actions))


def test_the_soak_slice_gets_one_latency_scaled_extension():
    verify = _action("verify.sqli.r01", "sqli.verify_batch")
    planned = plan_verification_extensions(
        parent_plan=_plan(verify),
        parent_results={"verify.sqli.r01": _settled("timed_out")},
        profile_limits=BALANCED, residual=ROOMY,
    )

    assert len(planned) == 1
    extension = planned[0]
    assert extension["action_id"] == "verify.sqli.r01.ext"
    assert extension["capability_name"] == "sqli.verify_batch"
    assert extension["capability_args"][EXTENDS_ARG] == "verify.sqli.r01"
    assert extension["capability_args"]["slice"] == {"start": 0, "count": 1}
    # The lane never re-enters the offset ledger through its extension.
    assert "continuation_work_key" not in extension["capability_args"]
    # 3.75 s per request measured; 800 requests need 3,000 s, but one extension holds at
    # most the lane share of the Balanced wall (900 s). The pacing rate is unchanged, so
    # every scaled hold keeps the slice's own ratio.
    assert extension["budget"]["tool_wall_seconds"] == 900
    assert extension["budget"]["http_requests"] == 800 * 900 // 420
    assert extension["budget"]["state_changing_requests"] == 480 * 900 // 420
    for name, amount in extension["budget"].items():
        assert amount <= ROOMY[name]


@pytest.mark.parametrize("status, consumed", [
    ("timed_out", {"http_requests": 700, "tool_wall_seconds": 420}),   # spent its requests
    ("timed_out", {"http_requests": 0, "tool_wall_seconds": 420}),     # nothing measured
    ("partial", SOAK_CONSUMED),                                        # not wall-killed
    ("success", SOAK_CONSUMED),
])
def test_only_a_latency_starved_timeout_is_extended(status, consumed):
    planned = plan_verification_extensions(
        parent_plan=_plan(_action("verify.sqli.r01", "sqli.verify_batch")),
        parent_results={"verify.sqli.r01": _settled(status, consumed=consumed)},
        profile_limits=BALANCED, residual=ROOMY,
    )
    assert planned == ()


def test_a_slice_is_extended_once_and_an_extension_never_again():
    original = _action("verify.sqli.r01", "sqli.verify_batch")
    extension = _action(
        "verify.sqli.r01.ext.r02", "sqli.verify_batch",
        args={"slice": {"start": 0, "count": 1}, EXTENDS_ARG: "verify.sqli.r01"},
    )
    planned = plan_verification_extensions(
        parent_plan=_plan(original, extension),
        parent_results={
            "verify.sqli.r01": _settled("timed_out"),
            "verify.sqli.r01.ext.r02": _settled("timed_out"),
        },
        profile_limits=BALANCED, residual=ROOMY,
    )
    assert planned == ()


def test_the_residual_bounds_the_extension_or_drops_it():
    scale = extension_scale(
        reserved=SOAK_RESERVED, consumed=SOAK_CONSUMED, wall_ceiling=900,
        residual={"http_requests": 14_000, "state_changing_requests": 600, "tool_wall_seconds": 2_300},
    )
    assert scale == pytest.approx(600 / 480)
    assert extension_scale(
        reserved=SOAK_RESERVED, consumed=SOAK_CONSUMED, wall_ceiling=900,
        residual={"http_requests": 14_000, "state_changing_requests": 480, "tool_wall_seconds": 2_300},
    ) is None, "an extension no larger than the slice buys nothing"


def test_two_extensions_share_one_residual():
    planned = plan_verification_extensions(
        parent_plan=_plan(
            _action("verify.sqli.r01", "sqli.verify_batch"),
            _action("verify.sqli.001.r01", "sqli.verify_batch"),
        ),
        parent_results={
            "verify.sqli.r01": _settled("timed_out"),
            "verify.sqli.001.r01": _settled("timed_out"),
        },
        profile_limits=BALANCED,
        residual={"http_requests": 14_000, "state_changing_requests": 1_700, "tool_wall_seconds": 2_000},
    )
    assert [item["action_id"] for item in planned] == ["verify.sqli.r01.ext", "verify.sqli.001.r01.ext"]
    # Each is sized against what the one before it left, and the finalizer keeps its second.
    assert sum(item["budget"]["tool_wall_seconds"] for item in planned) <= 2_000 - 1
    starved = plan_verification_extensions(
        parent_plan=_plan(
            _action("verify.sqli.r01", "sqli.verify_batch"),
            _action("verify.sqli.001.r01", "sqli.verify_batch"),
        ),
        parent_results={
            "verify.sqli.r01": _settled("timed_out"),
            "verify.sqli.001.r01": _settled("timed_out"),
        },
        profile_limits=BALANCED,
        residual={"http_requests": 14_000, "state_changing_requests": 1_700, "tool_wall_seconds": 1_400},
    )
    assert [item["action_id"] for item in starved] == ["verify.sqli.r01.ext"]


def test_proof_escalation_is_replanned_behind_the_extended_verifiers():
    verify = _action("verify.sqli.r01", "sqli.verify_batch")
    prove = _action(
        "prove.sqli.r01", "sqli.prove_batch", stage="prove_candidates",
        dependencies=("verify.sqli.r01",),
        args={"slice": {"start": 0, "count": 2}, "continuation_work_key": "prove.sqli"},
    )
    proof_hold = {"http_requests": 16, "state_changing_requests": 16, "tool_wall_seconds": 24}
    planned = plan_verification_extensions(
        parent_plan=_plan(verify, prove),
        parent_results={
            "verify.sqli.r01": _settled("timed_out"),
            "prove.sqli.r01": _settled(
                "skipped", reserved=proof_hold, consumed={name: 0 for name in proof_hold},
            ),
        },
        profile_limits=BALANCED, residual=ROOMY,
    )
    assert [item["action_id"] for item in planned] == ["verify.sqli.r01.ext", "prove.sqli.r01.ext"]
    assert planned[1]["dependencies"] == ("verify.sqli.r01.ext",)
    assert planned[1]["budget"] == proof_hold
    assert planned[1]["capability_args"][EXTENDS_ARG] == "prove.sqli.r01"


# --- the real round compiler ------------------------------------------------------------------


def test_the_next_round_compiles_the_extension_inside_the_reconciled_ceiling():
    from api.scan.continuation import reconciled_continuation_ceiling
    from api.scan.continuation_rounds import compile_next_continuation
    from tests.test_continuation_rounds import _settle_round_fixture, _shared_round_fixture
    from tests.test_scan_orchestrator import _result

    fixture = _shared_round_fixture(endpoint_count=4)
    _settle_round_fixture(fixture)
    first = compile_next_continuation(**fixture, revision_number=1)
    fixture["parent_plan"] = first.plan
    verify = next(action for action in first.plan.actions if action.action_id == "verify.xss.r01")
    sent = max(1, verify.requested_budget["http_requests"] // 10)
    fixture["parent_results"][verify.action_id] = replace(
        _result(verify, status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT),
        budget_consumed={
            "http_requests": sent,
            "tool_wall_seconds": verify.requested_budget["tool_wall_seconds"],
        },
        result_digest=None,
    )
    _settle_round_fixture(fixture)

    second = compile_next_continuation(**fixture, revision_number=2)

    appended = second.plan.actions[len(first.plan.actions):]
    extension = next(action for action in appended if action.action_id == "verify.xss.r01.ext.r02")
    assert extension.required is False
    assert extension.capability_args[EXTENDS_ARG] == "verify.xss.r01"
    assert extension.capability_args["slice"] == verify.capability_args["slice"]
    assert extension.requested_budget["tool_wall_seconds"] > verify.requested_budget["tool_wall_seconds"]
    ceiling = reconciled_continuation_ceiling(fixture["allocation"], fixture["parent_results"])
    for name, limit in ceiling.items():
        assert sum(action.requested_budget.get(name, 0) for action in appended) <= limit


# --- the finalizer reads the extension in place of the slice ---------------------------------


def _coverage_with_extension(extension_status):
    from api.scan.action_plan import ScanActionPlan
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    slice_args = {"slice": {"start": 0, "count": 1}, "manifest_entries": 1}
    verify = replace(
        plan_action("verify.xss.r01", 0, capability_name="xss.verify_batch"),
        capability_args=dict(slice_args), output_schema="dalfox-batch/v1", action_digest=None,
    )
    extension = replace(
        plan_action("verify.xss.r01.ext.r02", 1, capability_name="xss.verify_batch"),
        capability_args={**slice_args, EXTENDS_ARG: verify.action_id},
        output_schema="dalfox-batch/v1", required=False, action_digest=None,
    )
    final = plan_action(
        "finalize.report", 2, dependencies=(verify.action_id, extension.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(verify, extension, final),
    )
    reason = None if extension_status is CapabilityResultStatus.SUCCESS else CapabilityResultReason.TIMED_OUT
    results = {
        verify.action_id: settle(
            verify, status=CapabilityResultStatus.TIMED_OUT, reason=CapabilityResultReason.TIMED_OUT,
        ),
        extension.action_id: settle(extension, status=extension_status, reason=reason),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={},
    )
    return report["coverage"], verify, extension


def test_a_successful_extension_closes_the_gap_its_slice_left():
    coverage, verify, _extension = _coverage_with_extension(CapabilityResultStatus.SUCCESS)
    assert verify.required is True
    assert "timed_out" not in coverage["reasons"]
    assert "timed_out" not in coverage["grade_reliability"]["reasons"]


def test_an_extension_that_also_timed_out_keeps_the_gap():
    coverage, _verify, _extension = _coverage_with_extension(CapabilityResultStatus.TIMED_OUT)
    assert coverage["status"] == "partial"
    assert "timed_out" in coverage["grade_reliability"]["reasons"]


# --- the local checkpoint loader -------------------------------------------------------------


def test_the_local_backend_can_load_checkpointed_attempts():
    """Resuming any batch, and every extension, reads checkpoints through this loader."""
    import json as _json

    from api.scan.execution_backend import PostgresScanExecutionBackend

    class _Conn:
        async def fetch(self, *_args):
            return [{
                "attempt_id": "a" * 64, "candidate_id": "c-1", "status": "success",
                "budget_consumed": _json.dumps({"http_requests": 3}),
                "observations_json": _json.dumps([{"kind": "candidate_attempt"}]),
                "errors_json": _json.dumps([]), "timed_out": False, "proof_state": "unproven",
            }]

    class _Acquire:
        async def __aenter__(self):
            return _Conn()

        async def __aexit__(self, *_args):
            return None

    backend = object.__new__(PostgresScanExecutionBackend)
    backend._pool = SimpleNamespace(acquire=_Acquire)
    backend._plan = SimpleNamespace(scan_id="00000000-0000-4000-8000-000000000001")
    backend._require_action = lambda _action_id: SimpleNamespace(
        action_id="verify.xss.r01", action_digest="b" * 64,
    )
    attempts = asyncio.run(backend.load_batch_attempts("verify.xss.r01"))
    assert attempts[0]["observations"] == ({"kind": "candidate_attempt"},)
    assert attempts[0]["errors"] == ()


def test_the_explanation_reads_the_extension_in_place_of_the_slice():
    from api.scan.explanation import build_scan_execution_explanation
    from tests.test_scan_explanation import SCAN_ID, _plan as explanation_plan, _rows

    plan = explanation_plan()
    baseline = plan["actions"][0]
    plan["actions"][0] = {**baseline, "action_id": "verify.sqli.r01", "capability_name": "sqli.verify_batch"}
    extension = {
        **baseline, "action_id": "verify.sqli.r01.ext.r02", "capability_name": "sqli.verify_batch",
        "action_digest": "9" * 64, "ordinal": 1, "required": False,
        "capability_args": {"slice": {"start": 0, "count": 1}, EXTENDS_ARG: "verify.sqli.r01"},
    }
    plan["actions"][1] = extension
    rows = _rows()
    rows[0] = {**rows[0], "action_id": "verify.sqli.r01", "status": "timed_out", "reason_code": "timed_out"}
    rows[1] = {"action_id": extension["action_id"], "ordinal": 1, "status": "success"}

    explanation = build_scan_execution_explanation(
        scan_id=SCAN_ID, scan_status="completed", plan_payload=plan, action_rows=rows,
    )
    by_id = {item["action_id"]: item for item in explanation["actions"]}
    assert by_id["verify.sqli.r01.ext.r02"]["extends"] == "verify.sqli.r01"
    assert "extends" not in by_id["verify.sqli.r01"]
    reliability = explanation["coverage"]["grade_reliability"]
    assert "timed_out" not in reliability["reasons"]

    rows[1] = {**rows[1], "status": "timed_out", "reason_code": "timed_out"}
    again = build_scan_execution_explanation(
        scan_id=SCAN_ID, scan_status="completed", plan_payload=plan, action_rows=rows,
    )
    assert "timed_out" in again["coverage"]["grade_reliability"]["reasons"]


def test_an_extension_is_admitted_at_its_earned_holds_or_skipped():
    """The allocator never shrinks an extension to a floor tier smaller than its slice."""
    from api.scan.action_plan import ScanActionPlan
    from api.scan.budget_allocator import allocate_scan_action_plan
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action

    def verifier(action_id, budget, **args):
        return replace(
            plan_action(action_id, 0, capability_name="sqli.verify_batch"),
            capability_args={"slice": {"start": 0, "count": 1}, **args},
            requested_budget=budget, required=False, action_digest=None,
        )

    earned = {"http_requests": 1_714, "tool_wall_seconds": 900}
    extension = verifier("verify.sqli.r01.ext.r02", earned, **{EXTENDS_ARG: "verify.sqli.r01"})
    ordinary = replace(verifier("verify.sqli.r02", earned), ordinal=1, action_digest=None)
    final = replace(
        plan_action("finalize.report", 2, dependencies=(extension.action_id, ordinary.action_id)),
        requested_budget={"tool_wall_seconds": 1}, action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(extension, ordinary, final),
    )
    limits = SimpleNamespace(ledger_limits=lambda: {"http_requests": 1_000, "tool_wall_seconds": 600})

    admitted = {
        action.action_id: action for action in allocate_scan_action_plan(plan, limits).plan.actions
    }

    assert admitted[extension.action_id].admission_status == "skipped"
    assert admitted[extension.action_id].reason_code == "insufficient_plan_budget"
    # Ordinary work keeps the reviewed scaled-tier fallback it always had.
    assert admitted[ordinary.action_id].admission_status == "planned"
    assert admitted[ordinary.action_id].requested_budget == {"http_requests": 160, "tool_wall_seconds": 30}
