from __future__ import annotations

import hashlib
import pathlib

from api.scan.action_plan import ScanAction, ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action


def _batch_action(action_id, capability, ordinal, *, count, required=True):
    return ScanAction(
        action_id=action_id,
        stage="verify_candidates",
        ordinal=ordinal,
        capability_name=capability,
        capability_args={
            "slice": {"start": 0, "count": count},
            "profile": "balanced",
            "proof_policy": "deterministic_proof_contract_required",
        },
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 40, "tool_wall_seconds": 30},
        placement={
            "schema_version": "scan-action-placement/v1",
            "eligible_backends": ["local"],
            "adapter_name": "internal",
            "adapter_version": "1",
        },
        dependencies=(),
        required=required,
        supporting=False,
        output_schema="candidate-attempt/v1",
    )


def _attempt(candidate_id):
    return {
        "kind": "candidate_attempt",
        "attempt_id": hashlib.sha256(candidate_id.encode()).hexdigest(),
        "candidate_id": candidate_id,
        "family": "sqli",
        "status": "success",
        "proof_state": "verified",
    }


def _family(report, name):
    return next(
        row for row in report["coverage"]["family_coverage"] if row["family"] == name
    )


def test_selected_family_with_zero_attempts_makes_the_grade_unreliable():
    # A selected SQLi verifier planned candidates but attempted none.
    sqli = _batch_action("verify.sqli", "sqli.verify_batch", 0, count=10)
    final = _action("finalize.report", 1, dependencies=(sqli.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(sqli, final),
    )
    results = {sqli.action_id: _result_with_observation_count(sqli, 0)}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={sqli.action_id: ()},
    )

    row = _family(report, "sqli")
    assert row["selected"] is True
    assert row["planned_candidates"] == 10
    assert row["attempted_candidates"] == 0
    assert row["coverage_status"] == "partial"
    assert row["reason"] == "zero_attempts"
    assert "sqli" in report["coverage"]["selected_family_gaps"]
    assert report["result"]["grade_reliable"] is False
    assert "selected_family_incomplete" in report["coverage"]["grade_reliability"]["reasons"]


def test_complete_family_reports_findings_and_budget_and_stays_reliable():
    sqli = _batch_action("verify.sqli", "sqli.verify_batch", 0, count=2)
    prove = _batch_action("prove.sqli", "sqli.prove_batch", 1, count=2, required=False)
    final = _action("finalize.report", 2, dependencies=(sqli.action_id, prove.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(sqli, prove, final),
    )
    results = {
        sqli.action_id: _result_with_observation_count(sqli, 2),
        prove.action_id: _result_with_observation_count(prove, 3),
    }
    observations = {
        sqli.action_id: (_attempt("c1"), _attempt("c2")),
        prove.action_id: (
            _attempt("c1"), _attempt("c2"),
            {
                "kind": "sqli_proof", "candidate_id": "c1", "method": "GET",
                "field_path": "id", "request_class": "safe_read",
                "proof_state": "verified", "finding_verdict": "verified",
                "proof_contract": "sqli_error_differential/v2",
                "technique": "error_based_repeated", "repetitions": 2,
                "response_pairs": [{"control_response_sha256": "c" * 64}],
            },
        ),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    row = _family(report, "sqli")
    # Two candidates, attempted once. The proof action escalates over those same
    # candidates, so counting its slice again would report four attempts for two.
    assert row["attempted_candidates"] == 2
    assert row["proof_escalation"]["attempted_candidates"] == 2
    assert row["proof_escalation"]["status"] == "complete"
    assert row["verified_findings"] == 1
    assert row["coverage_status"] == "complete"
    assert row["reason"] is None
    assert row["budget_reserved"]["http_requests"] == 80  # summed over both actions
    assert report["coverage"]["selected_family_gaps"] == []
    # No selected-family gap and one verified finding: reliability is not reduced
    # by this family (any residual reason is unrelated).
    assert "selected_family_incomplete" not in report["coverage"]["grade_reliability"]["reasons"]


def test_optional_family_gap_does_not_flip_reliability():
    # A best-effort proof action that attempted nothing is not a selected-family
    # gap because it is not required.
    prove = _batch_action(
        "prove.xss", "xss.browser_prove_batch", 0, count=5, required=False,
    )
    final = _action("finalize.report", 1, dependencies=(prove.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(prove, final),
    )
    results = {prove.action_id: _result_with_observation_count(prove, 0)}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={prove.action_id: ()},
    )

    row = _family(report, "xss")
    assert row["required"] is False
    # No verifier action was planned for the family at all, so its execution
    # coverage is unestablished rather than complete.
    assert row["coverage_status"] == "partial"
    assert row["reason"] == "no_verifier_action"
    assert report["coverage"]["selected_family_gaps"] == []
    assert "selected_family_incomplete" not in report["coverage"]["grade_reliability"]["reasons"]


def test_not_applicable_proof_does_not_make_its_family_incomplete():
    """A proof escalation with nothing to escalate is a clean outcome.

    The required verifier attempted every candidate it planned. Its optional
    proof action then had no proof-eligible candidate and was correctly skipped
    as not_applicable. Folding that skip into the family's own statuses made a
    fully-executed family report partial, raised a selected-family gap, and
    marked the whole grade unreliable -- for work that succeeded.
    """
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from tests.test_scan_orchestrator import _result

    sqli = _batch_action("verify.sqli", "sqli.verify_batch", 0, count=2)
    prove = _batch_action("prove.sqli", "sqli.prove_batch", 1, count=2, required=False)
    final = _action("finalize.report", 2, dependencies=(sqli.action_id, prove.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(sqli, prove, final),
    )
    results = {
        sqli.action_id: _result_with_observation_count(sqli, 2),
        prove.action_id: _result(
            prove,
            status=CapabilityResultStatus.SKIPPED,
            reason=CapabilityResultReason.NOT_APPLICABLE,
        ),
    }
    observations = {
        sqli.action_id: (_attempt("c1"), _attempt("c2")),
        prove.action_id: (),
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    row = _family(report, "sqli")
    # The verifier planned two candidates and attempted both. The proof action's
    # slice covers those same candidates and must not be counted a second time.
    assert row["planned_candidates"] == 2
    assert row["attempted_candidates"] == 2
    assert row["coverage_status"] == "complete"
    assert row["reason"] is None
    assert report["coverage"]["selected_family_gaps"] == []
    assert "selected_family_incomplete" not in report["coverage"]["grade_reliability"]["reasons"]
    # The escalation is reported in its own right rather than as family failure.
    assert row["proof_escalation"]["status"] == "not_applicable"


def test_a_failed_proof_is_reported_without_failing_its_verifier():
    """A proof that ran and failed is a proof limitation, not a coverage gap."""
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from tests.test_scan_orchestrator import _result

    sqli = _batch_action("verify.sqli", "sqli.verify_batch", 0, count=2)
    prove = _batch_action("prove.sqli", "sqli.prove_batch", 1, count=2, required=False)
    final = _action("finalize.report", 2, dependencies=(sqli.action_id, prove.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(sqli, prove, final),
    )
    results = {
        sqli.action_id: _result_with_observation_count(sqli, 2),
        prove.action_id: _result(
            prove,
            status=CapabilityResultStatus.FAILED,
            reason=CapabilityResultReason.ADAPTER_FAILED,
        ),
    }
    observations = {sqli.action_id: (_attempt("c1"), _attempt("c2")), prove.action_id: ()}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    row = _family(report, "sqli")
    assert row["attempted_candidates"] == 2
    assert row["coverage_status"] == "complete"
    assert report["coverage"]["selected_family_gaps"] == []
    assert row["proof_escalation"]["status"] == "failed"


def test_an_unfundable_proof_is_reported_as_unavailable_not_failed():
    """An endpoint shard carries no browser budget.

    Its optional XSS browser proof is skipped for insufficient plan budget. That
    is a real limit on what was proved and must be visible, but it is neither a
    proof failure nor evidence that the verifier did not run -- parallel XSS
    would otherwise look identical to a broken one.
    """
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from tests.test_scan_orchestrator import _result

    xss = _batch_action("verify.xss", "xss.verify_batch", 0, count=2)
    prove = _batch_action(
        "prove.xss", "xss.browser_prove_batch", 1, count=2, required=False,
    )
    final = _action("finalize.report", 2, dependencies=(xss.action_id, prove.action_id))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(xss, prove, final),
    )
    results = {
        xss.action_id: _result_with_observation_count(xss, 2),
        prove.action_id: _result(
            prove,
            status=CapabilityResultStatus.SKIPPED,
            reason=CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET,
        ),
    }
    observations = {xss.action_id: (_attempt("c1"), _attempt("c2")), prove.action_id: ()}
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
    )

    row = _family(report, "xss")
    assert row["coverage_status"] == "complete"
    assert report["coverage"]["selected_family_gaps"] == []
    assert row["proof_escalation"]["status"] == "unavailable"
    assert row["proof_escalation"]["reason"] == "insufficient_plan_budget"


def test_a_budget_limited_batch_is_not_reported_as_truncated_output():
    """Partial is not automatically truncated.

    A batch stops attempting when the remaining reservation can no longer fund
    an attempt that could reach a verdict, so the leftover candidates are a
    budget outcome and nothing was cut off. Labelling that `output_truncated`
    put a false reason on the action and, because it is a required action, made
    the whole scan's grade unreliable.
    """
    from api.scan.capability_result import CapabilityResultReason

    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "api" / "scan" / "execution_backend.py"
    ).read_text(encoding="utf-8")
    partial_branch = source[source.index('elif raw_status == "partial"'):]
    partial_branch = partial_branch[:partial_branch.index('elif raw_status == "skipped"')]
    # The reason must come from the receipt, with truncation only as fallback.
    assert "self._receipt_reason(" in partial_branch
    assert "CapabilityResultReason.OUTPUT_TRUNCATED" in partial_branch

    adapter = (
        pathlib.Path(__file__).resolve().parent.parent
        / "api" / "scan" / "action_adapter.py"
    ).read_text(encoding="utf-8")
    # ...and the batch must actually state that reason when it under-attempts.
    assert (
        "CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET.value" in adapter
    ), "the external batch does not state why it is partial"
    assert CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET.value == "insufficient_plan_budget"
