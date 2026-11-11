"""A slice that ran out of its allowance and was continued says so in the coverage record.

A verification slice that stops on a spent request allowance (or a timeout) is re-planned as an
extension, and the extension's outcome decides the slice. The family row was already read that
way; the rest of the record was not: the stopped slice stayed listed as a coverage gap although
its continuation finished it, its action row did not name the continuation, and a family that
read complete gave no sign that some of its actions had stopped short on the way.

Package import layout, like tests/test_sqli_extension_chain.py.
"""
from __future__ import annotations

from dataclasses import replace

from api.scan.verification_extension import EXTENDS_ARG

SLICE = "verify.sqli.001.r01"
EXTENSION = "verify.sqli.001.r01.ext.r02"


def _report(extension_outcome: dict, *, extension_attempted: bool = True):
    """Two SQLi slices of a two-entry manifest; the second stops on its request allowance and
    is continued by an extension that ends as ``extension_outcome``."""
    from api.runtime.observation_manifests import ObservationManifest
    from api.scan.action_plan import ScanActionPlan
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as plan_action, _result as settle

    def batch(action_id, ordinal, start, *, required=False, extends=None):
        return replace(
            plan_action(action_id, ordinal, capability_name="sqli.verify_batch"),
            capability_args={
                "slice": {"start": start, "count": 1}, "manifest_entries": 2,
                **({EXTENDS_ARG: extends} if extends else {}),
            },
            output_schema="sqlmap-batch/v1", required=required, action_digest=None,
        )

    first = batch("verify.sqli.r01", 0, 0, required=True)
    stopped = batch(SLICE, 1, 1)
    extension = batch(EXTENSION, 2, 1, extends=SLICE)
    final = plan_action(
        "finalize.report", 3, dependencies=(first.action_id, stopped.action_id, extension.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(first, stopped, extension, final),
    )

    def attempted(action, result, attempt):
        rows = ({
            "kind": "candidate_attempt", "attempt_id": attempt * 64,
            "candidate_id": f"c{attempt}", "status": "success",
        },)
        return replace(result, observation_manifest_ref=ObservationManifest(
            manifest_id=f"00000000-0000-4000-8000-00000000000{attempt}", owner_id=SCAN_ID,
            action_id=action.action_id, capability_name=action.capability_name,
            output_schema=action.output_schema, observation_count=len(rows),
            content_sha256=attempt * 64, size_bytes=256, object_key=f"scans/{attempt}.jsonl",
        ).reference(), result_digest=None), rows

    first_result, first_rows = attempted(first, settle(first, status=CapabilityResultStatus.SUCCESS), "1")
    extension_result = settle(extension, **extension_outcome)
    observations = {first.action_id: first_rows}
    if extension_attempted:
        extension_result, observations[extension.action_id] = attempted(extension, extension_result, "2")
    results = {
        first.action_id: first_result,
        stopped.action_id: settle(
            stopped, status=CapabilityResultStatus.PARTIAL,
            reason=CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
        ),
        extension.action_id: extension_result,
    }
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test", action_results=results,
        observations=observations,
    )


def _family(report):
    return next(row for row in report["coverage"]["family_coverage"] if row["family"] == "sqli")


def _action_rows(report):
    return {row["action_id"]: row for row in report["coverage"]["capability_coverage"]["actions"]}


def test_a_slice_its_continuation_finished_is_not_a_gap_and_names_the_continuation():
    from api.scan.capability_result import CapabilityResultStatus

    report = _report({"status": CapabilityResultStatus.SUCCESS})
    coverage = report["coverage"]

    # Every candidate of the family has a verdict: the family is complete, as before.
    family = _family(report)
    assert (family["coverage_status"], family["reason"]) == ("complete", None)
    assert (family["planned_candidates"], family["attempted_candidates"]) == (2, 2)
    # It says that an action stopped on its allowance on the way, and that it was finished.
    assert family["continued_actions"] == {
        "count": 1, "finished": 1, "reasons": ["http_request_budget_exhausted"],
    }
    # The finished slice is not a coverage gap.
    assert SLICE not in {gap["action_id"] for gap in coverage["optional_gaps"]}
    # Its action row keeps its own outcome and names the action that continued it.
    row = _action_rows(report)[SLICE]
    assert (row["status"], row["reason_code"]) == ("partial", "http_request_budget_exhausted")
    assert (row["continued_by"], row["continued_status"]) == (EXTENSION, "success")
    # An action nothing continued carries no such field.
    assert "continued_by" not in _action_rows(report)["verify.sqli.r01"]
    assert "continued_by" not in _action_rows(report)[EXTENSION]
    assert SLICE in coverage["superseded_action_ids"]
    assert not any(key.startswith("_") for item in coverage["family_coverage"] for key in item)


def test_a_slice_whose_continuation_also_fell_short_stays_a_gap():
    from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus

    report = _report({
        "status": CapabilityResultStatus.PARTIAL,
        "reason": CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
    }, extension_attempted=False)
    coverage = report["coverage"]

    family = _family(report)
    assert family["coverage_status"] == "partial"
    assert family["continued_actions"] == {
        "count": 1, "finished": 0, "reasons": ["http_request_budget_exhausted"],
    }
    gaps = {gap["action_id"]: gap for gap in coverage["optional_gaps"]}
    assert set(gaps) == {SLICE, EXTENSION}
    assert gaps[EXTENSION]["reason_code"] == "http_request_budget_exhausted"
    row = _action_rows(report)[SLICE]
    assert (row["continued_by"], row["continued_status"]) == (EXTENSION, "partial")


def test_the_explanation_does_not_list_a_finished_slice_as_a_gap():
    from api.scan.explanation import build_scan_execution_explanation
    from tests.test_scan_explanation import SCAN_ID, _plan as explanation_plan, _rows

    def explain(extension_status, extension_reason=None):
        plan = explanation_plan()
        baseline, _middle, final = plan["actions"]
        ids = ("verify.sqli.r01", SLICE, EXTENSION)
        plan["actions"] = [
            {
                **baseline, "action_id": action_id, "capability_name": "sqli.verify_batch",
                "action_digest": str(index + 6) * 64, "ordinal": index, "required": index == 0,
                "capability_args": {
                    "slice": {"start": min(index, 1), "count": 1},
                    **({EXTENDS_ARG: SLICE} if action_id == EXTENSION else {}),
                },
            }
            for index, action_id in enumerate(ids)
        ] + [{**final, "ordinal": 3}]
        template = _rows()[0]
        rows = [
            {**template, "action_id": ids[0], "ordinal": 0, "status": "success", "reason_code": None},
            {"action_id": SLICE, "ordinal": 1, "status": "partial",
             "reason_code": "http_request_budget_exhausted"},
            {"action_id": EXTENSION, "ordinal": 2, "status": extension_status,
             **({"reason_code": extension_reason} if extension_reason else {})},
        ]
        return build_scan_execution_explanation(
            scan_id=SCAN_ID, scan_status="completed", plan_payload=plan, action_rows=rows,
        )["coverage"]

    finished = explain("success")
    assert SLICE not in {gap["action_id"] for gap in finished["optional_gaps"]}
    row = {item["action_id"]: item for item in finished["capability_coverage"]["actions"]}[SLICE]
    assert (row["status"], row["reason_code"]) == ("partial", "http_request_budget_exhausted")
    assert (row["continued_by"], row["continued_status"]) == (EXTENSION, "success")

    short = explain("partial", "http_request_budget_exhausted")
    assert {gap["action_id"] for gap in short["optional_gaps"]} == {SLICE, EXTENSION}
    row = {item["action_id"]: item for item in short["capability_coverage"]["actions"]}[SLICE]
    assert (row["continued_by"], row["continued_status"]) == (EXTENSION, "partial")
