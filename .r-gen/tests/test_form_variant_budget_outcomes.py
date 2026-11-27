"""The report's SQLi budget outcomes and sign-in limits are per attempt, not per candidate id.

The declared sign-in form, the crawled form with its hidden fields and a JSON variant share one
candidate id and are three SQLi attempts (tests/test_auth_endpoint_probe_limit.py). The report
grouped what it says about an unfinished candidate by candidate id: three unfinished variants read
as one outcome whose settled units were merged across the variants, so a technique the crawled form
never ran on its own fields could read refuted. Every record a variant's attempt leaves names its
attempt id; the budget outcome, its verdict row and the sign-in limit's count are keyed by it.
"""
from __future__ import annotations

import dataclasses

from scan.sqli_stages import (
    INCONCLUSIVE_RECORD_KIND,
    STAGE_RECORD_KIND,
    sqli_budget_outcomes,
)

from tests.test_auth_endpoint_probe_limit import (
    SIGN_IN_ROUTES,
    SQLI,
    _overspending,
    _slice,
    _StoredOnce,
)
from tests.test_sqli_budget_inconclusive import SLICE, _Scan

CANDIDATE = "c" * 64
DECLARED, CRAWLED = "a" * 64, "b" * 64
FIELDS = {DECLARED: ("password", "username"), CRAWLED: ("csrf_token", "password", "remember", "username")}


def _head(attempt, **extra):
    return {"kind": "candidate_attempt", "attempt_id": attempt, "candidate_id": CANDIDATE,
            "family": "sqli", "status": "partial", "proof_state": "unproven",
            "resume_wall_seconds": 300, "field_count": len(FIELDS[attempt]), **extra}


def _stage(attempt, technique, field):
    return {"kind": STAGE_RECORD_KIND, "attempt_id": attempt, "candidate_id": CANDIDATE,
            "technique": technique, "field": field, "status": "success", "timed_out": False}


def _rows():
    """The declared form settled U and B on its two fields; the crawled form only U on its four."""
    return [
        _head(DECLARED, resume_technique="E", resume_field="password"),
        *(_stage(DECLARED, technique, field) for technique in "UB" for field in FIELDS[DECLARED]),
        _head(CRAWLED, resume_technique="B", resume_field="csrf_token"),
        *(_stage(CRAWLED, "U", field) for field in FIELDS[CRAWLED]),
    ]


def test_two_unfinished_variants_of_one_candidate_get_an_outcome_each():
    outcomes = {item["attempt_id"]: item for item in sqli_budget_outcomes(_rows())}
    assert set(outcomes) == {DECLARED, CRAWLED}
    assert all(item["candidate_id"] == CANDIDATE for item in outcomes.values())
    assert outcomes[DECLARED]["refuted_techniques"] == ["U", "B"]
    assert outcomes[DECLARED]["unfinished_techniques"] == ["E", "T"]
    # Boolean-based ran on the declared form's two fields, never on the crawled form's four.
    assert outcomes[CRAWLED]["refuted_techniques"] == ["U"]
    assert outcomes[CRAWLED]["unfinished_techniques"] == ["B", "E", "T"]
    assert outcomes[CRAWLED]["next_technique"] == "B"


def test_a_variants_budget_verdict_belongs_to_that_variant():
    verdict = {"kind": INCONCLUSIVE_RECORD_KIND, "attempt_id": CRAWLED, "candidate_id": CANDIDATE,
               "family": "sqli", "verdict": "inconclusive", "closed": True,
               "refuted_techniques": ["U"], "unfundable_techniques": ["B", "E", "T"], "field_count": 4}
    outcomes = {item["attempt_id"]: item for item in sqli_budget_outcomes([*_rows(), verdict])}
    assert outcomes[CRAWLED]["closed"] is True
    assert outcomes[CRAWLED]["inconclusive_techniques"] == ["B", "E", "T"]
    assert outcomes[DECLARED]["closed"] is False
    assert outcomes[DECLARED]["reason"] == "scan_budget_exhausted"


def test_a_verdict_row_of_an_earlier_build_belongs_to_the_attempt_it_follows():
    """Earlier builds left the attempt id off the verdict row, which follows its own head."""
    rows = _rows()
    verdict = {"kind": INCONCLUSIVE_RECORD_KIND, "candidate_id": CANDIDATE, "family": "sqli",
               "verdict": "inconclusive", "closed": True, "refuted_techniques": ["U"],
               "unfundable_techniques": ["B", "E", "T"], "field_count": 4}
    outcomes = sqli_budget_outcomes([*rows, verdict])
    assert {item["attempt_id"] for item in outcomes} == {DECLARED, CRAWLED}
    by_attempt = {item["attempt_id"]: item for item in outcomes}
    assert by_attempt[CRAWLED]["closed"] is True and by_attempt[DECLARED]["closed"] is False


def test_records_of_an_earlier_build_without_attempt_ids_are_one_outcome_per_candidate():
    rows = [{key: value for key, value in item.items() if key != "attempt_id"} for item in _rows()[:5]]
    (outcome,) = sqli_budget_outcomes(rows)
    assert outcome["candidate_id"] == CANDIDATE and outcome["refuted_techniques"] == ["U", "B"]


def test_no_variant_reads_a_technique_it_never_ran_on_its_own_fields_as_refuted():
    """Three variants left unfinished by a 600 s second round, no sign-in profile."""
    budgets = {0: {"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 3_000},
               1: {"http_requests": 6_000, "state_changing_requests": 6_000, "tool_wall_seconds": 600}}
    receipts, rounds, _record = _slice(*SQLI[:1], tool="sqlmap", parser="sqlmap-output/v1", sent=0,
                                       options={}, routes=SIGN_IN_ROUTES[:3], rounds=2, budgets=budgets,
                                       runner=_overspending(1.0), backend_type=_StoredOnce)
    fields: dict[str, tuple] = {}
    ran: dict[str, set] = {}
    for calls in rounds:
        for call in calls:
            attempt = call["job"].split(":")[2]
            fields.setdefault(attempt, tuple(call["options"].get("body_field_names") or ()))
            ran.setdefault(attempt, set()).update(
                (call["options"]["technique"], field) for field in call["options"].get("injection_fields") or ()
            )
    outcomes = sqli_budget_outcomes([item for receipt in receipts for item in receipt.observations])
    assert len({item["attempt_id"] for item in outcomes}) == len(outcomes) >= 2, outcomes
    for outcome in outcomes:
        own = outcome["attempt_id"][:16]
        for technique in outcome["refuted_techniques"]:
            assert {(technique, field) for field in fields[own]} <= ran[own], (outcome, sorted(ran[own]))


def test_the_budget_verdict_row_names_the_attempt_it_judged(monkeypatch):
    scan = _Scan(monkeypatch, ("/slow",))
    scan.add("verify.sqli.r01", path="/slow", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    (probe,) = scan.next_round(2)
    scan.run({probe[0]})
    (head,) = scan.records(probe[0], "candidate_attempt")
    (verdict,) = scan.records(probe[0], INCONCLUSIVE_RECORD_KIND)
    assert verdict["attempt_id"] == head["attempt_id"]


def test_a_deferred_candidates_records_name_its_attempt(monkeypatch):
    scan = _Scan(monkeypatch, ("/stall",))
    scan.add("verify.sqli.r01", path="/stall", budget=SLICE)
    scan.run({"verify.sqli.r01"})
    (head,) = scan.records("verify.sqli.r01", "candidate_attempt")
    scan.add("verify.sqli.r01.ext.r02", path="/stall", extends="verify.sqli.r01",
             budget={**SLICE, "tool_wall_seconds": 420})
    scan.run({"verify.sqli.r01.ext.r02"})
    (deferred,) = scan.records("verify.sqli.r01.ext.r02", "candidate_deferred")
    assert deferred["attempt_id"] == head["attempt_id"]


def test_the_sign_in_limit_counts_each_limited_variant():
    from dataclasses import replace

    from api.runtime.observation_manifests import ObservationManifest
    from api.scan.action_plan import ScanActionPlan as PackagePlan
    from api.scan.auth_endpoint_probe import AUTH_ENDPOINT_PROBE_LIMITED
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID
    from tests.test_scan_orchestrator import _action as plan_action
    from tests.test_scan_orchestrator import _result as settle

    batch = replace(
        plan_action("verify.sqli.r01", 0, capability_name="sqli.verify_batch"),
        capability_args={"slice": {"start": 0, "count": 2}, "manifest_entries": 2},
        output_schema="sqlmap-batch/v1", action_digest=None,
    )
    final = plan_action("finalize.report", 1, dependencies=(batch.action_id,))
    plan = PackagePlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                       target_binding_digest="a" * 64, actions=(batch, final))
    rows = tuple(
        {"kind": "candidate_attempt", "attempt_id": attempt, "candidate_id": CANDIDATE, "family": "sqli",
         "status": "success", "proof_state": "unproven", "verdict": "inconclusive",
         "inconclusive_reason": AUTH_ENDPOINT_PROBE_LIMITED, "sign_in_endpoint": "/hub/login"}
        for attempt in (DECLARED, CRAWLED)
    )
    result = dataclasses.replace(
        settle(batch, status=CapabilityResultStatus.SUCCESS),
        observation_manifest_ref=ObservationManifest(
            manifest_id="00000000-0000-4000-8000-0000000000ae", owner_id=SCAN_ID,
            action_id=batch.action_id, capability_name=batch.capability_name,
            output_schema=batch.output_schema, observation_count=len(rows),
            content_sha256="0" * 64, size_bytes=512, object_key="scans/x.jsonl",
        ).reference(), result_digest=None,
    )
    report = finalize_scan_report(plan=plan, target_url="https://app.example.test",
                                  action_results={batch.action_id: result},
                                  observations={batch.action_id: rows})
    family = next(row for row in report["coverage"]["family_coverage"] if row["family"] == "sqli")
    assert family["sign_in_probe_limited"] == {"endpoints": ["/hub/login"], "candidates": 2}
