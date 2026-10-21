"""Honest coverage: a family or tool that did no work never reports complete.

One sweep over every capability the Scan planner gives a check family. For each one a Scan is
finalized in which that capability did no work -- no attempt, no request, rejected before it
ran, skipped, cancelled -- while every other action did its work. The family must not read
``complete`` and, when the work was required, the grade must not be reliable.

Two outcomes are deliberately not gaps, and each must say why:

* a family that had nothing to examine (every slice settled ``not_applicable``, or the
  manifest it indexes held no entry) is complete only with ``reason == "no_candidates"``;
* a proof escalation that could not be funded or placed (``unavailable``) leaves the family's
  status to its verifiers, and says so in ``proof_escalation``. A proof that broke -- failed,
  timed out, refused, cancelled, or ran nothing -- makes its family partial.

These are unit-test fixtures (synthetic receipts and observations), not live Scans. The first
part compiles real plans with the real admission and continuation compilers so the sweep cannot
fall behind what the planner produces.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import replace

import pytest

from api.scan import finalizer
from api.scan.action_plan import ScanAction, ScanActionPlan
from api.scan.capability_result import CapabilityResultReason as Reason
from api.scan.capability_result import CapabilityResultStatus as Status
from api.scan.contracts import (
    _SCAN_V2_FAMILY_CAPABILITIES,
    _SCAN_V2_FAMILY_PROOF_CAPABILITIES,
)
from api.scan.finalizer import finalize_scan_report
from tests.scan_round_fixtures import admitted_round_fixture, compile_round, settle_round
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action, _result

# Discovery families have no verifier and no coverage row (their truncation is a Scan-level
# gap: test_discovery_truncation_coverage).
DISCOVERY_FAMILIES = frozenset({"recon", "recon_active"})
CHECK_FAMILIES = tuple(sorted(set(_SCAN_V2_FAMILY_CAPABILITIES) - DISCOVERY_FAMILIES))
VERIFIERS = tuple(
    (family, capability)
    for family in CHECK_FAMILIES
    for capability in _SCAN_V2_FAMILY_CAPABILITIES[family]
)
PROOFS = tuple(
    (family, capability)
    for family, capabilities in sorted(_SCAN_V2_FAMILY_PROOF_CAPABILITIES.items())
    for capability in capabilities
    if capability in finalizer._PROOF_CAPABILITIES
)
# Checks that ride a family's authority without escalating its candidates.
AUXILIARIES = tuple(
    (family, capability)
    for family, capabilities in sorted(_SCAN_V2_FAMILY_PROOF_CAPABILITIES.items())
    for capability in capabilities
    if capability not in finalizer._PROOF_CAPABILITIES
)

# Every way an action can settle having done nothing.
ZERO_WORK = (
    ("success_without_attempts", Status.SUCCESS, None),
    ("partial_request_budget", Status.PARTIAL, Reason.HTTP_REQUEST_BUDGET_EXHAUSTED),
    ("partial_mutation_budget", Status.PARTIAL, Reason.STATE_CHANGING_BUDGET_EXHAUSTED),
    ("timed_out", Status.TIMED_OUT, Reason.TIMED_OUT),
    ("scan_time_limit", Status.TIMED_OUT, Reason.SCAN_TIME_LIMIT),
    ("adapter_failed", Status.FAILED, Reason.ADAPTER_FAILED),
    ("refused_by_policy", Status.BLOCKED, Reason.POLICY_DISABLED),
    ("refused_authorization", Status.BLOCKED, Reason.AUTHORIZATION_REVOKED),
    ("cancelled", Status.CANCELLED, Reason.CANCELLED),
    ("skipped_unfunded", Status.SKIPPED, Reason.INSUFFICIENT_PLAN_BUDGET),
    ("skipped_unplaced", Status.SKIPPED, Reason.PLACEMENT_UNAVAILABLE),
    ("skipped_manifest_unavailable", Status.SKIPPED, Reason.MANIFEST_UNAVAILABLE),
    ("skipped_dependency_failed", Status.SKIPPED, Reason.DEPENDENCY_FAILED),
    ("skipped_dependency_incomplete", Status.SKIPPED, Reason.DEPENDENCY_INCOMPLETE),
)
# A proof that could not be funded or placed: stated as unavailable, not a break.
PROOF_UNAVAILABLE = frozenset({
    Reason.INSUFFICIENT_PLAN_BUDGET, Reason.PLACEMENT_UNAVAILABLE, Reason.DEPENDENCY_INCOMPLETE,
})


# --- the planner: the sweep covers everything it can produce ----------------------------------


PLANNED_SCENARIOS = (
    # Every family the fixture compiler can plan without credentials or a request collection,
    # with state-changing authority (thorough funds the active-template mutation holds).
    ("thorough", True, (
        "recon", "nuclei_passive", "nuclei_active", "xss", "sqli", "sensitive_exposure",
        "nosqli", "graphql",
    )),
    ("balanced", False, ("recon", "nuclei_passive", "nuclei_active", "xss", "sqli")),
    ("fast", False, ("recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure")),
)


def _slice_attempts(action):
    """One completed attempt per slice entry: the action did its work."""
    raw = action.capability_args.get("slice")
    if not isinstance(raw, Mapping):
        return ()
    return tuple(
        {
            "kind": "candidate_attempt", "status": "success", "candidate_id": f"c-{index}",
            "attempt_id": hashlib.sha256(f"{action.action_id}:{index}".encode()).hexdigest(),
        }
        for index in range(int(raw["start"]), int(raw["start"]) + int(raw["count"]))
    )


def _settle_working(action):
    return Status.SUCCESS, None, {
        name: min(1, int(value)) for name, value in action.requested_budget.items()
    }


def _compiled_scan(profile, state_changing, families):
    fixture = admitted_round_fixture(
        profile, endpoints=9, queries=4, state_changing=state_changing, families=families,
    )
    prepared = None
    for number in range(1, 6):
        settle_round(fixture, _settle_working, observations=_slice_attempts)
        prepared = compile_round(fixture, number)
        if any(action.action_id == "finalize.report" for action in fixture["parent_plan"].actions):
            break
    settle_round(fixture, _settle_working, observations=_slice_attempts)
    return fixture, prepared


def _family_capabilities():
    return {capability for _family, capability in (*VERIFIERS, *PROOFS, *AUXILIARIES)}


@pytest.mark.parametrize("profile, state_changing, families", PLANNED_SCENARIOS)
def test_the_sweep_covers_every_family_capability_the_planner_plans(
    profile, state_changing, families,
):
    fixture, _prepared = _compiled_scan(profile, state_changing, families)
    discovery = {
        capability for family in DISCOVERY_FAMILIES
        for capability in _SCAN_V2_FAMILY_CAPABILITIES[family]
    }
    planned = {action.capability_name for action in fixture["parent_plan"].actions}
    checks = planned - discovery - {
        # Baseline and posture probes, and finalization: no check family.
        "http.request", "dns.inspect", "tls.inspect", "scan.finalize",
    }
    assert checks, "the planner planned no check family"
    assert checks <= _family_capabilities(), checks - _family_capabilities()


def test_every_family_capability_reaches_the_family_coverage_report():
    for family, capability in (*VERIFIERS, *PROOFS):
        assert finalizer._FAMILY_BY_CAPABILITY.get(capability) == family, capability
    for family, capability in AUXILIARIES:
        assert finalizer._AUXILIARY_CHECKS.get(capability, (None,))[0] == family, capability


@pytest.mark.parametrize("profile, state_changing, families", PLANNED_SCENARIOS)
def test_a_compiled_scan_whose_family_did_no_work_never_reads_complete(
    profile, state_changing, families,
):
    """The real plan: every action works, then each planned family's actions do nothing."""
    fixture, prepared = _compiled_scan(profile, state_changing, families)
    actions = {action.action_id: action for action in fixture["parent_plan"].actions}

    def report(idle_family=None):
        results, observations = {}, {}
        for action_id, result in fixture["parent_results"].items():
            if action_id == "finalize.report":
                continue
            action = actions[action_id]
            idle = (
                idle_family is not None
                and finalizer._FAMILY_BY_CAPABILITY.get(action.capability_name) == idle_family
            )
            rows = () if idle else tuple(fixture["observations"].get(action_id) or ())
            results[action_id] = replace(
                _result_with_observation_count(action, len(rows)),
                budget_consumed={} if idle else dict(result.budget_consumed),
                result_digest=None,
            ) if rows or idle else result
            observations[action_id] = rows
        return finalize_scan_report(
            plan=fixture["parent_plan"], target_url="https://app.example.test",
            action_results=results, observations=observations,
            plan_revision=prepared.revision,
            resolved_families=list(fixture["execution_plan"].resolved_families),
        )

    working = report()
    rows = {row["family"]: row for row in working["coverage"]["family_coverage"]}
    planned_families = sorted(
        {finalizer._FAMILY_BY_CAPABILITY[action.capability_name] for action in actions.values()
         if action.capability_name in finalizer._FAMILY_BY_CAPABILITY}
    )
    assert planned_families
    for family in planned_families:
        assert rows[family]["coverage_status"] == "complete", (family, rows[family]["reason"])
    assert working["result"]["grade_reliable"] is True, working["coverage"]["grade_reliability"]

    for family in planned_families:
        idle = report(idle_family=family)
        row = next(item for item in idle["coverage"]["family_coverage"] if item["family"] == family)
        assert row["coverage_status"] != "complete", family
        assert row["reason"] != "no_candidates", family
        if row["required"]:
            assert family in idle["coverage"]["selected_family_gaps"], family
            assert idle["result"]["grade_reliable"] is False, family
        else:
            # Planned best-effort (an opt-in family the profile did not make required).
            assert family not in idle["coverage"]["selected_family_gaps"], family
    assert any(
        row["required"] for row in working["coverage"]["family_coverage"]
        if row["family"] in planned_families
    )


# --- the sweep: every capability, every way of doing nothing --------------------------------


def _manifest_ref(entry_count, *, status="complete", digest="d" * 64):
    """A work manifest reference as the planner freezes one into a slice's arguments."""
    return {
        "manifest_id": "40000000-0000-4000-8000-000000000001", "kind": "candidate",
        "content_schema": "scan-candidate-work-entry/v1", "manifest_digest": digest,
        "entry_count": entry_count, "status": status,
    }


def _planned_slice(
    action_id, capability, ordinal, *, count=3, required=True, entries=None, manifest_ref=None,
):
    """A batch action shaped as the planner shapes one (``add_manifest_batches``)."""
    args = (
        {"principal_lanes": ["primary", "secondary"], "endpoint_manifest_ref": None}
        if capability == "authz.verify" else {
            "slice": {"start": 0, "count": count},
            "manifest_entries": count if entries is None else entries,
            "scheduled_batches": 1, "total_batches": 1,
            "profile": "balanced_batch_v1",
            "proof_policy": "deterministic_proof_contract_required",
            **({"candidate_manifest_ref": manifest_ref} if manifest_ref else {}),
        }
    )
    return ScanAction(
        action_id=action_id, stage="verify_candidates", ordinal=ordinal,
        capability_name=capability, capability_args=args,
        target_binding_digest="a" * 64,
        input_binding_digest=hashlib.sha256(action_id.encode()).hexdigest(),
        requested_budget={"http_requests": 40, "tool_wall_seconds": 30},
        placement={
            "schema_version": "scan-action-placement/v1", "eligible_backends": ["local"],
            "adapter_name": "internal", "adapter_version": "1",
        },
        dependencies=(), required=required, supporting=False,
        output_schema="candidate-attempt/v1",
    )


def _work_rows(action, count=3):
    """What a capability records when it did its work."""
    if action.capability_name == "authz.verify":
        return ({
            "kind": "authz_differential", "proof_state": "inconclusive",
            "reason": "ownership_differential_not_proven", "principal_contexts_distinct": True,
            "route_count": 3, "producers_tested": 2, "replays_completed": 1,
            "write_replays_attempted": 0, "secret_values_visible": False,
        },)
    return tuple(
        {
            "kind": "candidate_attempt", "status": "success", "candidate_id": f"c-{index}",
            "attempt_id": hashlib.sha256(f"{action.action_id}:{index}".encode()).hexdigest(),
        }
        for index in range(count)
    )


def _settled(action, status, reason, rows=()):
    if status is Status.SUCCESS:
        return _result_with_observation_count(action, len(rows))
    return _result(action, status=status, reason=reason)


def _companion_family(family):
    return "nuclei_active" if family == "nuclei_passive" else "nuclei_passive"


def _finalize(actions, results, observations, family, *, work_manifests=()):
    final = _action(
        "finalize.report", len(actions), dependencies=tuple(a.action_id for a in actions),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64,
        target_binding_digest="a" * 64, actions=(*actions, final),
    )
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations=observations,
        resolved_families=[family, _companion_family(family)],
        work_manifest_references=work_manifests,
    )
    rows = {row["family"]: row for row in report["coverage"]["family_coverage"]}
    return report, rows[family]


def _companion_that_worked(family):
    # An application-surface family that did its work, so a gap is the swept family's alone.
    companion = _companion_family(family)
    action = _planned_slice(
        "companion.templates", _SCAN_V2_FAMILY_CAPABILITIES[companion][0], 0,
    )
    return action, _result_with_observation_count(action, 3), _work_rows(action)


def _verifier_report(family, capability, status, reason, *, required=True, rows=()):
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.swept", capability, 1, required=required)
    return _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _settled(verifier, status, reason, rows)},
        {passive.action_id: passive_rows, verifier.action_id: rows},
        family,
    )


@pytest.mark.parametrize("family, capability", VERIFIERS)
@pytest.mark.parametrize("mode, status, reason", ZERO_WORK, ids=[m[0] for m in ZERO_WORK])
def test_a_verifier_that_did_no_work_leaves_its_family_partial(
    family, capability, mode, status, reason,
):
    report, row = _verifier_report(family, capability, status, reason)
    assert row["coverage_status"] != "complete", (mode, row["reason"])
    assert row["reason"] != "no_candidates"
    assert family in report["coverage"]["selected_family_gaps"]
    assert report["result"]["grade_reliable"] is False
    assert report["coverage"]["status"] != "complete"


@pytest.mark.parametrize("family, capability", VERIFIERS)
def test_an_optional_verifier_that_did_no_work_is_partial_without_flipping_the_grade(
    family, capability,
):
    report, row = _verifier_report(
        family, capability, Status.SUCCESS, None, required=False,
    )
    assert row["coverage_status"] != "complete"
    assert family not in report["coverage"]["selected_family_gaps"]


@pytest.mark.parametrize("family, capability", VERIFIERS)
def test_a_verifier_that_did_its_work_is_complete(family, capability):
    verifier = _planned_slice("verify.swept", capability, 1)
    report, row = _verifier_report(
        family, capability, Status.SUCCESS, None, rows=_work_rows(verifier),
    )
    assert row["coverage_status"] == "complete", row["reason"]
    assert row["reason"] is None
    assert report["coverage"]["selected_family_gaps"] == []
    assert report["result"]["grade_reliable"] is True


# --- nothing to examine is complete only when the coverage says so -------------------------


@pytest.mark.parametrize("family, capability", VERIFIERS)
def test_a_family_with_nothing_to_examine_is_complete_and_says_why(family, capability):
    """Skipped as not applicable over an empty manifest (the slice of one the planner gives
    it). The same skip over a slice of real entries stays a gap: nothing says they were
    examined."""
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.swept", capability, 1, count=1, entries=0)
    report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result(verifier, status=Status.SKIPPED, reason=Reason.NOT_APPLICABLE)},
        {passive.action_id: passive_rows, verifier.action_id: ()},
        family,
    )
    assert row["coverage_status"] == "complete"
    assert row["reason"] == "no_candidates"
    assert "selected_family_no_candidates" in report["coverage"]["reasons"]


@pytest.mark.parametrize(
    "family, capability", [item for item in VERIFIERS if item[1] != "authz.verify"],
)
def test_a_slice_over_an_empty_manifest_is_complete_and_says_why(family, capability):
    """The planner gives an empty manifest a slice of one (``add_manifest_batches``); a verifier
    that settled it successfully had nothing to attempt, and the coverage names that. The
    manifest's own reference proves it was produced complete with no entry."""
    passive, passive_result, passive_rows = _companion_that_worked(family)
    reference = _manifest_ref(0)
    verifier = _planned_slice(
        "verify.swept", capability, 1, count=1, entries=0, manifest_ref=reference,
    )
    report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 0)},
        {passive.action_id: passive_rows, verifier.action_id: ()},
        family, work_manifests=(reference,),
    )
    assert row["coverage_status"] == "complete"
    assert row["reason"] == "no_candidates"


EMPTY_WITHOUT_PROOF = (
    # The admission placeholder: the manifest did not exist yet, so the planner declared 0.
    ("no_manifest_reference", None, ()),
    # The producer stopped before the manifest was finished.
    ("incomplete_manifest", _manifest_ref(0, status="partial"), (_manifest_ref(0, status="partial"),)),
    # The slice names a manifest the Scan's references do not hold.
    ("unknown_manifest", _manifest_ref(0), (_manifest_ref(0, digest="e" * 64),)),
)


@pytest.mark.parametrize(
    "family, capability", [item for item in VERIFIERS if item[1] != "authz.verify"],
)
@pytest.mark.parametrize(
    "case, reference, work_manifests", EMPTY_WITHOUT_PROOF, ids=[c[0] for c in EMPTY_WITHOUT_PROOF],
)
def test_a_declared_empty_manifest_without_a_complete_reference_is_no_work(
    family, capability, case, reference, work_manifests,
):
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice(
        "verify.swept", capability, 1, count=1, entries=0, manifest_ref=reference,
    )
    report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 0)},
        {passive.action_id: passive_rows, verifier.action_id: ()},
        family, work_manifests=work_manifests,
    )
    assert row["coverage_status"] == "partial", case
    assert row["reason"] == "zero_work"
    assert report["result"]["grade_reliable"] is False


def test_a_failed_discovery_cannot_launder_an_empty_slice_into_no_candidates():
    """An optional crawl failed, so the candidate manifest was never produced; the XSS slice
    the admission plan declared empty settled successfully over nothing."""
    from tests.test_scan_orchestrator import _action as plain_action

    passive, passive_result, passive_rows = _companion_that_worked("xss")
    crawl = replace(
        plain_action("discover.web_crawl", 1, capability_name="web.crawl"),
        required=False, action_digest=None,
    )
    verifier = _planned_slice("verify.swept", "xss.verify_batch", 2, count=1, entries=0)
    report, row = _finalize(
        (passive, crawl, verifier),
        {passive.action_id: passive_result,
         crawl.action_id: _result(crawl, status=Status.FAILED, reason=Reason.ADAPTER_FAILED),
         verifier.action_id: _result_with_observation_count(verifier, 0)},
        {passive.action_id: passive_rows, verifier.action_id: ()},
        "xss",
    )
    assert (row["coverage_status"], row["reason"]) == ("partial", "zero_work")
    assert report["coverage"]["status"] != "complete"
    assert "discovery_failed" in report["coverage"]["reasons"]
    assert report["result"]["grade_reliable"] is False


def test_a_failed_discovery_producer_leaves_the_scan_partial_with_its_reason():
    from tests.test_scan_orchestrator import _action as plain_action

    passive, passive_result, passive_rows = _companion_that_worked("xss")
    verifier = _planned_slice("verify.swept", "xss.verify_batch", 2)
    crawl = replace(
        plain_action("discover.web_crawl", 1, capability_name="web.crawl"),
        required=False, action_digest=None,
    )
    report, row = _finalize(
        (passive, crawl, verifier),
        {passive.action_id: passive_result,
         crawl.action_id: _result(crawl, status=Status.FAILED, reason=Reason.ADAPTER_FAILED),
         verifier.action_id: _result_with_observation_count(verifier, 3)},
        {passive.action_id: passive_rows, verifier.action_id: _work_rows(verifier)},
        "xss",
    )
    assert row["coverage_status"] == "complete"
    assert report["coverage"]["status"] == "partial"
    assert "discovery_failed" in report["coverage"]["reasons"]
    assert report["coverage"]["failed_discovery_actions"] == [crawl.action_id]
    assert "discovery_failed" in report["coverage"]["grade_reliability"]["reasons"]


@pytest.mark.parametrize(
    "family, capability", [item for item in VERIFIERS if item[1] != "authz.verify"],
)
def test_inapplicable_records_count_distinct_entries(family, capability):
    """Two records about one entry leave the slice's other entry unaccounted for."""
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.swept", capability, 1, count=2)
    rows = tuple(
        {"kind": "candidate_inapplicable", "candidate_id": "c-0", "reason": reason}
        for reason in ("not_this_family", "path_segment_candidate")
    )
    _report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, len(rows))},
        {passive.action_id: passive_rows, verifier.action_id: rows},
        family,
    )
    assert row["planned_candidates"] == 1
    assert row["coverage_status"] == "partial"
    assert row["reason"] != "no_candidates"


@pytest.mark.parametrize(
    "family, capability", [item for item in VERIFIERS if item[1] != "authz.verify"],
)
def test_a_slice_that_recorded_attempts_is_not_a_family_without_candidates(family, capability):
    """Every slice entry was recorded inapplicable, yet the verifier also recorded an attempt:
    it did work, so it is complete but not "no candidates"."""
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.swept", capability, 1, count=2)
    rows = (
        *({"kind": "candidate_inapplicable", "candidate_id": f"c-{index}", "reason": "x"}
          for index in range(2)),
        *_work_rows(verifier, 1),
    )
    _report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, len(rows))},
        {passive.action_id: passive_rows, verifier.action_id: rows},
        family,
    )
    assert row["attempted_candidates"] == 1
    assert row["coverage_status"] == "complete"
    assert row["reason"] is None


@pytest.mark.parametrize(
    "family, capability", [item for item in VERIFIERS if item[1] != "authz.verify"],
)
def test_a_slice_whose_entries_were_all_inapplicable_is_complete_and_says_why(family, capability):
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.swept", capability, 1, count=2)
    rows = tuple(
        {"kind": "candidate_inapplicable", "candidate_id": f"c-{index}", "reason": "not_this_family"}
        for index in range(2)
    )
    report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, len(rows))},
        {passive.action_id: passive_rows, verifier.action_id: rows},
        family,
    )
    assert row["coverage_status"] == "complete"
    assert row["reason"] == "no_candidates"


def test_a_verifier_without_a_declared_manifest_that_attempted_nothing_is_partial():
    """No slice entry, no declared manifest, no attempt: nothing shows the family had nothing to
    examine, so it did no work."""
    family = "xss"
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = replace(
        _planned_slice("verify.swept", "xss.verify_batch", 1, count=1, entries=0),
        capability_args={"profile": "balanced_batch_v1"}, action_digest=None,
    )
    report, row = _finalize(
        (passive, verifier),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 0)},
        {passive.action_id: passive_rows, verifier.action_id: ()},
        family,
    )
    assert row["coverage_status"] == "partial"
    assert row["reason"] == "zero_work"
    assert report["result"]["grade_reliable"] is False


# --- object authorization: a comparison that never ran ---------------------------------------


@pytest.mark.parametrize("observation, expected", [
    # The two credentials resolved to one identity: no cross-principal comparison happened.
    ({"proof_state": "inconclusive", "reason": "principal_contexts_not_distinct",
      "principal_contexts_distinct": False}, ("partial", "zero_attempts")),
    ({"proof_state": "inconclusive", "reason": "same_principal_context",
      "principal_contexts_distinct": True, "route_count": 3, "producers_tested": 0,
      "replays_completed": 0}, ("partial", "zero_attempts")),
    # Routes existed but not one producer was tested.
    ({"proof_state": "inconclusive", "reason": "ownership_differential_not_proven",
      "principal_contexts_distinct": True, "route_count": 3, "producers_tested": 0,
      "replays_completed": 0}, ("partial", "zero_attempts")),
    # No route of the target was in scope: nothing to examine, and the row says so.
    ({"proof_state": "inconclusive", "reason": "no_target_bound_routes",
      "principal_contexts_distinct": True}, ("complete", "no_candidates")),
    # Routes existed and every one was filtered out as a low-value producer: nothing to examine.
    ({"proof_state": "inconclusive", "reason": "ownership_differential_not_proven",
      "principal_contexts_distinct": True, "route_count": 3, "producer_candidate_count": 0,
      "producers_tested": 0, "replays_completed": 0}, ("complete", "no_candidates")),
    # The selected-object comparison (two sibling object URLs) ran its requests.
    ({"mode": "selected_object", "proof_state": "inconclusive",
      "selected_request_examined": True, "access_denied": True,
      "reason": "selected_object_denied_to_secondary", "requests_attempted": 3},
     ("complete", None)),
    ({"mode": "selected_object", "proof_state": "inconclusive",
      "selected_request_examined": True, "cross_access_observed": True,
      "reason": "selected_object_cross_access_observed_entitlement_unproven",
      "requests_attempted": 4}, ("complete", None)),
    # It stopped at the secondary baseline, after a request.
    ({"mode": "selected_object", "proof_state": "inconclusive",
      "selected_request_examined": False, "reason": "secondary_baseline_status_404",
      "requests_attempted": 1}, ("complete", None)),
    # It sent nothing.
    ({"mode": "selected_object", "proof_state": "inconclusive",
      "selected_request_examined": False, "reason": "selected_object_not_examined",
      "requests_attempted": 0}, ("partial", "zero_attempts")),
])
def test_an_object_authorization_check_that_compared_nothing_is_not_complete(
    observation, expected,
):
    rows = ({"kind": "authz_differential", "secret_values_visible": False, **observation},)
    report, row = _verifier_report("bola", "authz.verify", Status.SUCCESS, None, rows=rows)
    assert (row["coverage_status"], row["reason"]) == expected
    assert report["result"]["grade_reliable"] is (expected[0] == "complete")


@pytest.mark.parametrize("observation, stated", [
    ({"reason": "no_target_bound_routes"}, "no_target_bound_routes"),
    ({"reason": "ownership_differential_not_proven", "route_count": 3,
      "producer_candidate_count": 0, "producers_tested": 0}, "no_producer_candidates"),
])
def test_object_authorization_with_nothing_to_examine_states_why(observation, stated):
    rows = ({"kind": "authz_differential", "proof_state": "inconclusive",
             "principal_contexts_distinct": True, **observation},)
    _report, row = _verifier_report("bola", "authz.verify", Status.SUCCESS, None, rows=rows)
    assert row["reason"] == "no_candidates"
    assert row["no_candidates_reasons"] == [stated]


def test_a_family_whose_verifier_produced_a_finding_did_work():
    """A finding is evidence of work even when the verifier counted no attempt."""
    family = "sensitive_exposure"
    passive, passive_result, passive_rows = _companion_that_worked(family)
    probe = replace(
        _planned_slice("verify.swept", "exposure.verify_batch", 1, count=1, entries=0),
        capability_args={"profile": "balanced_batch_v1"}, action_digest=None,
    )
    rows = ({"kind": "sensitive_exposure_proof", "proof_state": "verified",
             "finding_verdict": "verified", "exposure_class": "directory_listing",
             "severity": "high", "response_status": 200,
             "request_url": "https://app.example.test/files/", "response_body_sha256": "c" * 64},)
    report, row = _finalize(
        (passive, probe),
        {passive.action_id: passive_result,
         probe.action_id: _result_with_observation_count(probe, 1)},
        {passive.action_id: passive_rows, probe.action_id: rows},
        family,
    )
    assert row["verified_findings"] == 1
    assert row["coverage_status"] == "complete"
    assert row["reason"] is None


# --- proof escalation ------------------------------------------------------------------------


def _proof_report(family, capability, status, reason, rows=()):
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier_capability = _SCAN_V2_FAMILY_CAPABILITIES[family][0]
    verifier = _planned_slice("verify.family", verifier_capability, 1)
    proof = _planned_slice("prove.swept", capability, 2, required=False)
    return _finalize(
        (passive, verifier, proof),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 3),
         proof.action_id: _settled(proof, status, reason, rows)},
        {passive.action_id: passive_rows, verifier.action_id: _work_rows(verifier),
         proof.action_id: rows},
        family,
    )


@pytest.mark.parametrize("family, capability", PROOFS)
@pytest.mark.parametrize(
    "mode, status, reason",
    [item for item in ZERO_WORK if item[2] not in PROOF_UNAVAILABLE],
    ids=[item[0] for item in ZERO_WORK if item[2] not in PROOF_UNAVAILABLE],
)
def test_a_proof_that_broke_or_ran_nothing_leaves_its_family_partial(
    family, capability, mode, status, reason,
):
    if status is Status.SUCCESS:
        pytest.skip("a proof that succeeded over no candidate escalated nothing it was given")
    report, row = _proof_report(family, capability, status, reason)
    assert row["coverage_status"] == "partial", (mode, row["proof_escalation"])
    assert row["reason"] == "proof_escalation_failed"
    assert family in report["coverage"]["selected_family_gaps"]
    assert report["result"]["grade_reliable"] is False


@pytest.mark.parametrize("family, capability", PROOFS)
@pytest.mark.parametrize("reason", sorted(PROOF_UNAVAILABLE, key=lambda item: item.value))
def test_an_unavailable_proof_is_stated_not_hidden(family, capability, reason):
    report, row = _proof_report(family, capability, Status.SKIPPED, reason)
    assert row["proof_escalation"]["status"] == "unavailable"
    assert row["proof_escalation"]["reason"] == reason.value
    assert row["proof_escalation"]["status"] != "complete"


@pytest.mark.parametrize("family, capability", PROOFS)
def test_a_proof_with_nothing_eligible_is_not_applicable(family, capability):
    report, row = _proof_report(family, capability, Status.SKIPPED, Reason.NOT_APPLICABLE)
    assert row["coverage_status"] == "complete"
    assert row["proof_escalation"]["status"] == "not_applicable"
    assert report["result"]["grade_reliable"] is True


# --- checks that ride a family's authority ---------------------------------------------------


def _auxiliary_report(family, capability, status, reason, rows=()):
    passive, passive_result, passive_rows = _companion_that_worked(family)
    verifier = _planned_slice("verify.family", _SCAN_V2_FAMILY_CAPABILITIES[family][0], 1)
    check = _planned_slice("verify.auxiliary", capability, 2, required=False)
    return _finalize(
        (passive, verifier, check),
        {passive.action_id: passive_result,
         verifier.action_id: _result_with_observation_count(verifier, 3),
         check.action_id: _settled(check, status, reason, rows)},
        {passive.action_id: passive_rows, verifier.action_id: _work_rows(verifier),
         check.action_id: rows},
        family,
    )


@pytest.mark.parametrize("family, capability", AUXILIARIES)
@pytest.mark.parametrize("mode, status, reason", ZERO_WORK, ids=[m[0] for m in ZERO_WORK])
def test_an_auxiliary_check_that_did_no_work_reports_partial(
    family, capability, mode, status, reason,
):
    """The open-redirect probe rides the XSS family's authority and is best-effort (never
    required), so it does not move the family's grade; its own coverage must still say it ran
    nothing instead of vanishing from the report."""
    _report, row = _auxiliary_report(family, capability, status, reason)
    name = finalizer._AUXILIARY_CHECKS[capability][1]
    assert row[name]["status"] == "partial", (mode, row[name])
    assert row[name]["reason"]
    assert row["coverage_status"] == "complete"


@pytest.mark.parametrize("family, capability", AUXILIARIES)
def test_an_auxiliary_check_reports_its_work_and_its_empty_surface(family, capability):
    name = finalizer._AUXILIARY_CHECKS[capability][1]
    check = _planned_slice("verify.auxiliary", capability, 2, required=False)
    _report, row = _auxiliary_report(family, capability, Status.SUCCESS, None, _work_rows(check))
    assert row[name]["status"] == "complete"
    assert row[name]["attempted_candidates"] == 3
    inapplicable = tuple(
        {"kind": "candidate_inapplicable", "candidate_id": f"c-{index}",
         "reason": "no_redirect_parameter"}
        for index in range(3)
    )
    _report, row = _auxiliary_report(family, capability, Status.SUCCESS, None, inapplicable)
    assert row[name]["status"] == "not_applicable"
    assert row[name]["reason"] == "no_candidates"
    _report, row = _auxiliary_report(family, capability, Status.SKIPPED, Reason.NOT_APPLICABLE)
    assert row[name]["status"] == "not_applicable"


def test_an_auxiliary_check_is_reported_when_its_family_had_no_verifier_action():
    """The XSS verifier was never planned (no candidates), yet the open-redirect probe ran: its
    row is attached to the family's unplanned row instead of being dropped."""
    family, capability = AUXILIARIES[0]
    name = finalizer._AUXILIARY_CHECKS[capability][1]
    passive, passive_result, passive_rows = _companion_that_worked(family)
    check = _planned_slice("verify.auxiliary", capability, 1, required=False)
    _report, row = _finalize(
        (passive, check),
        {passive.action_id: passive_result,
         check.action_id: _result(check, status=Status.FAILED, reason=Reason.ADAPTER_FAILED)},
        {passive.action_id: passive_rows},
        family,
    )
    assert row["batch_actions"] == 0
    assert row[name]["status"] == "partial"
    assert row[name]["reason"] == "adapter_failed"


# --- the parallel merge keeps the distinction ------------------------------------------------


@pytest.mark.parametrize("attempted, expected", [(9, "child_family_incomplete"), (0, "zero_work")])
def test_a_shard_that_did_no_work_keeps_the_merged_family_partial(attempted, expected):
    from api.scan.parallel_compiler import _reconciled_family_coverage

    merged = _reconciled_family_coverage({
        "family": "xss", "reason": "zero_work", "attempted_candidates": attempted,
        "coverage_status": "partial", "batch_actions": 2,
    })
    assert merged["coverage_status"] == "partial"
    assert merged["reason"] == expected


@pytest.mark.parametrize("children, expected", [
    ((("complete", None, 2, 2), ("complete", None, 1, 1)), ("complete", None, 3, 3)),
    ((("complete", None, 2, 2), ("partial", "adapter_failed", 1, 0)), ("partial", "adapter_failed", 3, 2)),
    ((("not_applicable", "no_candidates", 0, 0), ("complete", None, 1, 1)), ("complete", None, 1, 1)),
    ((("not_applicable", "no_candidates", 0, 0),) * 2, ("not_applicable", "no_candidates", 0, 0)),
])
def test_the_parallel_merge_carries_the_auxiliary_check_row(children, expected):
    from api.scan.parallel_compiler import merge_auxiliary_check_rows

    merged = merge_auxiliary_check_rows([
        {"actions": 1, "status": status, "reason": reason,
         "planned_candidates": planned, "attempted_candidates": attempted}
        for status, reason, planned, attempted in children
    ])
    assert (merged["status"], merged["reason"], merged["planned_candidates"],
            merged["attempted_candidates"]) == expected
    assert merged["actions"] == len(children)


def test_the_reconciled_family_keeps_the_merged_auxiliary_row():
    from api.scan.parallel_compiler import _reconciled_family_coverage

    merged = _reconciled_family_coverage({
        "family": "xss", "reason": None, "coverage_status": "complete",
        "attempted_candidates": 3, "batch_actions": 2,
        "_auxiliary": {"open_redirect": [
            {"actions": 1, "status": "complete", "reason": None,
             "planned_candidates": 1, "attempted_candidates": 1},
            {"actions": 1, "status": "partial", "reason": "timed_out",
             "planned_candidates": 2, "attempted_candidates": 0},
        ]},
    })
    assert "_auxiliary" not in merged
    assert merged["open_redirect"]["status"] == "partial"
    assert merged["open_redirect"]["reason"] == "timed_out"
