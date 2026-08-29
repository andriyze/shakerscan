"""Scoring is two axes, and neither may be inferred from the other.

Risk answers "how bad is what we found", discounted by how well each finding is proven.
Assurance answers "how much did we actually examine". Blending them produced the failure this
replaces: an application nobody managed to scan graded A, because finding nothing and looking
nowhere were indistinguishable.

The severity-ceiling behaviour that this file inherits from
``test_scan_grade_severity_ceiling`` is preserved for *proven* findings: scoring was once
purely subtractive, so one proven critical scored 80 and graded B next to a proven injection.
"""

from __future__ import annotations

import pytest

from api.scan.scoring import (
    ASSURANCE_COMPONENTS,
    GRADE_BANDS,
    assurance,
    caps_risk_grade,
    grade_for,
    proof_weight,
    risk,
    score_scan,
)


def proven(severity):
    """The shape the V2 finalizer stamps once a deterministic proof contract is satisfied."""
    return {
        "severity": severity, "verified": True, "suspected": False,
        "proof_state": "verified",
        "proof_contract_v2": {
            "schema_version": "proof-contract/v2",
            "contract_id": "dast.test",
            "contract_version": "1.0.0",
            "reexecution": {
                "required": True,
                "performed": True,
                "verifier_build": "test-verifier",
            },
            "predicate": {"satisfied": True, "missing": []},
            "verdict": "verified",
            "promotable": True,
        },
    }


def suspected(severity):
    return {"severity": severity, "suspected": True}


# --- risk: proven findings still cap the grade -------------------------------------------

def test_one_proven_critical_cannot_grade_above_f():
    assert risk([proven("critical")])["grade"] == "F"


def test_one_proven_high_cannot_grade_above_c():
    assert risk([proven("high")])["grade"] in {"C", "D", "F"}


def test_one_proven_medium_cannot_grade_above_b():
    assert risk([proven("medium")])["grade"] in {"B", "C", "D", "F"}


def test_a_clean_scan_scores_full_marks():
    result = risk([])
    assert (result["score"], result["grade"]) == (100, "A")


def test_informational_findings_do_not_move_the_grade():
    assert risk([proven("info"), proven("info")])["score"] == 100


def test_deterministic_application_posture_weaknesses_reduce_risk_score():
    result = risk(
        [proven("info")],
        posture={
            "http": {
                "missing_security_headers": [
                    "content-security-policy",
                    "referrer-policy",
                    "strict-transport-security",
                ],
            },
        },
    )
    assert result["score"] == 80
    assert result["posture_penalty"] == 20
    assert "posture_missing_content-security-policy:12" in result["reasons"]
    assert "posture_missing_referrer-policy:2" in result["reasons"]
    assert "posture_missing_strict-transport-security:6" in result["reasons"]


def test_a_low_finding_still_permits_a_high_grade():
    result = risk([proven("low")])
    assert result["grade"] == "A"
    assert result["score"] < 100, "it should still cost something"


def test_volume_eventually_matters_below_the_ceiling():
    one = risk([proven("high")])["score"]
    several = risk([proven("high")] * 3)["score"]
    many = risk([proven("high")] * 6)["score"]
    assert several == one, "the ceiling dominates until the weight exceeds it"
    assert many < one, "volume must eventually matter"


def test_the_worst_proven_severity_sets_the_ceiling():
    assert risk([proven("critical"), proven("low")])["grade"] == "F"


def test_an_unknown_severity_is_treated_as_informational():
    assert risk([{"severity": "bogus"}])["score"] == 100


# --- risk: proof tier changes the ceiling ------------------------------------------------

def test_a_suspected_finding_caps_one_band_softer_than_a_proven_one():
    """Grading an unproven claim as if it were confirmed costs the reader's trust in every
    grade the scanner emits."""
    assert risk([proven("critical")])["grade"] == "F"
    assert risk([suspected("critical")])["grade"] == "C"
    assert risk([proven("high")])["score"] < risk([suspected("high")])["score"]


def test_a_suspected_finding_still_costs_something():
    assert risk([suspected("critical")])["score"] < 100


def test_the_v2_finalizer_proof_contract_counts_as_proven():
    assert caps_risk_grade(proven("high")) is True
    assert proof_weight(proven("high")) == 1.0


def test_generic_verified_pair_is_not_deterministic_proof():
    generic = {"severity": "critical", "verified": True, "proof_state": "verified"}
    assert caps_risk_grade(generic) is False
    assert proof_weight(generic) < 1.0


def test_a_bare_verified_flag_is_not_proof_on_its_own():
    """It can come from a coarse scanner heuristic, so it does not cap the grade."""
    assert caps_risk_grade({"severity": "critical", "verified": True}) is False


def test_a_trusted_ai_false_positive_neither_scores_nor_caps():
    finding = {
        "severity": "critical",
        "ai_verdict": "false_positive",
        "ai_confidence": 0.99,
        "ai_classification_source": "semantic_judge",
    }
    assert proof_weight(finding) == 0.0
    assert risk([finding])["score"] == 100


def test_reasons_separate_proven_from_suspected_counts():
    result = risk([proven("high"), suspected("high"), suspected("critical")])
    assert "proven_high:1" in result["reasons"]
    assert "suspected_high:1" in result["reasons"]
    assert "suspected_critical:1" in result["reasons"]


# --- assurance: it must be earned --------------------------------------------------------

def test_a_scan_that_examined_nothing_scores_zero_assurance():
    """The whole point of the second axis. Silence is not safety."""
    result = assurance({})
    assert result["score"] == 0
    assert result["band"] == "none"
    assert result["gaps"] == ["no_examination_recorded"]


def test_full_coverage_with_authenticated_traffic_scores_strong():
    coverage = {
        "planned_action_count": 10, "terminal_action_count": 10,
        "family_coverage": [
            # Proof escalation actually ran, which is what earns the verification credit.
            {
                "family": "xss", "selected": True, "status": "complete",
                "verified_findings": 1,
                "proof_escalation": {"attempted_candidates": 4},
            },
            {
                "family": "sqli", "selected": True, "status": "complete",
                "verified_findings": 0,
                "proof_escalation": {"attempted_candidates": 2},
            },
        ],
        "candidate_coverage": {
            "xss": {"planned_candidates": 20, "attempted_candidates": 20},
            "sqli": {"planned_candidates": 20, "attempted_candidates": 20},
        },
        "grade_reliability": {"reliable": True, "reasons": []},
        "placement_executed": True,
    }
    result = assurance(coverage, smart_coverage={"principal_contexts_exercised": 2})
    assert result["score"] == 100
    assert result["band"] == "strong"
    assert result["gaps"] == []


def test_verification_credit_requires_verification_to_have_run():
    """A passive scan plans no active verifier, so the zero-attempt reason never appears.
    Reading only that reason handed it full marks for work it never attempted."""
    coverage = {
        "planned_action_count": 4, "terminal_action_count": 4,
        "family_coverage": [{"family": "xss", "selected": True, "status": "complete"}],
        "candidate_coverage": {"xss": {"planned_candidates": 5, "attempted_candidates": 5}},
        "grade_reliability": {"reliable": True, "reasons": []},
    }
    assert "active_verification_attempted" in assurance(coverage)["gaps"]

    escalated = dict(coverage)
    escalated["family_coverage"] = [{
        "family": "xss", "selected": True, "status": "complete",
        "proof_escalation": {"attempted_candidates": 3},
    }]
    assert "active_verification_attempted" not in assurance(escalated)["gaps"]


def test_an_incomplete_family_lowers_assurance_and_is_named():
    coverage = {
        "planned_action_count": 10, "terminal_action_count": 10,
        "family_coverage": [
            {"family": "xss", "selected": True, "status": "complete"},
            {"family": "sqli", "selected": True, "status": "partial"},
        ],
        "candidate_coverage": {
            "sqli": {"planned_candidates": 20, "attempted_candidates": 5},
        },
        "grade_reliability": {"reliable": False, "reasons": ["selected_family_incomplete"]},
    }
    result = assurance(coverage)
    assert result["score"] < 100
    assert "selected_families_complete" in result["gaps"]
    assert "candidates_attempted" in result["gaps"]


def test_a_cancelled_scan_cannot_report_high_assurance():
    coverage = {
        "status": "cancelled",
        "planned_action_count": 10, "terminal_action_count": 10,
        "family_coverage": [{"family": "xss", "selected": True, "status": "complete"}],
        "candidate_coverage": {"xss": {"planned_candidates": 5, "attempted_candidates": 5}},
        "grade_reliability": {"reliable": True, "reasons": []},
    }
    assert assurance(coverage)["score"] <= 40


def test_anonymous_only_coverage_is_not_full_assurance():
    coverage = {
        "planned_action_count": 4, "terminal_action_count": 4,
        "family_coverage": [{"family": "xss", "selected": True, "status": "complete"}],
        "candidate_coverage": {"xss": {"planned_candidates": 5, "attempted_candidates": 5}},
        "grade_reliability": {"reliable": True, "reasons": []},
    }
    result = assurance(coverage, smart_coverage={"auth_states_tested": ["anonymous"]})
    assert "authenticated_coverage" in result["gaps"]


def test_the_component_weights_total_one_hundred():
    assert sum(weight for _, weight in ASSURANCE_COMPONENTS) == 100


def test_assurance_reads_canonical_family_coverage_status():
    coverage = {
        "planned_action_count": 1,
        "terminal_action_count": 1,
        "family_coverage": [
            {"family": "nuclei_passive", "selected": True, "coverage_status": "complete"},
        ],
        "candidate_coverage": {},
    }
    result = assurance(coverage)
    assert result["components"]["selected_families_complete"]["value"] == 1.0
    assert "selected_families_complete" not in result["gaps"]


def test_assurance_counts_required_capabilities_not_the_separate_finalizer():
    coverage = {
        "planned_action_count": 10,
        "terminal_action_count": 9,
        "finalization_action_id": "finalize.report",
        "family_coverage": [],
        "candidate_coverage": {},
        "capability_coverage": {
            "actions": [
                {"action_id": "discover", "required": True, "status": "success"},
                {"action_id": "baseline", "required": True, "status": "success"},
                {"action_id": "optional", "required": False, "status": "skipped"},
            ],
        },
    }
    result = assurance(coverage)
    assert result["components"]["required_actions_complete"]["value"] == 1.0
    assert "required_actions_complete" not in result["gaps"]


def test_required_capability_success_cannot_hide_an_abandoned_plan():
    coverage = {
        "planned_action_count": 20,
        "terminal_action_count": 2,
        "family_coverage": [],
        "candidate_coverage": {},
        "capability_coverage": {
            "actions": [
                {"action_id": "baseline", "required": True, "status": "success"},
            ],
        },
    }
    result = assurance(coverage)
    assert result["components"]["required_actions_complete"]["value"] == 0.1
    assert "required_actions_complete" in result["gaps"]


def test_a_trivial_complete_plan_cannot_look_like_a_broad_examination():
    coverage = {
        "planned_action_count": 1,
        "terminal_action_count": 1,
        "placement_executed": True,
        "family_coverage": [{
            "family": "xss", "selected": True, "status": "complete",
            "proof_escalation": {"attempted_candidates": 1},
        }],
        "candidate_coverage": {
            "xss": {"planned_candidates": 1, "attempted_candidates": 1},
        },
    }
    result = assurance(
        coverage, smart_coverage={"principal_contexts_exercised": 2},
    )
    assert result["score"] < 85
    assert result["band"] != "strong"
    assert result["components"]["examination_breadth"]["value"] < 1


def test_placement_points_must_be_earned_by_execution():
    coverage = {
        "planned_action_count": 8, "terminal_action_count": 8,
        "family_coverage": [
            {"family": "xss", "selected": True, "status": "complete"},
            {"family": "sqli", "selected": True, "status": "complete"},
        ],
        "candidate_coverage": {
            "xss": {"planned_candidates": 10, "attempted_candidates": 10},
            "sqli": {"planned_candidates": 10, "attempted_candidates": 10},
        },
    }
    assert assurance(coverage)["components"]["placement_available"]["value"] == 0
    coverage["placement_executed"] = True
    assert assurance(coverage)["components"]["placement_available"]["value"] == 1


# --- the two axes stay separate ----------------------------------------------------------

def test_a_clean_but_shallow_scan_reports_a_good_grade_and_poor_assurance():
    """The case the old single number could not express."""
    result = score_scan([], {}, grade_reliable=True)
    assert result["risk_grade"] == "A"
    assert result["assurance_score"] == 0
    assert result["assurance_band"] == "none"


def test_the_compatibility_projection_carries_the_risk_axis():
    result = score_scan([proven("critical")], {}, grade_reliable=True)
    assert result["score"] == result["risk_score"]
    assert result["grade"] == result["risk_grade"] == "F"


def test_an_unreliable_grade_still_renders_the_star():
    result = score_scan([], {}, grade_reliable=False)
    assert result["grade"].endswith("*")
    assert result["grade_reliable"] is False


def test_every_engine_resolves_letters_from_one_band_table():
    assert [grade_for(score) for score in (100, 90, 89, 80, 70, 60, 59, 0)] == [
        "A", "A", "B", "B", "C", "D", "F", "F",
    ]
    assert GRADE_BANDS[0] == (90, "A")


def test_legacy_report_narrative_uses_the_canonical_risk_result():
    from grading import grade

    findings = [proven("critical"), suspected("high"), {"severity": "low"}]
    canonical = risk(findings)
    narrative = grade({"findings": findings, "http": {}})
    assert narrative["score"] == canonical["score"]
    assert narrative["grade"].rstrip("*") == canonical["grade"]
