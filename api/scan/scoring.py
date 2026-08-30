"""The one place a ShakerScan score or letter grade is decided.

Three implementations used to exist with different grade bands, so the same findings could
render a different letter depending on which path finalized the scan. Worse, the canonical
one read nothing but severities: an application nobody managed to scan graded A, because
finding nothing and looking nowhere were indistinguishable.

Scoring is therefore two independent axes that are never blended:

* **Risk** answers "how bad is what we found", weighted by how well it is proven. A verified
  critical and a suspected one are not the same claim and must not cap the grade equally.
* **Assurance** answers "how much of the application did we actually examine, and how much
  of what we claim did we prove". It is the axis that stops silence reading as safety.

A single number cannot carry both. A blended 40 could mean a thoroughly tested application
with a real problem, or a clean sweep of nothing, and those call for opposite actions.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

try:
    from risk_scoring import (
        HTTP_POSTURE_WEIGHT, PROVEN_CEILING, SEVERITY_WEIGHT, SUSPECTED_CEILING,
        caps_risk_grade, proof_weight, risk,
    )
    from score_bands import GRADE_BANDS, grade_for
except ModuleNotFoundError:  # package import layout
    from scanner.risk_scoring import (
        HTTP_POSTURE_WEIGHT, PROVEN_CEILING, SEVERITY_WEIGHT, SUSPECTED_CEILING,
        caps_risk_grade, proof_weight, risk,
    )
    from scanner.score_bands import GRADE_BANDS, grade_for


SCORE_POLICY = "risk_and_assurance/v8"

ASSURANCE_BANDS: tuple[tuple[int, str], ...] = (
    (85, "strong"), (70, "adequate"), (50, "limited"), (1, "weak"), (0, "none"),
)


def assurance_band(score: int) -> str:
    for threshold, band in ASSURANCE_BANDS:
        if score >= threshold:
            return band
    return "none"


# What assurance is made of, and what each part is worth. The weights say which gaps most
# undermine confidence in a clean result: work that was planned and never ran matters more
# than the breadth of identities exercised.
ASSURANCE_COMPONENTS: tuple[tuple[str, int], ...] = (
    ("required_actions_complete", 15),
    ("selected_families_complete", 15),
    ("candidates_attempted", 10),
    ("active_verification_attempted", 10),
    ("authenticated_coverage", 10),
    ("placement_available", 5),
    # Plan-relative completion alone lets a one-action, one-family, one-candidate plan earn
    # the same 100 as a broad examination. This component is deliberately absolute.
    ("examination_breadth", 35),
)


def _ratio(done: float, planned: float) -> float:
    """Proportion of planned work that happened.

    Nothing planned scores zero, not full marks. Assurance measures examination that was
    demonstrated, so "we planned nothing here" and "we covered everything here" must not
    produce the same number -- treating them alike is how an unscanned application ends up
    looking thoroughly checked.
    """
    if planned <= 0:
        return 0.0
    return max(0.0, min(1.0, done / planned))


def _severity(finding: Mapping[str, Any]) -> str:
    value = str(finding.get("severity") or "info").strip().lower()
    return value if value in SEVERITY_WEIGHT else "info"


def assurance(
    coverage: Mapping[str, Any],
    *,
    smart_coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Score how much of the application was actually examined and proven.

    Reads only what the finalizer already computes. Every input here was previously
    calculated and then used for nothing but appending a star to the letter.
    """
    reliability = coverage.get("grade_reliability")
    reliability = reliability if isinstance(reliability, Mapping) else {}
    reasons = {str(item) for item in (reliability.get("reasons") or ())}

    families = [
        item for item in (coverage.get("family_coverage") or ())
        if isinstance(item, Mapping)
    ]
    selected = [item for item in families if item.get("selected")]
    complete = [
        item for item in selected
        if str(item.get("status") or item.get("coverage_status") or "") == "complete"
    ]

    planned = attempted = 0
    for item in (coverage.get("candidate_coverage") or {}).values():
        if isinstance(item, Mapping):
            planned += int(item.get("planned_candidates") or 0)
            attempted += int(item.get("attempted_candidates") or 0)

    contexts = (smart_coverage or {}).get("principal_contexts_exercised")
    auth_states = (smart_coverage or {}).get("auth_states_tested") or ()
    authenticated = bool(contexts) or len([
        state for state in auth_states if str(state) != "anonymous"
    ])

    # Proof escalation actually attempted, across every selected family.
    verifier_attempts = sum(
        int((item.get("proof_escalation") or {}).get("attempted_candidates") or 0)
        + int(item.get("verified_findings") or 0)
        for item in families
        if isinstance(item.get("proof_escalation"), Mapping)
        or item.get("verified_findings") is not None
    )
    planned_actions = int(coverage.get("planned_action_count") or 0)
    terminal_actions = int(coverage.get("terminal_action_count") or 0)
    if coverage.get("finalization_action_id") and planned_actions > terminal_actions:
        # Legacy reports counted finalize.report in the plan but never in terminal action
        # rows. It is report construction, not examination, so remove it from denominator.
        planned_actions -= 1
    capability_coverage = coverage.get("capability_coverage")
    capability_coverage = (
        capability_coverage if isinstance(capability_coverage, Mapping) else {}
    )
    capability_actions = [
        item for item in (capability_coverage.get("actions") or ())
        if isinstance(item, Mapping)
    ]
    required_actions = [item for item in capability_actions if item.get("required")]
    required_completed = [
        item for item in required_actions
        if str(item.get("status") or "").lower() in {"success", "succeeded", "completed"}
    ]
    plan_completion = _ratio(terminal_actions, planned_actions)

    # Nothing ran, so nothing was examined. Reporting this as anything but zero is the
    # failure this axis exists to prevent: a scan that never executed would otherwise
    # inherit full marks for every component that had no work to fall short of.
    if planned_actions <= 0 and not selected and planned <= 0:
        return {
            "score": 0,
            "band": "none",
            "components": {
                name: {"weight": weight, "value": 0.0}
                for name, weight in ASSURANCE_COMPONENTS
            },
            "gaps": ["no_examination_recorded"],
            "reasons": sorted(reasons),
        }

    values = {
        "required_actions_complete": (
            0.0 if "required_action_incomplete" in reasons
            else min(
                _ratio(len(required_completed), len(required_actions)),
                plan_completion,
            )
            if required_actions
            else plan_completion
        ),
        "selected_families_complete": _ratio(len(complete), len(selected)),
        "candidates_attempted": _ratio(attempted, planned),
        # Credit is for verification that actually ran. Awarding it whenever the
        # zero-attempt reason was absent gave a passive scan -- which planned no active
        # verifier at all -- full marks for work it never attempted, the same
        # earned-versus-defaulted mistake the ratios above avoid.
        "active_verification_attempted": (
            0.0 if "active_verifier_zero_attempts" in reasons
            else 1.0 if verifier_attempts > 0
            else 0.0
        ),
        "authenticated_coverage": 1.0 if authenticated else 0.0,
        # Availability has to be recorded by the finalizer. Absence of an error is not
        # evidence that an executable placement existed.
        "placement_available": (
            1.0
            if coverage.get("placement_executed") is True
            and "placement_unavailable" not in reasons
            else 0.0
        ),
        "examination_breadth": (
            _ratio(planned_actions, 8)
            + _ratio(len(selected), 2)
            + _ratio(planned, 20)
        ) / 3.0,
    }
    score = int(round(sum(
        weight * values[name] for name, weight in ASSURANCE_COMPONENTS
    )))
    # A cancelled or failed scan examined less than it planned to, whatever the components
    # say about the part that ran.
    if str(coverage.get("status") or "") in {"cancelled", "failed"}:
        score = min(score, 40)
    gaps = sorted(name for name, value in values.items() if value < 1.0)
    return {
        "score": score,
        "band": assurance_band(score),
        "components": {
            name: {"weight": weight, "value": round(values[name], 3)}
            for name, weight in ASSURANCE_COMPONENTS
        },
        "gaps": gaps,
        "reasons": sorted(reasons),
    }


def severity_notes(findings: Sequence[Mapping[str, Any]]) -> list[str]:
    """Human-readable notes about what was found, by severity.

    Lives with the scorer so the penalties quoted in the prose cannot drift from the ones
    the score was actually computed with -- they were separate literals before.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        severity = _severity(finding)
        counts[severity] = counts.get(severity, 0) + 1
    notes: list[str] = []
    if counts.get("critical"):
        worst = max(
            [float(item.get("cvss_score") or 0) for item in findings] or [0]
        )
        notes.append(
            f"{counts['critical']} critical vulnerability(ies) found "
            f"(max CVSS: {worst:g})."
        )
    for severity in ("high", "medium"):
        if counts.get(severity):
            notes.append(f"{counts[severity]} {severity} severity issue(s) found.")
    return notes


def stamp_terminal_assurance(report: dict[str, Any], *, status: str) -> int:
    """Write an explicit assurance projection onto one deterministic terminal report."""
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    coverage = {**coverage, "status": status}
    computed = assurance(
        coverage,
        smart_coverage=(
            report.get("smart_coverage")
            if isinstance(report.get("smart_coverage"), dict) else {}
        ),
    )
    result = report.setdefault("result", {})
    if not isinstance(result, dict):
        result = {}
        report["result"] = result
    result.update({
        "assurance_score": int(computed["score"]),
        "assurance_band": computed["band"],
        "assurance_components": computed["components"],
        "assurance_gaps": computed["gaps"],
    })
    return int(computed["score"])


def recompute_parallel_parent_assurance(
    merged: dict[str, Any], *, completed_count: int, total_count: int,
) -> int:
    """Score a merged execution record and cap missing shard evidence fail-closed."""
    coverage = merged.get("coverage") if isinstance(merged.get("coverage"), dict) else {}
    coverage = dict(coverage)
    if total_count > 0 and completed_count < total_count:
        coverage["status"] = "failed" if completed_count == 0 else "partial"
    computed = assurance(
        coverage,
        smart_coverage=(
            merged.get("smart_coverage")
            if isinstance(merged.get("smart_coverage"), dict) else {}
        ),
    )
    score = int(computed["score"])
    gaps = list(computed.get("gaps") or ())
    if total_count > 0 and completed_count < total_count:
        score = min(score, int(round(100 * completed_count / total_count)))
        if "parallel_shards_incomplete" not in gaps:
            gaps.append("parallel_shards_incomplete")
    result = merged.setdefault("result", {})
    if not isinstance(result, dict):
        result = {}
        merged["result"] = result
    result.update({
        "assurance_score": score,
        "assurance_band": assurance_band(score),
        "assurance_components": computed.get("components") or {},
        "assurance_gaps": sorted(gaps),
    })
    return score


def parallel_result_is_partial(result: dict[str, Any] | None) -> bool:
    """Whether one shard report is incomplete for parent assurance and reliability."""
    if not isinstance(result, dict):
        return True
    meta = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    if any(meta.get(key) is True for key in ("partial", "degraded", "timed_out", "cancelled")):
        return True
    result_block = result.get("result") if isinstance(result.get("result"), dict) else {}
    if result_block.get("grade_reliable") is False:
        return True
    coverage = result.get("smart_coverage") if isinstance(result.get("smart_coverage"), dict) else {}
    return str(coverage.get("status") or "").strip().lower() in {
        "partial", "incomplete", "failed", "timed_out", "cancelled",
    }


def score_scan(
    findings: Sequence[Mapping[str, Any]],
    coverage: Mapping[str, Any],
    *,
    smart_coverage: Mapping[str, Any] | None = None,
    posture: Mapping[str, Any] | None = None,
    grade_reliable: bool = True,
) -> dict[str, Any]:
    """Both axes plus the compatibility projection older readers still expect."""
    risk_result = risk(findings, posture=posture)
    assurance_result = assurance(coverage, smart_coverage=smart_coverage)
    grade = risk_result["grade"]
    return {
        "score_policy": SCORE_POLICY,
        "risk_score": risk_result["score"],
        "risk_grade": grade,
        "assurance_score": assurance_result["score"],
        "assurance_band": assurance_result["band"],
        "assurance_components": assurance_result["components"],
        "assurance_gaps": assurance_result["gaps"],
        "score_reasons": risk_result["reasons"],
        "posture_penalty": risk_result["posture_penalty"],
        "posture_penalties": risk_result["posture_penalties"],
        # Kept so existing readers, stored rows, and the device presentation keep working.
        # They are the risk axis; assurance has no equivalent in the old shape.
        "score": risk_result["score"],
        "grade": grade if grade_reliable else f"{grade}*",
        "grade_reliable": grade_reliable,
    }


def project_current_score_policy(report: dict[str, Any]) -> dict[str, Any]:
    """Preserve the score produced by the run and label its policy provenance.

    A historical report cannot be rescored faithfully when its findings predate explicit
    proof typing or when its producer was not deterministic DAST. API reads therefore never
    replace the stored grade. A future comparison can be exposed as a separate advisory
    artifact with an explicit subject contract; it must not masquerade as measured output.
    """
    result = report.get("result")
    if not isinstance(result, dict):
        return report
    stored_policy = str(result.get("score_policy") or "legacy/unknown")
    if stored_policy == SCORE_POLICY:
        return report

    stored = {
        "score_policy": stored_policy,
        "score": result.get("score"),
        "grade": result.get("grade"),
        "risk_score": result.get("risk_score"),
        "risk_grade": result.get("risk_grade"),
        "assurance_score": result.get("assurance_score"),
        "assurance_band": result.get("assurance_band"),
    }
    result["score_projection"] = {
        "recomputed_for_display": False,
        "display_policy": stored_policy,
        "stored": stored,
        "reason": "historical_policy_preserved",
    }
    return report


__all__ = [
    "ASSURANCE_BANDS",
    "ASSURANCE_COMPONENTS",
    "GRADE_BANDS",
    "HTTP_POSTURE_WEIGHT",
    "PROVEN_CEILING",
    "SCORE_POLICY",
    "SEVERITY_WEIGHT",
    "SUSPECTED_CEILING",
    "assurance",
    "assurance_band",
    "caps_risk_grade",
    "grade_for",
    "proof_weight",
    "project_current_score_policy",
    "risk",
    "score_scan",
    "stamp_terminal_assurance",
    "recompute_parallel_parent_assurance",
    "parallel_result_is_partial",
]
