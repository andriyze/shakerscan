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
    from ai_verdict_policy import (
        has_deterministic_exploit_proof,
        is_trusted_ai_false_positive,
    )
    from score_bands import GRADE_BANDS, grade_for
except ModuleNotFoundError:  # package import layout
    from scanner.ai_verdict_policy import (
        has_deterministic_exploit_proof,
        is_trusted_ai_false_positive,
    )
    from scanner.score_bands import GRADE_BANDS, grade_for


SCORE_POLICY = "risk_and_assurance/v3"

SEVERITY_WEIGHT: Mapping[str, int] = {
    "critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0,
}
# Deterministic baseline posture is evidence too. These deductions intentionally cover
# application-layer headers that are meaningful on both public and local targets. Public
# delivery controls such as HSTS, certificate health, DNSSEC, and mail policy require target
# context and remain outside this narrow table until that context is part of the finalizer.
HTTP_POSTURE_WEIGHT: Mapping[str, int] = {
    "content-security-policy": 12,
    "x-frame-options": 4,
    "x-content-type-options": 4,
    "referrer-policy": 2,
}
# The best risk score that may stand once a *proven* finding of this severity exists. One
# proven critical is an F however few findings there are; one proven high cannot exceed C.
# Low and informational have no ceiling: a single low-severity issue is not a reason to fail
# an application, though it still costs weight.
PROVEN_CEILING: Mapping[str, int] = {"critical": 40, "high": 70, "medium": 85}
# A finding that is only suspected caps one band softer. It is evidence worth acting on, but
# grading an application as if an unproven claim were confirmed is how a scanner loses the
# reader's trust in every grade it emits.
SUSPECTED_CEILING: Mapping[str, int] = {"critical": 70, "high": 85}

ASSURANCE_BANDS: tuple[tuple[int, str], ...] = (
    (85, "strong"), (70, "adequate"), (50, "limited"), (1, "weak"), (0, "none"),
)


def assurance_band(score: int) -> str:
    for threshold, band in ASSURANCE_BANDS:
        if score >= threshold:
            return band
    return "none"


def _has_deterministic_proof(item: Mapping[str, Any]) -> bool:
    """Whether a finding carries proof strong enough to be treated as demonstrated.

    ``has_deterministic_exploit_proof`` was written against the legacy scanner's findings,
    where a bare ``verified=True`` could come from a coarse heuristic and is deliberately
    not trusted on its own. The V2 finalizer is different: it stamps ``verified`` together
    with ``proof_state="verified"`` only on paths that already satisfied a deterministic
    proof contract. Reading only the legacy helper graded a browser-proven XSS as merely
    suspected, which is the opposite of the problem severity ceilings were added to fix.
    """
    if has_deterministic_exploit_proof(dict(item)):
        return True
    return (
        item.get("verified") is True
        and str(item.get("proof_state") or "") == "verified"
    )


def proof_weight(finding: Mapping[str, Any]) -> float:
    """How much of a finding's severity weight counts against the risk score."""
    item = dict(finding)
    if is_trusted_ai_false_positive(item):
        return 0.0
    if _has_deterministic_proof(item):
        return 1.0
    if item.get("suspected") or item.get("needs_verification"):
        return 0.25
    try:
        confidence = float(item.get("confidence"))
    except (TypeError, ValueError):
        confidence = 0.6
    if confidence < 0.5:
        return 0.25
    if confidence < 0.65:
        return 0.5
    if confidence < 0.8:
        return 0.75
    return 1.0


def caps_risk_grade(finding: Mapping[str, Any]) -> bool:
    """Whether this finding's severity is proven well enough to cap the grade."""
    item = dict(finding)
    if is_trusted_ai_false_positive(item):
        return False
    if _has_deterministic_proof(item):
        return True
    if item.get("suspected") or item.get("needs_verification"):
        return False
    validation = item.get("validation")
    validation = validation if isinstance(validation, Mapping) else {}
    try:
        confidence = float(item.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return (
        confidence >= 0.80
        or str(validation.get("evidence_level") or "").lower() == "strong_indicator"
    )


def _severity(finding: Mapping[str, Any]) -> str:
    name = str(finding.get("severity") or "info").strip().lower()
    return name if name in SEVERITY_WEIGHT else "info"


def risk(
    findings: Sequence[Mapping[str, Any]],
    *,
    posture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Score observed finding risk plus deterministic application posture weaknesses."""
    penalty = 0.0
    ceiling = 100
    proven: dict[str, int] = {}
    suspected: dict[str, int] = {}
    for finding in findings:
        severity = _severity(finding)
        weight = proof_weight(finding)
        penalty += SEVERITY_WEIGHT[severity] * weight
        if weight <= 0.0:
            # A trusted false positive contributes nothing and caps nothing.
            continue
        if caps_risk_grade(finding):
            proven[severity] = proven.get(severity, 0) + 1
            ceiling = min(ceiling, PROVEN_CEILING.get(severity, 100))
        else:
            suspected[severity] = suspected.get(severity, 0) + 1
            ceiling = min(ceiling, SUSPECTED_CEILING.get(severity, 100))
    http = (posture or {}).get("http")
    http = http if isinstance(http, Mapping) else {}
    missing_headers = {
        str(header).strip().lower()
        for header in (http.get("missing_security_headers") or ())
        if str(header).strip()
    }
    posture_penalties = {
        header: points
        for header, points in HTTP_POSTURE_WEIGHT.items()
        if header in missing_headers
    }
    posture_penalty = sum(posture_penalties.values())
    penalty += posture_penalty

    score = min(max(0, 100 - int(round(penalty))), ceiling)
    reasons: list[str] = []
    for severity in ("critical", "high", "medium"):
        if proven.get(severity):
            reasons.append(f"proven_{severity}:{proven[severity]}")
        if suspected.get(severity):
            reasons.append(f"suspected_{severity}:{suspected[severity]}")
    reasons.extend(
        f"posture_missing_{header}:{points}"
        for header, points in posture_penalties.items()
    )
    return {
        "score": score,
        "grade": grade_for(score),
        "reasons": reasons,
        "proven_counts": proven,
        "suspected_counts": suspected,
        "posture_penalty": posture_penalty,
        "posture_penalties": posture_penalties,
    }


# What assurance is made of, and what each part is worth. The weights say which gaps most
# undermine confidence in a clean result: work that was planned and never ran matters more
# than the breadth of identities exercised.
ASSURANCE_COMPONENTS: tuple[tuple[str, int], ...] = (
    ("required_actions_complete", 25),
    ("selected_families_complete", 25),
    ("candidates_attempted", 20),
    ("active_verification_attempted", 15),
    ("authenticated_coverage", 10),
    ("placement_available", 5),
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
            else _ratio(len(required_completed), len(required_actions))
            if required_actions
            else _ratio(terminal_actions, planned_actions)
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
        "placement_available": 0.0 if "placement_unavailable" in reasons else 1.0,
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
    "risk",
    "score_scan",
]
