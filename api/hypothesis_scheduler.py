"""Pure, deterministic hypothesis scheduling (Wave 6).

No engine imports — the ranking is an explainable, stored score, host-testable in isolation. The
model from the plan doc:

    priority = impact + boundary_value + novelty + evidence_strength + reachability
               - request_cost - prior_failures - blocker_penalty

Every term is bounded and returned in a breakdown so the ordering is auditable. LLM hints may nudge
ordering within ``MAX_HINT_DELTA`` but can never move a terminal/blocked lead into scheduling or
override the deterministic gates — that clamp is enforced here, not trusted from the planner.
"""

from __future__ import annotations

from typing import Any

import hypothesis_lifecycle

SCHEDULER_VERSION = "hypothesis-scheduler-2026-07-12.v1"

_SEVERITY_IMPACT = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}

# Families whose bugs sit on an authorization / object / tenant boundary — the high-yield classes.
_HIGH_BOUNDARY_FAMILIES = frozenset(
    {"bola", "idor", "bfla", "mass_assignment", "auth_bypass", "authentication_bypass",
     "privilege_escalation", "tenant_isolation", "business_logic", "workflow"}
)
_INJECTION_FAMILIES = frozenset({"sqli", "xss", "ssrf", "rce", "xxe", "nosqli", "ssti", "lfi", "injection"})

# Evidence-strength rung -> score (mirrors adjudicate.EVIDENCE_STRENGTH_ORDER).
_STRENGTH_SCORE = {"claimed": 0.0, "signal": 1.0, "reproduced": 2.0, "cross_principal_verified": 3.0}

MAX_HINT_DELTA = 2.0


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _metadata(h: dict[str, Any]) -> dict[str, Any]:
    md = h.get("metadata_json")
    return md if isinstance(md, dict) else {}


def _next_action(h: dict[str, Any]) -> dict[str, Any]:
    na = h.get("next_test_action")
    return na if isinstance(na, dict) else {}


def score_hypothesis(h: dict[str, Any], *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Deterministic priority + explainable breakdown for one hypothesis.

    ``context`` may carry: ``completed_dimensions`` (iterable of dedupe keys already
    completed/refuted, for novelty), ``auth_available`` (bool), ``remaining_requests`` /
    ``remaining_seconds`` (budget), and ``hint_delta`` (a bounded LLM nudge). Never raises.
    """
    ctx = context or {}
    md = _metadata(h)
    na = _next_action(h)
    family = str(h.get("family") or "").strip().lower()
    status = str(h.get("effective_status") or h.get("status") or "").strip().lower()

    # Terminal or parked leads are excluded from scheduling regardless of any hint.
    if not hypothesis_lifecycle.is_actionable(status):
        return {"hypothesis_id": h.get("id"), "priority": None, "excluded": True,
                "exclude_reason": f"not_actionable:{status}", "breakdown": {}, "version": SCHEDULER_VERSION}

    impact = _SEVERITY_IMPACT.get(str(h.get("severity_guess") or "").strip().lower(), 2.0)

    boundary = 3.0 if family in _HIGH_BOUNDARY_FAMILIES else (2.0 if family in _INJECTION_FAMILIES else 1.0)
    if md.get("authenticated") or md.get("requires_auth"):
        boundary += 1.0
    if md.get("boundary") in {"role", "tenant", "money", "entitlement", "approval", "state_transition"}:
        boundary += 1.0

    completed = set(str(x) for x in (ctx.get("completed_dimensions") or []))
    dedupe = str(h.get("dedupe_key") or "")
    novelty = 0.0 if dedupe and dedupe in completed else 2.0

    strength_label = str(md.get("evidence_strength") or "").strip().lower()
    if strength_label in _STRENGTH_SCORE:
        evidence_strength = _STRENGTH_SCORE[strength_label]
    else:
        evidence_strength = round(min(1.0, max(0.0, _num(h.get("confidence")))) * 3.0, 2)

    # Reachability: if the family needs auth, it's only reachable when auth is available.
    needs_auth = bool(md.get("requires_auth") or family in {"bola", "idor", "bfla", "auth_bypass"})
    reachability = 2.0 if (not needs_auth or ctx.get("auth_available")) else 0.0

    request_cost = min(5.0, max(1.0, _num(na.get("request_cost") or md.get("request_cost") or 1, 1)))
    prior_failures = min(5.0, max(0.0, _num(md.get("prior_failures") or md.get("attempt_count") or 0)))
    blocker_penalty = 3.0 if md.get("blockers") else (2.0 if (needs_auth and not ctx.get("auth_available")) else 0.0)

    breakdown = {
        "impact": impact,
        "boundary_value": boundary,
        "novelty": novelty,
        "evidence_strength": evidence_strength,
        "reachability": reachability,
        "request_cost": request_cost,
        "prior_failures": prior_failures,
        "blocker_penalty": blocker_penalty,
    }
    base = (impact + boundary + novelty + evidence_strength + reachability
            - request_cost - prior_failures - blocker_penalty)

    hint = max(-MAX_HINT_DELTA, min(MAX_HINT_DELTA, _num(ctx.get("hint_delta"))))
    priority = round(base + hint, 4)
    return {
        "hypothesis_id": h.get("id"),
        "priority": priority,
        "excluded": False,
        "exclude_reason": None,
        "breakdown": {**breakdown, "hint_delta": hint},
        "request_cost": request_cost,
        "version": SCHEDULER_VERSION,
    }


def rank_hypotheses(hypotheses: list[dict[str, Any]], *, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Rank actionable hypotheses by priority, excluding terminal/blocked and cost-unaffordable leads.

    Cost-aware: a lead whose ``request_cost`` exceeds ``context.remaining_requests`` is deferred
    (kept, flagged) rather than scheduled. Deterministic tie-break by hypothesis_id.
    """
    ctx = context or {}
    remaining = ctx.get("remaining_requests")
    scored = [score_hypothesis(h, context=ctx) for h in (hypotheses or []) if isinstance(h, dict)]
    schedulable, excluded, deferred = [], [], []
    for s in scored:
        if s["excluded"]:
            excluded.append(s)
        elif remaining is not None and s["request_cost"] > _num(remaining, float("inf")):
            deferred.append({**s, "deferred_reason": "insufficient_request_budget"})
        else:
            schedulable.append(s)
    schedulable.sort(key=lambda s: (-s["priority"], str(s["hypothesis_id"])))
    return {
        "version": SCHEDULER_VERSION,
        "scheduled": schedulable,
        "deferred": deferred,
        "excluded": excluded,
        "counts": {"scheduled": len(schedulable), "deferred": len(deferred), "excluded": len(excluded)},
    }


def _self_test() -> None:
    hi = {"id": "a", "family": "bola", "severity_guess": "high", "confidence": 0.6,
          "dedupe_key": "d1", "status": "open",
          "metadata_json": {"authenticated": True, "evidence_strength": "reproduced"}}
    lo = {"id": "b", "family": "info_disclosure", "severity_guess": "low", "confidence": 0.1,
          "dedupe_key": "d2", "status": "open", "metadata_json": {}}
    terminal = {"id": "c", "family": "bola", "severity_guess": "critical", "status": "refuted",
                "dedupe_key": "d3", "metadata_json": {}}

    sh = score_hypothesis(hi, context={"auth_available": True})
    sl = score_hypothesis(lo, context={})
    assert sh["priority"] > sl["priority"], (sh["priority"], sl["priority"])
    assert score_hypothesis(terminal, context={})["excluded"] is True

    # needs-auth without auth -> reachability 0 + blocker penalty.
    no_auth = score_hypothesis(hi, context={"auth_available": False})
    assert no_auth["breakdown"]["reachability"] == 0.0 and no_auth["breakdown"]["blocker_penalty"] == 2.0
    assert no_auth["priority"] < sh["priority"]

    # novelty drops when the dimension was already completed.
    seen = score_hypothesis(hi, context={"auth_available": True, "completed_dimensions": ["d1"]})
    assert seen["breakdown"]["novelty"] == 0.0 and seen["priority"] < sh["priority"]

    # hint is clamped.
    huge = score_hypothesis(hi, context={"auth_available": True, "hint_delta": 999})
    assert huge["breakdown"]["hint_delta"] == MAX_HINT_DELTA

    ranked = rank_hypotheses([lo, hi, terminal], context={"auth_available": True})
    assert [s["hypothesis_id"] for s in ranked["scheduled"]] == ["a", "b"]
    assert ranked["counts"]["excluded"] == 1

    # cost-aware deferral.
    costly = {"id": "e", "family": "bola", "severity_guess": "high", "status": "open",
              "dedupe_key": "d4", "next_test_action": {"request_cost": 4}, "metadata_json": {}}
    r2 = rank_hypotheses([costly], context={"remaining_requests": 2, "auth_available": True})
    assert r2["counts"]["deferred"] == 1 and r2["counts"]["scheduled"] == 0

    print("hypothesis_scheduler self-test OK")


if __name__ == "__main__":
    _self_test()
