"""Read-side continuity for retained leads; never infer proof from history."""
from __future__ import annotations

from typing import Any, Mapping, Sequence


def with_candidate_history(
    state: Mapping[str, Any], candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Keep historical associations separate from the latest attempt's assessment.

    Callers supply links read from the canonical store, not newly inferred candidates.
    A denial or an incomplete retry neither deletes an older lead nor reproduces it.
    """
    history = [dict(candidate) for candidate in candidates]
    history.sort(key=lambda candidate: candidate["created_from_attempt"])
    latest = (state.get("attempts") or [{}])[-1]
    candidate = history[-1] if history else None
    current = bool(candidate and candidate["created_from_attempt"] == latest.get("attempt"))
    resume = dict(state.get("resume") or {})
    resume.update(
        retained_candidate_ids=list(dict.fromkeys(item["id"] for item in history)),
        latest_authorization_assessment=state.get("authorization_assessment", "not_examined"),
        historical_lead_requires_review=bool(candidate and not current),
    )
    return {
        **state,
        "candidate": candidate,
        "candidate_history": history,
        "candidate_matches_latest_attempt": current,
        "candidate_relation": "current_attempt" if current else "historical_only" if candidate else "none",
        "resume": resume,
    }
