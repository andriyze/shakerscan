"""Offline operator review metrics, kept separate from technical proof and recall."""
from __future__ import annotations

import math


def score_review(record, investigations=None, review=None):
    hunt_id = str(record["hunt"]["hunt_id"])
    actions = {str(action["action_id"]): action for action in record["decision_trace"]}
    candidate_ids, proposals = set(), set()
    for investigation in investigations or []:
        if (investigation.get("schema_version") != "hunt-authorization/v1"
                or str(investigation.get("hunt_id")) != hunt_id):
            raise ValueError("Investigation export and Hunt scope differ")
        proposal = investigation.get("proposal_id")
        if not isinstance(proposal, str) or not proposal or proposal in proposals:
            raise ValueError("Missing or duplicate investigation export")
        proposals.add(proposal)
        attempts = {attempt["attempt"]: attempt for attempt in investigation.get("attempts", [])}
        history = investigation.get("candidate_history")
        if history is None:
            history = [investigation["candidate"]] if investigation.get("candidate") else []
        for candidate in history:
            attempt = attempts.get(candidate.get("created_from_attempt"), {})
            action = actions.get(str(attempt.get("action_id")), {})
            candidate_id = candidate.get("id")
            if not isinstance(candidate_id, str) or not candidate_id or action.get("status") not in {"completed", "partial"}:
                raise ValueError("Candidate history is not linked to an executed Hunt action")
            candidate_ids.add(candidate_id)
    result = {
        "available": review is not None,
        "source": "operator_recorded_not_technical_proof",
        "exported_investigations": len(proposals),
        "retained_candidates": len(candidate_ids),
        "human_minutes": None, "useful_leads": None, "not_useful_leads": None,
        "unreviewed_leads": len(candidate_ids), "reported_duplicate_experiments": None,
        "productivity_improvement_demonstrated": False,
    }
    if review is None:
        return result
    if str(review.get("hunt_id")) != hunt_id:
        raise ValueError("Operator review and Hunt scope differ")
    labels = []
    for key in ("useful_lead_ids", "not_useful_lead_ids"):
        values = review.get(key)
        if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
                or len(values) != len(set(values)) or set(values) - candidate_ids):
            raise ValueError("Review labels must name distinct exported candidate IDs")
        labels.append(set(values))
    useful, not_useful = labels
    if useful & not_useful:
        raise ValueError("A lead cannot have contradictory review labels")
    minutes = review.get("human_minutes")
    if minutes is not None and (isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or not math.isfinite(minutes) or minutes < 0):
        raise ValueError("Human time must be a finite nonnegative number or null")
    duplicates = review.get("duplicate_experiments")
    if duplicates is not None and (type(duplicates) is not int or not 0 <= duplicates <= len(actions)):
        raise ValueError("Duplicate experiment count must be bounded by the recorded actions")
    result.update(human_minutes=minutes, useful_leads=len(useful), not_useful_leads=len(not_useful),
                  unreviewed_leads=len(candidate_ids - useful - not_useful), reported_duplicate_experiments=duplicates)
    return result
