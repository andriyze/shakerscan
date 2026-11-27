#!/usr/bin/env python3
"""Offline, operator-held scoring of independent external-planner Hunt runs.

Consumes unmodified API exports, not planner claims. Never invokes a capability,
starts a Hunt, or sends the hidden oracle to a model. See docs/hunt-investigation-evaluation.md.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .hunt_review_metrics import score_review
else:
    from hunt_review_metrics import score_review


def signature(item):
    return str(item.get("cwe") or "").upper(), urlsplit(str(item.get("url") or item.get("path") or "")).path


def score_run(record, findings, oracle, *, investigations=None, review=None):
    if record.get("schema_version") != "hunt-record/v1":
        raise ValueError("Expected a canonical hunt-record/v1 export")
    hunt = record["hunt"]
    if str(hunt["hunt_id"]) != str(oracle["hunt_id"]) or str(hunt["target_id"]) != str(oracle["target_id"]):
        raise ValueError("Oracle and Hunt scope differ")
    if hunt["status"] not in {"completed", "cancelled", "failed", "budget_exhausted"}:
        raise ValueError("Score only terminal Hunt runs")
    actions = record["decision_trace"]
    linked = {
        str(finding_id)
        for action in actions if action["status"] in {"completed", "partial"}
        for finding_id in action.get("result", {}).get("reference_ids", {}).get("finding_ids", [])
    }
    baseline = set(oracle["baseline_fingerprints"])
    missing = linked - {str(item.get("id")) for item in findings}
    if missing:
        raise ValueError("Finding export omits action-linked finding IDs")
    promoted = {}
    rejected = 0
    for finding in findings:
        if str(finding.get("id")) not in linked:
            continue
        if (str(finding.get("target_id")) != str(oracle["target_id"])
                or finding.get("is_verified") is not True
                or finding.get("proof_state") != "verified"
                or not finding.get("fingerprint")):
            rejected += 1
            continue
        if finding["fingerprint"] not in baseline:
            promoted[finding["fingerprint"]] = finding
    expected = {signature(item) for item in oracle["expected"]}
    negatives = {signature(item) for item in oracle["negative_controls"]}
    if expected & negatives:
        raise ValueError("Expected vulnerabilities and negative controls overlap")
    found = {signature(item) for item in promoted.values()}
    matched, false_promotions = expected & found, negatives & found
    unexpected = found - expected - negatives
    measured, upper_bounds, complete_accounting = {}, {}, True
    for action in actions:
        if action["status"] in {"reserved", "running", "queued"}:
            complete_accounting = False
        accounting = action.get("result", {}).get("budget_accounting", {})
        if accounting.get("basis") != "exact_settlement":
            complete_accounting = False
            continue
        # A settled ledger entry does not establish that its charge was measured.
        # Older or incomplete exports must not silently become measured traffic.
        charge_basis = accounting.get("charge_basis")
        if charge_basis not in {"capability_reported_settlement", "conservative_full_reservation"}:
            complete_accounting = False
            continue
        destination = upper_bounds if charge_basis == "conservative_full_reservation" else measured
        if destination is upper_bounds:
            complete_accounting = False
        actual = accounting.get("actual")
        if not isinstance(actual, dict):
            complete_accounting = False
            continue
        for key, amount in actual.items():
            if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(amount) or amount < 0:
                raise ValueError("Invalid measured action budget")
            destination[key] = destination.get(key, 0) + amount
    action_by_id = {str(item["action_id"]): item for item in actions}
    linked_skills = set()
    for event in record.get("methodology_trace", []):
        action = action_by_id.get(str(event.get("action_id")), {})
        if event.get("event_type") in {"used", "completed"} and action.get("status") in {"completed", "partial"}:
            linked_skills.add((event["skill_id"], event.get("body_sha256")))
    return {
        "schema_version": "hunt-investigation-score/v1", "hunt_id": hunt["hunt_id"],
        "status": hunt["status"], "expected_classes": len(expected),
        "matched_classes": len(matched), "recall": len(matched) / len(expected) if expected else None,
        "negative_control_classes": len(negatives), "false_promotion_classes": len(false_promotions),
        "unexpected_classes_requiring_review": [list(item) for item in sorted(unexpected)],
        "new_verified_fingerprints": len(promoted), "rejected_linked_findings": rejected,
        "measured_action_budget": measured, "complete_exact_accounting": complete_accounting,
        "settled_upper_bound_budget": upper_bounds,
        "action_linked_skill_revisions": len(linked_skills),
        "methodology_compliance_proven": False,
        "operator_review": score_review(record, investigations, review),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--findings", type=Path, required=True, help="JSON array of authoritative /findings/{id} responses")
    parser.add_argument("--oracle", type=Path, required=True, help="Operator-only JSON; never send to the planner")
    parser.add_argument("--investigations", type=Path, help="Optional JSON array of saved authorization-investigation GET responses")
    parser.add_argument("--review", type=Path, help="Optional operator-recorded time and candidate-usefulness labels; never technical proof")
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(score_run(read(args.record), read(args.findings), read(args.oracle),
        investigations=read(args.investigations) if args.investigations else None,
        review=read(args.review) if args.review else None), indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
