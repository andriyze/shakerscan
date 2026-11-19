"""One ledger of intent: what a Hunt records elsewhere about a lead moves the lead.

A lead on the board (``hypotheses``) is the one place that says "this is worth testing here".
Two other records describe work on it:

* a coverage angle, when it names the lead (``hypothesis_id``): the angle's state moves the
  lead through the same claim and transition code a Hunt calls directly, so a planner records the
  angle once instead of the angle and the lead;
* a ``hypothesis_refuted`` interpretation, whose subject is the lead: it is recorded on the lead
  as a test that found against it, which lowers the lead's rank for every Hunt.

Neither is proof. A lead still becomes ``refuted`` only with a deterministic verification, and
``supported`` is still not a finding. A move the lifecycle refuses leaves the angle or the
interpretation recorded and is reported, never raised.
"""
from __future__ import annotations

import json
from typing import Any, Mapping
import uuid

from fastapi import HTTPException

from .hunt_hypotheses import _loads, _number, _owner, _target, claim, hunt_view, transition

#: What each coverage state means for the lead it names.
ANGLE_EFFECTS = {
    "planned": "hold",        # take or renew this Hunt's lease
    "testing": "test",        # hold, and move to testing when a falsifier is stated
    "partial": "test",
    "negative": "found_nothing",   # count a test that found nothing and hand the lead back
    "candidate": "support",   # the expected signal was observed
    "blocked": "release",     # this Hunt cannot go on; another may
}


async def _lead(conn: Any, run: Mapping[str, Any], lead_id: uuid.UUID) -> Mapping[str, Any] | None:
    return await conn.fetchrow(
        """SELECT * FROM hypotheses WHERE id=$1 AND target_id=$2 AND NOT (metadata_json ? 'hunt_withheld')
           FOR UPDATE""", lead_id, _target(run))


async def require_lead(conn: Any, run: Mapping[str, Any], lead_id: Any) -> uuid.UUID:
    """The lead a record names, on this Hunt's target and readable by it; ``ValueError`` otherwise."""
    try:
        identifier = uuid.UUID(str(lead_id))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("hypothesis_id must be a UUID") from None
    if await _lead(conn, run, identifier) is None:
        raise ValueError("hypothesis_id does not name a lead on this Hunt's target")
    return identifier


def _has_falsifier(view: Mapping[str, Any]) -> bool:
    return bool(view.get("has_falsifier"))


async def apply_angle(conn: Any, run: Mapping[str, Any], lead_id: uuid.UUID, angle: Mapping[str, Any]) -> dict[str, Any]:
    """Move the lead a coverage angle names as the angle's state says. Returns what happened."""
    owner = _owner(run)
    effect = ANGLE_EFFECTS[str(angle["status"])]
    steps: list[str] = []

    async def current() -> dict[str, Any]:
        return hunt_view(await _lead(conn, run, lead_id), owner=owner)

    async def move(values: dict[str, Any]) -> None:
        view = await current()
        await transition(conn, run, {"hypothesis_id": str(lead_id), "expected_version": view["version"], **values})
        steps.append(values["to"])

    try:
        async with conn.transaction():
            view = await current()
            if view["status"] in {"refuted", "promoted", "dead", "exhausted", "blocked"}:
                return {"hypothesis_id": str(lead_id), "moved": False, "status": view["status"],
                        "reason": "lead_is_closed"}
            holder = view["claim"]
            if holder["active"] and not holder["held_by_this_hunt"]:
                return {"hypothesis_id": str(lead_id), "moved": False, "status": view["status"],
                        "reason": "held_by_another"}
            if effect == "release":
                if holder["held_by_this_hunt"]:
                    await move({"to": "open", "reason_code": "released"})
                return {"hypothesis_id": str(lead_id), "moved": bool(steps), "steps": steps,
                        "status": (await current())["status"]}
            if not holder["held_by_this_hunt"] or view["status"] == "open":
                await claim(conn, run, {"hypothesis_id": str(lead_id), "expected_version": view["version"]})
                steps.append("claimed")
                view = await current()
            evidence = [str(ref) for ref in angle.get("evidence_action_ids") or []]
            # What this Hunt runs and what it expects, when the lead states none: the angle's own words.
            stated = {}
            if not _has_falsifier(view) and angle.get("mechanism") and angle.get("hypothesis"):
                stated = {"falsifier": str(angle["mechanism"])[:1000], "expected_signal": str(angle["hypothesis"])[:1000]}
            can_test = _has_falsifier(view) or bool(stated)
            if effect in {"test", "support"} and view["status"] == "claimed" and can_test:
                await move({"to": "testing", "reason_code": "testing_started", **stated})
                view = await current()
            if effect == "support":
                if view["status"] == "testing":
                    await move({"to": "supported", "reason_code": "expected_signal_observed", "evidence_refs": evidence})
                elif view["status"] != "supported":
                    return {"hypothesis_id": str(lead_id), "moved": bool(steps), "steps": steps,
                            "status": view["status"], "reason": "falsifier_required",
                            "note": "state what you ran and expected (mechanism and hypothesis) so the lead can "
                                    "enter testing before it is supported"}
            elif effect == "found_nothing" and view["status"] in {"claimed", "testing"}:
                await move({"to": "open", "reason_code": "expected_signal_absent", "evidence_refs": evidence})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, Mapping) else {}
        return {"hypothesis_id": str(lead_id), "moved": False, "reason": detail.get("reason_code") or "refused",
                "status": (await current())["status"]}
    return {"hypothesis_id": str(lead_id), "moved": bool(steps), "steps": steps, "status": (await current())["status"]}


async def count_refutation_claim(conn: Any, run: Mapping[str, Any], lead_id: uuid.UUID, interpretation_id: Any,
                                 evidence_refs: list[str]) -> dict[str, Any]:
    """Record a Hunt's ``hypothesis_refuted`` interpretation on the lead it names.

    It counts as a test that found against the lead (the scheduler ranks the lead lower), and names
    the interpretation, which carries the exact conditions. The lead's state and holder do not
    change: only a deterministic verification refutes a lead.
    """
    owner = _owner(run)
    row = await _lead(conn, run, lead_id)
    if row is None:
        return {"hypothesis_id": str(lead_id), "counted": False, "reason": "lead_not_found"}
    metadata = dict(_loads(row["metadata_json"], {}) or {})
    tests = dict(metadata.get("tests") or {}) if isinstance(metadata.get("tests"), dict) else {}
    mine = dict(tests.get(owner) or {}) if isinstance(tests.get(owner), dict) else {}
    claims = [str(item) for item in mine.get("refutation_claims") or []]
    if str(interpretation_id) not in claims:
        claims = (claims + [str(interpretation_id)])[-20:]
        mine["no_signal_count"] = min(99, int(_number(mine.get("no_signal_count"))) + 1)
    mine.update(hunt_run_id=str(run["id"]), refutation_claims=claims,
                evidence_refs=sorted(set(mine.get("evidence_refs") or []) | set(evidence_refs))[-50:])
    tests[owner] = mine
    await conn.execute(
        """UPDATE hypotheses SET metadata_json = jsonb_set(metadata_json, '{tests}', $2::jsonb, true),
                                 version = version + 1, updated_at = NOW() WHERE id=$1""",
        lead_id, json.dumps(tests))
    return {"hypothesis_id": str(lead_id), "counted": True, "status": row["status"],
            "note": "counted as a test against this lead; the lead is refuted only by a deterministic verification"}


__all__ = ["ANGLE_EFFECTS", "apply_angle", "count_refutation_claim", "require_lead"]
