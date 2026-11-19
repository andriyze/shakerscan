"""What a target's Hunts spent and what came of it, measured from server records.

For calibration done offline: which capabilities produce verified findings for the requests they
spend, and which lead sources end supported rather than refuted. Three sections:

* ``capabilities``: per capability, the settled actions of every Hunt on the target in the window,
  how they ended, the HTTP requests and tool seconds they settled, and the verified findings
  attributed to one of those actions (``finding_hunt_verifications``);
* ``leads``: per lead source and family on the lead board, how many leads stand in each state,
  and the share of settled ones that ended supported or promoted;
* ``derived``: the same for leads that record a lineage (``derived_from``), which is how far
  chaining went.

Everything is read from existing records. Nothing here changes a ranking weight, sends traffic,
decides or grants anything; a planner never reads it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import uuid

from .attempts import SETTLED_STATES
from .knowledge_dependencies import asset_scope
from .run_service import public_hunt_action

YIELD_SCHEMA = "hunt-yield/v1"
MAX_ACTIONS = 20_000
MAX_LEADS = 5_000
#: Lead states that are an answer, and the ones among them that say the lead held.
SETTLED_LEAD_STATES = frozenset({"supported", "promoted", "refuted", "exhausted", "dead"})
HELD_LEAD_STATES = frozenset({"supported", "promoted"})


def _rate(numerator: int, denominator: float) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _lead_summary(rows: list[Any]) -> dict[str, Any]:
    states: dict[str, int] = {}
    for row in rows:
        states[row["status"]] = states.get(row["status"], 0) + 1
    settled = sum(count for state, count in states.items() if state in SETTLED_LEAD_STATES)
    held = sum(count for state, count in states.items() if state in HELD_LEAD_STATES)
    return {"leads": len(rows), "by_state": dict(sorted(states.items())), "settled": settled,
            "held": held, "held_share_of_settled": _rate(held, settled)}


async def target_yield(conn: Any, target_id: Any, *, weeks: int = 8) -> dict[str, Any]:
    """Spend and outcomes on one target's asset over the last ``weeks`` weeks."""
    target = uuid.UUID(str(target_id))
    since = datetime.now(timezone.utc) - timedelta(weeks=weeks)
    scope = f"({asset_scope('h.target_id')} OR {asset_scope('h.device_target_id')})"
    actions = await conn.fetch(
        f"""SELECT a.id, a.hunt_run_id, a.capability_name, a.status, a.input_summary, a.result_summary,
                   a.receipt_id, a.started_at, a.completed_at
            FROM hunt_actions a JOIN hunt_runs h ON h.id = a.hunt_run_id
            WHERE {scope} AND a.status = ANY($2::text[]) AND COALESCE(a.completed_at, a.started_at) >= $3
            ORDER BY a.completed_at DESC NULLS LAST, a.id LIMIT {MAX_ACTIONS + 1}""",
        target, list(SETTLED_STATES), since)
    verified = await conn.fetch(
        f"""SELECT v.action_id, v.finding_id FROM finding_hunt_verifications v
            JOIN hunt_runs h ON h.id = v.hunt_run_id
            WHERE {scope} AND v.verified_at >= $2""", target, since)
    findings_by_action: dict[str, set[str]] = {}
    for row in verified:
        findings_by_action.setdefault(str(row["action_id"]), set()).add(str(row["finding_id"]))

    capabilities: dict[str, dict[str, Any]] = {}
    for row in actions[:MAX_ACTIONS]:
        item = capabilities.setdefault(row["capability_name"], {
            "capability": row["capability_name"], "actions": 0, "outcomes": {}, "http_requests": 0,
            "tool_wall_seconds": 0, "_findings": set(), "_hunts": set()})
        item["actions"] += 1
        item["outcomes"][row["status"]] = item["outcomes"].get(row["status"], 0) + 1
        # The settled charge as the action view reports it: measured when the settlement was exact.
        consumed = (public_hunt_action(row).get("result") or {}).get("budget_consumed") or {}
        item["http_requests"] += int(consumed.get("http_requests") or 0)
        item["tool_wall_seconds"] += int(consumed.get("tool_wall_seconds") or 0)
        item["_findings"] |= findings_by_action.get(str(row["id"]), set())
        item["_hunts"].add(str(row["hunt_run_id"]))
    capability_rows = []
    for item in capabilities.values():
        found = len(item.pop("_findings"))
        hunts = len(item.pop("_hunts"))
        capability_rows.append({
            **item, "outcomes": dict(sorted(item["outcomes"].items())), "hunts": hunts, "verified_findings": found,
            "verified_per_1000_requests": _rate(found * 1000, item["http_requests"]),
            "verified_per_tool_hour": _rate(found * 3600, item["tool_wall_seconds"]),
        })
    capability_rows.sort(key=lambda row: (-row["verified_findings"], -row["actions"], row["capability"]))

    leads = await conn.fetch(
        f"""SELECT source, family, status, (metadata_json ? 'derived_from'
                   AND jsonb_array_length(metadata_json->'derived_from') > 0) AS derived
            FROM hypotheses WHERE target_id=$1 AND updated_at >= $2
              AND NOT (metadata_json ? 'hunt_withheld')
            ORDER BY updated_at DESC, id LIMIT {MAX_LEADS + 1}""", target, since)
    leads = list(leads[:MAX_LEADS])
    groups: dict[tuple[str, str], list[Any]] = {}
    for row in leads:
        groups.setdefault((row["source"], row["family"]), []).append(row)
    lead_rows = [{"source": source, "family": family, **_lead_summary(rows)}
                 for (source, family), rows in sorted(groups.items())]
    return {
        "schema_version": YIELD_SCHEMA, "target_id": str(target), "weeks": weeks, "since": since.isoformat(),
        "capabilities": capability_rows, "actions_read": min(len(actions), MAX_ACTIONS),
        "actions_truncated": len(actions) > MAX_ACTIONS,
        "leads": lead_rows, "leads_truncated": len(leads) >= MAX_LEADS,
        "derived": _lead_summary([row for row in leads if row["derived"]]),
        "note": ("Measured from the action ledger, verification attributions and the lead board. Use it to "
                 "compare runs offline; it changes no ranking and is not shown to planners."),
    }


__all__ = ["YIELD_SCHEMA", "target_yield"]
