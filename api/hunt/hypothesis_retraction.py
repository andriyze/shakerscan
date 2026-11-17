"""Withhold the hypothesis text one Hunt wrote when an operator retracts that Hunt's entries.

Kept apart from ``hunt_hypotheses`` (which reads interpretation helpers) so the interpretation
retraction can call it without an import cycle. Plain SQL over the ``hypotheses`` lead board.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

#: The states a retraction closes or releases. Proof-backed and already-terminal leads are untouched.
_LIVE = "('open','claimed','testing','supported','blocked','exhausted')"


async def retract_hunt_hypotheses(conn: Any, target_id: Any, hunt_id: Any, *, actor: str, note: str) -> dict[str, int]:
    """An operator retracted this Hunt's entries: withhold every hypothesis text it wrote on the target.

    A lead is its writer's words: the title, and also the family, dimensions and dedupe key it
    chose. So every lead this Hunt created is withheld from Hunts, and each one still live is closed
    and gives up its dedupe key, whoever else endorsed it. Another source that finds the same thing
    raises it again in its own words instead of inheriting a withheld row. Proof-backed and
    already-closed leads keep their state and key. The Hunt's test records are removed from every
    lead, and leads it held are released back to open.
    """
    writer = f"hunt:{hunt_id}"
    flag = json.dumps({"by": actor, "note": note, "hunt_id": str(hunt_id),
                       "at": datetime.now(timezone.utc).isoformat()})
    owned = await conn.fetch(
        f"""UPDATE hypotheses SET metadata_json = jsonb_set(metadata_json, '{{hunt_withheld}}', $3::jsonb),
               dedupe_key = CASE WHEN status IN {_LIVE} THEN dedupe_key || '|retracted:' || id::text
                                 ELSE dedupe_key END,
               terminal_reason = CASE WHEN status IN {_LIVE} THEN 'hunt_entries_retracted' ELSE terminal_reason END,
               claim_owner = CASE WHEN status IN {_LIVE} THEN NULL ELSE claim_owner END,
               claim_lease_expires_at = CASE WHEN status IN {_LIVE} THEN NULL ELSE claim_lease_expires_at END,
               status = CASE WHEN status IN {_LIVE} THEN 'dead' ELSE status END,
               version = version + 1, updated_at = NOW()
           WHERE target_asset_access_owner(target_id)=target_asset_access_owner($1) AND created_by = $2
             AND NOT (metadata_json ? 'hunt_withheld')
           RETURNING id, (terminal_reason = 'hunt_entries_retracted') AS closed""",
        target_id, writer, flag)
    released = await conn.fetch(
        """UPDATE hypotheses SET status = 'open', claim_owner = NULL, claim_lease_expires_at = NULL,
               metadata_json = metadata_json || jsonb_build_object('released_by_retraction', $3::jsonb),
               version = version + 1, updated_at = NOW()
           WHERE target_asset_access_owner(target_id)=target_asset_access_owner($1)
             AND claim_owner = $2 AND status IN ('claimed','testing','supported')
           RETURNING id""",
        target_id, writer, flag)
    scrubbed = await conn.fetch(
        """UPDATE hypotheses SET metadata_json = metadata_json #- ARRAY['tests', $2::text],
               version = version + 1, updated_at = NOW()
           WHERE target_asset_access_owner(target_id)=target_asset_access_owner($1)
             AND metadata_json->'tests' ? $2
           RETURNING id""",
        target_id, writer)
    return {"withheld": len(owned), "closed": sum(1 for row in owned if row["closed"]),
            "released": len(released), "test_records_removed": len(scrubbed)}
