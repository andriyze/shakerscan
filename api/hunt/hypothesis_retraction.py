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

    Leads it created are withheld from Hunts and closed when no other source endorsed them (one an
    operator or another source also recorded stays open for them); its test records are removed
    from every lead; leads it held are released back to open. Proof-backed state is untouched.
    """
    writer = f"hunt:{hunt_id}"
    flag = json.dumps({"by": actor, "note": note, "hunt_id": str(hunt_id),
                       "at": datetime.now(timezone.utc).isoformat()})
    sole = ("NOT EXISTS (SELECT 1 FROM jsonb_array_elements(endorsements) e "
            "WHERE e->>'created_by' IS DISTINCT FROM $2)")
    owned = await conn.fetch(
        f"""UPDATE hypotheses SET metadata_json = jsonb_set(metadata_json, '{{hunt_withheld}}', $3::jsonb),
               status = CASE WHEN status IN {_LIVE} AND {sole} THEN 'dead' ELSE status END,
               terminal_reason = CASE WHEN status IN {_LIVE} AND {sole}
                                      THEN 'hunt_entries_retracted' ELSE terminal_reason END,
               claim_owner = CASE WHEN status IN {_LIVE} AND {sole} THEN NULL ELSE claim_owner END,
               claim_lease_expires_at = CASE WHEN status IN {_LIVE} AND {sole}
                                             THEN NULL ELSE claim_lease_expires_at END,
               version = version + 1, updated_at = NOW()
           WHERE target_asset_access_owner(target_id)=target_asset_access_owner($1) AND created_by = $2
           RETURNING id""",
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
    return {"withheld": len(owned), "released": len(released), "test_records_removed": len(scrubbed)}
