"""Linking a completed finding retest to the Deep Hunt candidate it verifies."""

from __future__ import annotations

from typing import Any


async def find_retest_candidate(conn: Any, verification: Any) -> Any:
    """The Deep Hunt candidate a completed retest belongs to, by candidate id or finding id.

    The finding id is compared as text against JSON, so it is bound as text: the verification
    row carries a UUID, and asyncpg rejects a UUID for a text parameter. That rejection crashed
    every finding retest after its result was saved, so the candidate verdict, ASM campaign
    completion and the retest status update never ran.
    """
    finding_id = verification["finding_id"]
    return await conn.fetchrow(
        """SELECT id, verifier_contract_id
           FROM investigation_candidates
           WHERE plane='web' AND (
                 id=$2::uuid
                 OR verification_context->>'finding_id'=$1::text
           )
           ORDER BY last_seen_at DESC, id DESC LIMIT 1""",
        str(finding_id) if finding_id else None, verification.get("candidate_id"),
    )
