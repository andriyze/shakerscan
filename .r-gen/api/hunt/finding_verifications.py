"""Which Hunts verified a finding, and which one owns it (D21).

A finding names one owning Hunt in ``findings.hunt_run_id``: the first Hunt whose deterministic
verification produced or re-proved it. A later Hunt that verifies the same finding again does
not take it over. Its verification is appended to ``finding_hunt_verifications`` (the Hunt, the
action and the time), and that Hunt's outcome lists the finding too, so neither Hunt's verified
result disappears from its record.

Concurrent verifications are serialized on the finding row: the owner is read under
``SELECT ... FOR UPDATE`` and set only while the row has none, so two Hunts racing on one
finding cannot both become, or swap, its owner.

Deleting a Hunt never deletes a finding another Hunt verified; ownership passes to the earliest
remaining verifier (``api/data_lifecycle/records.py``).
"""
from __future__ import annotations

from typing import Any
import uuid

FINDING_HUNT_VERIFICATION_SCHEMA = "finding-hunt-verification/v1"
ROLE_OWNER = "owner"
ROLE_ADDITIONAL = "additional"

# Additive and idempotent: installed on every start by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS finding_hunt_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES hunt_actions(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner','additional')),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT finding_hunt_verifications_action_unique UNIQUE (finding_id, action_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_hunt_verifications_run
    ON finding_hunt_verifications(hunt_run_id, verified_at, id);
CREATE INDEX IF NOT EXISTS idx_finding_hunt_verifications_finding
    ON finding_hunt_verifications(finding_id, verified_at, id);
"""


def _uuid(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def record_hunt_verification(
    conn: Any, *, finding_id: Any, hunt_id: Any, action_id: Any,
) -> None:
    """Append this Hunt's verification of a finding whose row the caller's transaction holds.

    The role is read from the row in the same statement: ``owner`` when the finding names this
    Hunt, ``additional`` otherwise. A replay of the same action records nothing new.
    """
    await conn.execute(
        """INSERT INTO finding_hunt_verifications (finding_id, hunt_run_id, action_id, role)
           SELECT f.id, $2, $3,
                  CASE WHEN f.hunt_run_id IS NOT DISTINCT FROM $2 THEN 'owner' ELSE 'additional' END
           FROM findings f WHERE f.id=$1
           ON CONFLICT (finding_id, action_id) DO NOTHING""",
        _uuid(finding_id), _uuid(hunt_id), _uuid(action_id),
    )


async def attribute_verified_finding(
    conn: Any, *, run: Any, finding_id: Any, action_id: Any,
) -> dict[str, Any] | None:
    """Record a Hunt's verification of a finding; only an unowned finding gets this Hunt as owner.

    Runs in one transaction. ``None`` means the finding is not a verified finding of this Hunt's
    target, so nothing was recorded.
    """
    hunt = _uuid(run["id"])
    finding = _uuid(finding_id)
    async with conn.transaction():
        row = await conn.fetchrow(
            """SELECT id, hunt_run_id FROM findings
               WHERE id=$1 AND target_id=$2 AND last_verified_at IS NOT NULL
               FOR UPDATE""",
            finding, run["target_id"],
        )
        if row is None:
            return None
        owner = row["hunt_run_id"]
        if owner is None:
            owner = await conn.fetchval(
                """UPDATE findings SET hunt_run_id=$2, updated_at=NOW()
                   WHERE id=$1 AND hunt_run_id IS NULL
                   RETURNING hunt_run_id""",
                finding, hunt,
            )
        await record_hunt_verification(
            conn, finding_id=finding, hunt_id=hunt, action_id=action_id,
        )
    role = ROLE_OWNER if owner == hunt else ROLE_ADDITIONAL
    return {
        "schema_version": FINDING_HUNT_VERIFICATION_SCHEMA,
        "finding_id": str(finding),
        "owner_hunt_id": str(owner) if owner is not None else None,
        "role": role,
    }


# A Hunt's findings: the ones it owns and the ones it verified again after another Hunt.
HUNT_FINDINGS_QUERY = """
WITH hunt_findings AS (
    SELECT id FROM findings WHERE hunt_run_id=$1
    UNION
    SELECT finding_id FROM finding_hunt_verifications WHERE hunt_run_id=$1
)
SELECT id, COUNT(*) OVER() AS total_count FROM hunt_findings ORDER BY id LIMIT 500
"""


__all__ = [
    "FINDING_HUNT_VERIFICATIONS_SCHEMA_SQL",
    "FINDING_HUNT_VERIFICATION_SCHEMA",
    "HUNT_FINDINGS_QUERY",
    "ROLE_ADDITIONAL",
    "ROLE_OWNER",
    "attribute_verified_finding",
    "record_hunt_verification",
]
