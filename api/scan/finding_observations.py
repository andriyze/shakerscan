"""Which findings each Scan observed (``finding_scan_observations``).

A finding is one row per target and fingerprint. ``findings.scan_id`` names the Scan that saw it
last and ``first_seen_scan_id`` the one that saw it first, so a later run that sees a finding
again takes it away from every earlier Scan's own list: the earlier Scan's stored count and
report still include it, while its list and its severity links no longer do.

This relation keeps one row per Scan and finding. A trigger writes it whenever a finding is
saved with a ``scan_id`` (insert, or an update that sets the column), so no writer has to
remember it. A Scan's findings (``GET /findings?scan_id=``, the Scan detail, the release gate's
report-row links) are read through it, so a Scan keeps showing everything it observed however
many later runs see the same findings.

Deleting a Scan or a finding deletes its observations (cascading foreign keys). Deleting the
Scan that saw a finding last still deletes the finding itself, as before.
"""
from __future__ import annotations

from typing import Any

OBSERVATIONS_MIGRATION = "finding_scan_observations_v1"

# Additive and idempotent: installed on every start by the unified startup migration
# (api/targets/asset_migration.py) and, with the same definition, by db/init.sql.
FINDING_SCAN_OBSERVATIONS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS finding_scan_observations (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_scan_observations_finding
    ON finding_scan_observations(finding_id);
CREATE OR REPLACE FUNCTION record_finding_scan_observation() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.scan_id IS NOT NULL THEN
        INSERT INTO finding_scan_observations (scan_id, finding_id)
        VALUES (NEW.scan_id, NEW.id)
        ON CONFLICT (scan_id, finding_id) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
"""

OBSERVATION_TRIGGER = "trg_record_finding_scan_observation"
OBSERVATION_TRIGGER_SQL = f"""
CREATE TRIGGER {OBSERVATION_TRIGGER}
AFTER INSERT OR UPDATE OF scan_id ON findings
FOR EACH ROW EXECUTE FUNCTION record_finding_scan_observation();
"""

# What the three scan columns of existing findings still say: the Scan that saw each finding
# last and the one that saw it first. Scans in between left no record and cannot be restored.
OBSERVATION_BACKFILL_SQL = """
INSERT INTO finding_scan_observations (scan_id, finding_id, observed_at)
SELECT seen.scan_id, seen.finding_id, min(seen.observed_at)
FROM (
    SELECT scan_id, id AS finding_id, COALESCE(last_seen_at, NOW()) AS observed_at
    FROM findings WHERE scan_id IS NOT NULL
    UNION ALL
    SELECT last_seen_scan_id, id, COALESCE(last_seen_at, NOW())
    FROM findings WHERE last_seen_scan_id IS NOT NULL
    UNION ALL
    SELECT first_seen_scan_id, id, COALESCE(first_seen_at, NOW())
    FROM findings WHERE first_seen_scan_id IS NOT NULL
) seen
GROUP BY seen.scan_id, seen.finding_id
ON CONFLICT (scan_id, finding_id) DO NOTHING
"""


def observed_by_scan_sql(finding_id: str, scan_param: str) -> str:
    """A predicate: the finding named by ``finding_id`` was observed by the Scan ``scan_param``."""
    return (f"{finding_id} IN (SELECT fso.finding_id FROM finding_scan_observations fso "
            f"WHERE fso.scan_id = {scan_param})")


async def install_finding_scan_observations(conn: Any) -> None:
    """Install the relation and its trigger; backfill once. Runs inside the startup transaction.

    The trigger is created only when missing, so a restart takes no table lock. On the first run
    the backfill happens after the trigger exists and while its CREATE TRIGGER lock still blocks
    writers, so no observation is missed between the two.
    """
    await conn.execute(FINDING_SCAN_OBSERVATIONS_SCHEMA_SQL)
    has_trigger = await conn.fetchval(
        "SELECT 1 FROM pg_trigger WHERE tgrelid = 'findings'::regclass AND tgname = $1 "
        "AND NOT tgisinternal", OBSERVATION_TRIGGER)
    if not has_trigger:
        await conn.execute(OBSERVATION_TRIGGER_SQL)
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", OBSERVATIONS_MIGRATION):
        return
    await conn.execute(OBSERVATION_BACKFILL_SQL)
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", OBSERVATIONS_MIGRATION)


__all__ = [
    "FINDING_SCAN_OBSERVATIONS_SCHEMA_SQL",
    "OBSERVATION_BACKFILL_SQL",
    "OBSERVATION_TRIGGER",
    "OBSERVATION_TRIGGER_SQL",
    "OBSERVATIONS_MIGRATION",
    "install_finding_scan_observations",
    "observed_by_scan_sql",
]
