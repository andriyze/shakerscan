"""Discovery runs do not grade the application.

A discovery run (the attack-surface discovery pass of a target, or the discovery step of a
parallel Scan) maps hosts and endpoints with active testing off. It is stored as a scan row
with a score and a grade of its own, and the Scans list hides it by default. It must not
decide what a target shows as its latest result: the target's grade, score, last-scanned
time and Scan count come from application Scans only, and so do the dashboard's latest
results. Findings a discovery run records still count: the target's active-finding count is
refreshed when one completes.

``update_target_stats`` (the trigger function on ``scans``) is defined here and, with the same
text, in db/init.sql. The startup migration (api/targets/asset_migration.py) installs it on
every start and repairs, once, targets whose stored latest result came from a discovery run.
"""
from __future__ import annotations

from typing import Any

#: ``scans.scan_role`` of a discovery run (asm_inventory.ASM_RECON_ROLE,
#: parallel_scan.PARALLEL_DISCOVERY_ROLE; a test keeps the three in step).
DISCOVERY_SCAN_ROLES = ("asm_recon", "parallel_discovery")

_ROLE_LIST = ", ".join(f"'{role}'" for role in DISCOVERY_SCAN_ROLES)

TARGET_HEADLINE_MIGRATION = "target_headline_from_application_scans_v1"


def not_discovery_run_sql(alias: str = "") -> str:
    """A predicate: the scan row is not a discovery run. ``alias`` is the table alias, if any."""
    column = f"{alias}.scan_role" if alias else "scan_role"
    return f"COALESCE({column}, '') NOT IN ({_ROLE_LIST})"


TARGET_STATS_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION update_target_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed'
       AND NEW.target_id IS NOT NULL
       AND COALESCE(NEW.scan_role, 'standalone') <> 'shard' THEN
        IF COALESCE(NEW.scan_role, 'standalone') IN ({_ROLE_LIST}) THEN
            -- A discovery run maps the target; it does not grade the application.
            UPDATE targets SET
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = NEW.target_id AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = NEW.target_id;
        ELSE
            UPDATE targets SET
                last_scan_id = NEW.id,
                last_scanned_at = NEW.completed_at,
                last_score = NEW.score,
                last_grade = NEW.grade,
                last_assurance_score = NEW.assurance_score,
                total_scans = total_scans + 1,
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = NEW.target_id AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = NEW.target_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

# Targets whose stored latest result is a discovery run get the latest completed application
# Scan back (or no result when there is none).
TARGET_HEADLINE_REPAIR_SQL = f"""
UPDATE targets t SET
    last_scan_id = app.id,
    last_scanned_at = app.completed_at,
    last_score = app.score,
    last_grade = app.grade,
    last_assurance_score = app.assurance_score
FROM scans discovery
LEFT JOIN LATERAL (
    SELECT s.id, s.completed_at, s.score, s.grade, s.assurance_score
    FROM scans s
    WHERE s.target_id = discovery.target_id AND s.status = 'completed'
      AND COALESCE(s.scan_role, 'standalone') <> 'shard'
      AND {not_discovery_run_sql("s")}
    ORDER BY s.completed_at DESC NULLS LAST
    LIMIT 1
) app ON true
WHERE discovery.id = t.last_scan_id AND discovery.scan_role IN ({_ROLE_LIST})
"""

# Completed discovery runs were counted as Scans of their target.
TARGET_SCAN_COUNT_REPAIR_SQL = f"""
UPDATE targets t SET total_scans = GREATEST(COALESCE(t.total_scans, 0) - counted.n, 0)
FROM (
    SELECT target_id, count(*) AS n FROM scans
    WHERE status = 'completed' AND target_id IS NOT NULL AND scan_role IN ({_ROLE_LIST})
    GROUP BY target_id
) counted
WHERE counted.target_id = t.id
"""


async def install_target_headline(conn: Any) -> None:
    """Install the trigger function; repair stored target results once. Runs at startup."""
    await conn.execute(TARGET_STATS_FUNCTION_SQL)
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", TARGET_HEADLINE_MIGRATION):
        return
    await conn.execute(TARGET_HEADLINE_REPAIR_SQL)
    await conn.execute(TARGET_SCAN_COUNT_REPAIR_SQL)
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", TARGET_HEADLINE_MIGRATION)


__all__ = [
    "DISCOVERY_SCAN_ROLES",
    "TARGET_HEADLINE_MIGRATION",
    "TARGET_HEADLINE_REPAIR_SQL",
    "TARGET_SCAN_COUNT_REPAIR_SQL",
    "TARGET_STATS_FUNCTION_SQL",
    "install_target_headline",
    "not_discovery_run_sql",
]
