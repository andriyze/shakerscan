"""Trigger-maintained finding and scan counts, and the read-path indexes for targets and scans.

The dashboard, the Targets inventory (``sort=risk`` and facets) and the grouped Targets view
need counts over every finding or scan. Counting the tables per request was the 2.10 outage
class, so the counts are kept current by triggers instead:

* ``finding_summary_counts`` / ``scan_summary_counts`` hold compacted counts per bucket (a
  finding bucket is its target, status, severity, source, Model Intake tool flag and AI target
  flag; a scan bucket is its status, run kind and shard flag).
* Triggers on ``findings`` and ``scans`` only ever INSERT signed delta rows into
  ``*_summary_deltas``. No writer updates a shared counter row, so concurrent scans and workers
  never wait on each other or deadlock on the summary.
* ``summary_compact()`` folds the deltas into the counts in one transaction (one compactor at a
  time, by a transaction advisory lock; a busy compactor is skipped, never waited for). Readers
  add the counts and any not-yet-compacted deltas, so a read is exact whether or not compaction
  has run.

Exactness: the backfill and the triggers are installed in the same startup transaction, under the
trigger's table lock, so no write falls between them. TRUNCATE resets the summary. A pg_dump
restore loads the summary rows with the data and creates the triggers afterwards (post-data), so a
restored database is consistent too. NULL status/source are stored as '' (every reader predicate
treats NULL and '' alike) and findings without a target as the nil UUID.

The read-path indexes these readers use are built by the one background index builder
(``runtime/loop_scale_indexes.py``), concurrently, once the API serves.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("shakerscan.api.targets.scale_summary")

SUMMARY_MIGRATION = "finding_scan_summary_counts_v1"
NIL_UUID = "00000000-0000-0000-0000-000000000000"
# (int, int) advisory keys do not collide with the single-bigint startup lock (8675309).
_LOCK_CLASS = 2110
_COMPACT_LOCK = 1

FINDING_KEY = ("target_id", "status", "severity", "source", "model_intake_tool", "ai_target")
SCAN_KEY = ("status", "run_kind", "shard")

SUMMARY_SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS finding_summary_counts (
    target_id UUID NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    model_intake_tool BOOLEAN NOT NULL,
    ai_target BOOLEAN NOT NULL,
    n BIGINT NOT NULL,
    PRIMARY KEY (target_id, status, severity, source, model_intake_tool, ai_target)
);
CREATE TABLE IF NOT EXISTS finding_summary_deltas (
    id BIGSERIAL PRIMARY KEY,
    target_id UUID NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    model_intake_tool BOOLEAN NOT NULL,
    ai_target BOOLEAN NOT NULL,
    n BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_summary_counts (
    status TEXT NOT NULL,
    run_kind TEXT NOT NULL,
    shard BOOLEAN NOT NULL,
    n BIGINT NOT NULL,
    PRIMARY KEY (status, run_kind, shard)
);
CREATE TABLE IF NOT EXISTS scan_summary_deltas (
    id BIGSERIAL PRIMARY KEY,
    status TEXT NOT NULL,
    run_kind TEXT NOT NULL,
    shard BOOLEAN NOT NULL,
    n BIGINT NOT NULL
);

-- The Targets inventory's domain group of each asset locator (Public Suffix List, computed in
-- Python): a pure function of the locator and the bundled list, filled on first read.
CREATE TABLE IF NOT EXISTS target_inventory_groups (
    locator TEXT PRIMARY KEY,
    group_domain TEXT NOT NULL,
    psl_version TEXT NOT NULL
);
-- Each target URL's host class (asset_cohorts.target_exposure_class, computed in Python): a pure
-- function of the URL, filled on first read, so cohort filters run in SQL (target_cohort_sql.py).
CREATE TABLE IF NOT EXISTS target_url_classes (
    url_hash TEXT PRIMARY KEY,
    exposure_class TEXT NOT NULL,
    classifier_version TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION finding_summary_insert_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_summary_deltas(target_id, status, severity, source, model_intake_tool, ai_target, n)
    SELECT COALESCE(r.target_id, '{NIL_UUID}'::uuid), COALESCE(r.status, ''), COALESCE(r.severity, ''),
           COALESCE(r.source, ''), COALESCE(r.tool = 'model_intake', false), r.ai_target_id IS NOT NULL,
           CASE WHEN TG_OP = 'DELETE' THEN -count(*) ELSE count(*) END
    FROM changed_rows r
    GROUP BY 1, 2, 3, 4, 5, 6;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION finding_summary_update_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_summary_deltas(target_id, status, severity, source, model_intake_tool, ai_target, n)
    VALUES (COALESCE(OLD.target_id, '{NIL_UUID}'::uuid), COALESCE(OLD.status, ''), COALESCE(OLD.severity, ''),
            COALESCE(OLD.source, ''), COALESCE(OLD.tool = 'model_intake', false), OLD.ai_target_id IS NOT NULL, -1),
           (COALESCE(NEW.target_id, '{NIL_UUID}'::uuid), COALESCE(NEW.status, ''), COALESCE(NEW.severity, ''),
            COALESCE(NEW.source, ''), COALESCE(NEW.tool = 'model_intake', false), NEW.ai_target_id IS NOT NULL, 1);
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION scan_summary_insert_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO scan_summary_deltas(status, run_kind, shard, n)
    SELECT COALESCE(r.status, ''), COALESCE(r.run_kind, ''), COALESCE(r.scan_role = 'shard', false),
           CASE WHEN TG_OP = 'DELETE' THEN -count(*) ELSE count(*) END
    FROM changed_rows r
    GROUP BY 1, 2, 3;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION scan_summary_update_row() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO scan_summary_deltas(status, run_kind, shard, n)
    VALUES (COALESCE(OLD.status, ''), COALESCE(OLD.run_kind, ''), COALESCE(OLD.scan_role = 'shard', false), -1),
           (COALESCE(NEW.status, ''), COALESCE(NEW.run_kind, ''), COALESCE(NEW.scan_role = 'shard', false), 1);
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION summary_reset_on_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'findings' THEN
        DELETE FROM finding_summary_deltas;
        DELETE FROM finding_summary_counts;
    ELSE
        DELETE FROM scan_summary_deltas;
        DELETE FROM scan_summary_counts;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION summary_compact() RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE folded bigint := 0; scan_folded bigint := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock({_LOCK_CLASS}, {_COMPACT_LOCK}) THEN
        RETURN -1;
    END IF;
    -- Returns the number of delta rows folded (both tables).
    WITH gone AS (DELETE FROM finding_summary_deltas RETURNING *),
         summed AS (
             SELECT target_id, status, severity, source, model_intake_tool, ai_target, sum(n)::bigint AS n
             FROM gone GROUP BY 1, 2, 3, 4, 5, 6),
         merged AS (
             INSERT INTO finding_summary_counts AS c
             SELECT * FROM summed WHERE n <> 0
             ON CONFLICT (target_id, status, severity, source, model_intake_tool, ai_target)
             DO UPDATE SET n = c.n + EXCLUDED.n
             RETURNING 1)
    SELECT count(*) INTO folded FROM gone;
    IF folded > 0 THEN
        DELETE FROM finding_summary_counts WHERE n = 0;
    END IF;
    WITH gone AS (DELETE FROM scan_summary_deltas RETURNING *),
         summed AS (SELECT status, run_kind, shard, sum(n)::bigint AS n FROM gone GROUP BY 1, 2, 3),
         merged AS (
             INSERT INTO scan_summary_counts AS c
             SELECT * FROM summed WHERE n <> 0
             ON CONFLICT (status, run_kind, shard) DO UPDATE SET n = c.n + EXCLUDED.n
             RETURNING 1)
    SELECT count(*) INTO scan_folded FROM gone;
    IF scan_folded > 0 THEN
        DELETE FROM scan_summary_counts WHERE n = 0;
    END IF;
    RETURN folded + scan_folded;
END $$;
"""

# Statement triggers aggregate a bulk insert or a cascade delete into one delta row per bucket;
# the update trigger fires only when a bucket column changes (the common last_seen_at refresh
# does not reach PL/pgSQL at all).
_TRIGGERS = (
    ("findings", "finding_summary_insert", """CREATE TRIGGER finding_summary_insert AFTER INSERT ON findings
        REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION finding_summary_insert_rows()"""),
    ("findings", "finding_summary_delete", """CREATE TRIGGER finding_summary_delete AFTER DELETE ON findings
        REFERENCING OLD TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION finding_summary_insert_rows()"""),
    ("findings", "finding_summary_update", """CREATE TRIGGER finding_summary_update AFTER UPDATE ON findings
        FOR EACH ROW WHEN (OLD.target_id IS DISTINCT FROM NEW.target_id OR OLD.status IS DISTINCT FROM NEW.status
            OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.source IS DISTINCT FROM NEW.source
            OR OLD.tool IS DISTINCT FROM NEW.tool
            OR (OLD.ai_target_id IS NULL) IS DISTINCT FROM (NEW.ai_target_id IS NULL))
        EXECUTE FUNCTION finding_summary_update_row()"""),
    ("findings", "finding_summary_truncate", """CREATE TRIGGER finding_summary_truncate AFTER TRUNCATE ON findings
        FOR EACH STATEMENT EXECUTE FUNCTION summary_reset_on_truncate()"""),
    ("scans", "scan_summary_insert", """CREATE TRIGGER scan_summary_insert AFTER INSERT ON scans
        REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION scan_summary_insert_rows()"""),
    ("scans", "scan_summary_delete", """CREATE TRIGGER scan_summary_delete AFTER DELETE ON scans
        REFERENCING OLD TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION scan_summary_insert_rows()"""),
    ("scans", "scan_summary_update", """CREATE TRIGGER scan_summary_update AFTER UPDATE ON scans
        FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.run_kind IS DISTINCT FROM NEW.run_kind
            OR OLD.scan_role IS DISTINCT FROM NEW.scan_role)
        EXECUTE FUNCTION scan_summary_update_row()"""),
    ("scans", "scan_summary_truncate", """CREATE TRIGGER scan_summary_truncate AFTER TRUNCATE ON scans
        FOR EACH STATEMENT EXECUTE FUNCTION summary_reset_on_truncate()"""),
)

_BACKFILL_SQL = (
    "DELETE FROM finding_summary_deltas",
    "DELETE FROM finding_summary_counts",
    f"""INSERT INTO finding_summary_counts(target_id, status, severity, source, model_intake_tool, ai_target, n)
        SELECT COALESCE(target_id, '{NIL_UUID}'::uuid), COALESCE(status, ''), COALESCE(severity, ''),
               COALESCE(source, ''), COALESCE(tool = 'model_intake', false), ai_target_id IS NOT NULL, count(*)
        FROM findings GROUP BY 1, 2, 3, 4, 5, 6""",
    "DELETE FROM scan_summary_deltas",
    "DELETE FROM scan_summary_counts",
    """INSERT INTO scan_summary_counts(status, run_kind, shard, n)
        SELECT COALESCE(status, ''), COALESCE(run_kind, ''), COALESCE(scan_role = 'shard', false), count(*)
        FROM scans GROUP BY 1, 2, 3""",
)


async def install_summary_counts(conn: Any) -> None:
    """Install the summary tables and triggers; backfill once. Runs inside the startup transaction.

    A trigger is created only when missing, so a restart takes no table lock. On the first run the
    backfill happens after the triggers exist and while their CREATE TRIGGER lock still blocks
    writers, so the counts start exact.
    """
    await conn.execute(SUMMARY_SCHEMA_SQL)
    existing = {
        row["tgname"] for row in await conn.fetch(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN ('findings'::regclass, 'scans'::regclass)"
        )
    }
    for _table, name, ddl in _TRIGGERS:
        if name not in existing:
            await conn.execute(ddl)
    if await conn.fetchval("SELECT 1 FROM app_schema_migrations WHERE name=$1", SUMMARY_MIGRATION):
        return
    await conn.execute("LOCK TABLE findings, scans IN SHARE ROW EXCLUSIVE MODE")
    await conn.execute("SET LOCAL statement_timeout = 0")
    for statement in _BACKFILL_SQL:
        await conn.execute(statement)
    await conn.execute("INSERT INTO app_schema_migrations(name) VALUES($1)", SUMMARY_MIGRATION)


async def compact(conn: Any) -> int:
    """Fold pending deltas into the counts; -1 when another compactor holds the lock.

    Best effort: a reader that cannot write (or races a schema change) still reads exact counts.
    """
    try:
        async with conn.transaction():
            return int(await conn.fetchval("SELECT summary_compact()") or 0)
    except Exception as exc:  # pragma: no cover - logged, never fails a read
        logger.warning("summary compaction skipped: %s: %s", type(exc).__name__, exc)
        return 0


async def compact_pool(pool: Any) -> int:
    async with pool.acquire() as conn:
        return await compact(conn)


def _env_seconds(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except ValueError:
        return default


SUMMARY_COMPACT_INTERVAL_SECONDS = _env_seconds("SUMMARY_COMPACT_INTERVAL_SECONDS", 60.0)
SUMMARY_COMPACT_TICK_TIMEOUT = 600.0
# Statistics stay current after a large fold (cheap: the counts tables are small).
ANALYZE_AFTER_FOLDED_ROWS = 50_000


#: More upkeep the compactor's tick runs after folding, each ``hook(pool)``, registered by its own
#: module (the exposure facts warm-up, ``exposure/asset_rank.py``) so this module imports none.
TICK_HOOKS: list[Any] = []


async def compact_tick(pool: Any) -> int:
    """One compaction: fold every pending delta; ANALYZE the counts after a large fold. Then the
    registered ``TICK_HOOKS`` (a failing hook never fails the compaction)."""
    async with pool.acquire() as conn:
        folded = await compact(conn)
        if folded >= ANALYZE_AFTER_FOLDED_ROWS:
            await conn.execute("ANALYZE finding_summary_counts, scan_summary_counts, "
                               "finding_summary_deltas, scan_summary_deltas")
    for hook in list(TICK_HOOKS):
        try:
            await hook(pool)
        except Exception as exc:  # the next tick (or a read) retries
            logger.warning("summary tick upkeep %s skipped: %s", getattr(hook, "__name__", hook),
                           type(exc).__name__)
    return folded


async def summary_compactor(pool: Any) -> None:
    """The API's led loop: one process folds the summary deltas every interval, so they stay few
    whether or not anyone opens the dashboard (whose computation also folds them)."""
    try:
        from loop_leader import run_led_loop
    except ModuleNotFoundError:
        from ..loop_leader import run_led_loop
    if SUMMARY_COMPACT_INTERVAL_SECONDS <= 0:
        return
    await run_led_loop(pool, "summary_compactor", lambda: compact_tick(pool),
                       interval=SUMMARY_COMPACT_INTERVAL_SECONDS, timeout=SUMMARY_COMPACT_TICK_TIMEOUT)


# Exact current counts per bucket: compacted counts plus pending deltas.
FINDING_COUNTS_SQL = """(
    SELECT target_id, status, severity, source, model_intake_tool, ai_target, sum(n)::bigint AS n
    FROM (SELECT target_id, status, severity, source, model_intake_tool, ai_target, n FROM finding_summary_counts
          UNION ALL
          SELECT target_id, status, severity, source, model_intake_tool, ai_target, n FROM finding_summary_deltas) parts
    GROUP BY 1, 2, 3, 4, 5, 6 HAVING sum(n) <> 0)"""

# The same, without the target dimension (dashboard totals).
FINDING_TOTALS_SQL = """(
    SELECT status, severity, source, model_intake_tool, ai_target, sum(n)::bigint AS n
    FROM (SELECT status, severity, source, model_intake_tool, ai_target, n FROM finding_summary_counts
          UNION ALL
          SELECT status, severity, source, model_intake_tool, ai_target, n FROM finding_summary_deltas) parts
    GROUP BY 1, 2, 3, 4, 5 HAVING sum(n) <> 0)"""

# Active findings per target with the inventory's risk weight.
ACTIVE_FINDINGS_BY_TARGET_SQL = """(
    SELECT target_id,
           sum(n)::bigint AS active,
           (sum(n) FILTER (WHERE severity IN ('critical', 'high')))::bigint AS critical_high,
           sum(n * CASE severity WHEN 'critical' THEN 1000 WHEN 'high' THEN 100
                                 WHEN 'medium' THEN 10 WHEN 'low' THEN 1 ELSE 0 END)::bigint AS risk
    FROM (SELECT target_id, severity, n FROM finding_summary_counts WHERE status = 'active'
          UNION ALL
          SELECT target_id, severity, n FROM finding_summary_deltas WHERE status = 'active') parts
    GROUP BY target_id HAVING sum(n) <> 0)"""

SCAN_TOTALS_SQL = """(
    SELECT status, run_kind, shard, sum(n)::bigint AS n
    FROM (SELECT status, run_kind, shard, n FROM scan_summary_counts
          UNION ALL
          SELECT status, run_kind, shard, n FROM scan_summary_deltas) parts
    GROUP BY 1, 2, 3 HAVING sum(n) <> 0)"""


__all__ = [
    "ACTIVE_FINDINGS_BY_TARGET_SQL",
    "FINDING_COUNTS_SQL",
    "FINDING_TOTALS_SQL",
    "NIL_UUID",
    "SCAN_TOTALS_SQL",
    "SUMMARY_MIGRATION",
    "compact",
    "compact_pool",
    "compact_tick",
    "summary_compactor",
    "install_summary_counts",
]
