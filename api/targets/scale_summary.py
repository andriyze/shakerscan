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

``ensure_scale_indexes`` builds the read-path indexes with CREATE INDEX CONCURRENTLY after the
startup lock is released, so writes are never blocked while they build. One process builds (a
session advisory lock that others skip); an index left INVALID by an interrupted build is dropped
and rebuilt on the next start.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from typing import Any, AsyncIterator, Sequence

logger = logging.getLogger("shakerscan.api.targets.scale_summary")

SUMMARY_MIGRATION = "finding_scan_summary_counts_v1"
NIL_UUID = "00000000-0000-0000-0000-000000000000"
# (int, int) advisory keys do not collide with the single-bigint startup lock (8675309).
_LOCK_CLASS = 2110
_COMPACT_LOCK = 1
_INDEX_LOCK = 2
INDEX_LOCK_TIMEOUT = "10s"

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
DECLARE moved bigint := 0; scan_moved bigint := 0;
BEGIN
    IF NOT pg_try_advisory_xact_lock({_LOCK_CLASS}, {_COMPACT_LOCK}) THEN
        RETURN -1;
    END IF;
    WITH gone AS (DELETE FROM finding_summary_deltas RETURNING *),
         summed AS (
             SELECT target_id, status, severity, source, model_intake_tool, ai_target, sum(n)::bigint AS n
             FROM gone GROUP BY 1, 2, 3, 4, 5, 6)
    INSERT INTO finding_summary_counts AS c
    SELECT * FROM summed WHERE n <> 0
    ON CONFLICT (target_id, status, severity, source, model_intake_tool, ai_target)
    DO UPDATE SET n = c.n + EXCLUDED.n;
    GET DIAGNOSTICS moved = ROW_COUNT;
    IF moved > 0 THEN
        DELETE FROM finding_summary_counts WHERE n = 0;
    END IF;
    WITH gone AS (DELETE FROM scan_summary_deltas RETURNING *),
         summed AS (SELECT status, run_kind, shard, sum(n)::bigint AS n FROM gone GROUP BY 1, 2, 3)
    INSERT INTO scan_summary_counts AS c
    SELECT * FROM summed WHERE n <> 0
    ON CONFLICT (status, run_kind, shard) DO UPDATE SET n = c.n + EXCLUDED.n;
    GET DIAGNOSTICS scan_moved = ROW_COUNT;
    IF scan_moved > 0 THEN
        DELETE FROM scan_summary_counts WHERE n = 0;
    END IF;
    RETURN moved + scan_moved;
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


@asynccontextmanager
async def without_jit(conn: Any) -> AsyncIterator[Any]:
    """Run the enclosed reads with JIT compilation off.

    The planner prices correlated per-row subqueries high, which crosses the JIT thresholds: on
    the reference seed the inventory facet query spent 0.94 s of 1.17 s compiling and 0.18 s
    without JIT. A session setting rather than a transaction, so a failing optional read cannot
    abort the others; it is reset on exit (and the pool's RESET ALL on release resets it too).
    """
    await conn.execute("SET jit = off")
    try:
        yield conn
    finally:
        try:
            await conn.execute("RESET jit")
        except Exception:  # an aborted transaction: the pool resets the session on release
            pass


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


# --- Read-path indexes -------------------------------------------------------------------------

# (name, table, definition after "ON table"). Each is created CONCURRENTLY; a definition change
# needs a new name. ``trgm`` indexes need the pg_trgm extension and are skipped without it.
SCALE_INDEXES: tuple[tuple[str, str, str, bool], ...] = (
    # Keyset lists of targets and Hunts, newest first (list/v1 orders both columns one way).
    ("idx_targets_updated_id", "targets", "(updated_at DESC, id DESC)", False),
    ("idx_hunt_runs_updated_id", "hunt_runs", "(updated_at DESC, id DESC)", False),
    # The grouped Targets order (root domain, root first, then URL).
    ("idx_targets_root_domain_root_url", "targets", "(root_domain, is_root DESC, url)", False),
    # Scans of one target newest first; scans in a status newest first (dashboard, queue views).
    ("idx_scans_target_created", "scans", "(target_id, created_at DESC)", False),
    ("idx_scans_status_created", "scans", "(status, created_at DESC)", False),
    # Queued work and "is anything running on this asset" probes.
    ("idx_scans_pending_queued_created", "scans", "(created_at) WHERE status IN ('pending', 'queued')", False),
    ("idx_scans_active_target", "scans", "(target_id) WHERE status IN ('pending', 'queued', 'running')", False),
    # The dashboard's latest completed scan per URL (``latest_scans`` view) as an index-only scan.
    ("idx_scans_latest_completed_url", "scans",
     "(target_url, completed_at DESC) INCLUDE (score) WHERE status = 'completed' "
     "AND (scan_role IS NULL OR scan_role <> 'shard') "
     "AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')", False),
    # The latest ASM attempt per endpoint (coverage) without sorting every attempt.
    ("idx_asm_endpoint_attempts_latest", "asm_endpoint_attempts",
     "(endpoint_id, (COALESCE(completed_at, started_at)) DESC, started_at DESC)", False),
    # Paged application-graph edges.
    ("idx_app_graph_edges_target_type_id", "application_graph_edges", "(target_id, edge_type, id)", False),
    # Substring search (ILIKE '%term%').
    ("idx_targets_url_trgm", "targets", "USING gin (url gin_trgm_ops)", True),
    ("idx_targets_name_trgm", "targets", "USING gin (name gin_trgm_ops)", True),
    ("idx_targets_root_domain_trgm", "targets", "USING gin (root_domain gin_trgm_ops)", True),
    ("idx_scans_target_url_trgm", "scans", "USING gin (target_url gin_trgm_ops)", True),
    ("idx_hunt_runs_objective_trgm", "hunt_runs", "USING gin (objective gin_trgm_ops)", True),
)


async def ensure_scale_indexes(pool: Any, indexes: Sequence[tuple[str, str, str, bool]] = SCALE_INDEXES) -> dict[str, str]:
    """Create missing read-path indexes concurrently; returns ``{name: outcome}``.

    Runs outside any transaction (CONCURRENTLY requires it) and after the startup lock is
    released. One process builds; another that finds the build lock taken returns at once.
    """
    outcome: dict[str, str] = {}
    async with pool.acquire() as conn:
        in_transaction = getattr(conn, "is_in_transaction", None)
        if callable(in_transaction) and in_transaction():
            return {name: "skipped_in_transaction" for name, *_ in indexes}
        if not await conn.fetchval("SELECT pg_try_advisory_lock($1, $2)", _LOCK_CLASS, _INDEX_LOCK):
            return {name: "skipped_locked" for name, *_ in indexes}
        previous = await conn.fetchrow(
            "SELECT current_setting('statement_timeout') AS statement, current_setting('lock_timeout') AS lock"
        )
        deferred = False
        try:
            # The build itself may take long on a big table; waiting for another session's open
            # transaction may not: a concurrent build waits for every older snapshot, and an
            # idle-in-transaction session elsewhere must not hold a start for long. The first
            # such wait defers the remaining builds to the next start.
            await conn.execute(f"SET statement_timeout = 0; SET lock_timeout = '{INDEX_LOCK_TIMEOUT}'")
            trgm = await _ensure_trgm(conn)
            for name, table, definition, needs_trgm in indexes:
                if deferred:
                    outcome[name] = "deferred"
                    continue
                if needs_trgm and not trgm:
                    outcome[name] = "skipped_no_pg_trgm"
                    continue
                if not await conn.fetchval("SELECT to_regclass($1)", table):
                    outcome[name] = "skipped_no_table"
                    continue
                valid = await conn.fetchval(
                    """SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
                       JOIN pg_namespace n ON n.oid = c.relnamespace
                       WHERE c.relname = $1 AND n.nspname = current_schema()""",
                    name,
                )
                if valid:
                    outcome[name] = "present"
                    continue
                if valid is False:  # an interrupted concurrent build left it unusable
                    await conn.execute(f'DROP INDEX CONCURRENTLY IF EXISTS "{name}"')
                try:
                    await conn.execute(f'CREATE INDEX CONCURRENTLY IF NOT EXISTS "{name}" ON {table} {definition}')
                    outcome[name] = "created"
                except Exception as exc:
                    outcome[name] = f"failed: {type(exc).__name__}"
                    deferred = exc.__class__.__name__ == "LockNotAvailableError"
                    logger.warning("index %s was not built: %s: %s", name, type(exc).__name__, exc)
        finally:
            try:
                await conn.execute(
                    f"SET statement_timeout = '{_quote_setting(previous['statement'])}'; "
                    f"SET lock_timeout = '{_quote_setting(previous['lock'])}'"
                )
            finally:
                await conn.fetchval("SELECT pg_advisory_unlock($1, $2)", _LOCK_CLASS, _INDEX_LOCK)
    if any(value.startswith(("failed", "deferred")) for value in outcome.values()):
        logger.warning("read-path indexes incomplete, retried on the next start: %s", outcome)
    return outcome


def _quote_setting(value: Any) -> str:
    return str(value or "0").replace("'", "''")


async def _ensure_trgm(conn: Any) -> bool:
    if await conn.fetchval("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'"):
        return True
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        return True
    except Exception as exc:  # no privilege or no contrib package: search stays a sequential scan
        logger.warning("pg_trgm unavailable; substring-search indexes skipped: %s", exc)
        return False


__all__ = [
    "ACTIVE_FINDINGS_BY_TARGET_SQL",
    "FINDING_COUNTS_SQL",
    "FINDING_TOTALS_SQL",
    "NIL_UUID",
    "SCALE_INDEXES",
    "SCAN_TOTALS_SQL",
    "SUMMARY_MIGRATION",
    "compact",
    "compact_pool",
    "ensure_scale_indexes",
    "install_summary_counts",
    "without_jit",
]
