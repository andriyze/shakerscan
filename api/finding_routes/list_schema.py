"""Schema behind the bounded findings lists (2.11): a stored severity rank and the list indexes.

``findings.severity_rank`` orders severity with an index: critical 5, high 4, medium 3, low 2, and 1
for info or anything else (the order the list's ``CASE severity`` used to compute per row, with the
direction flipped so "most severe, then most recently seen" is one descending keyset). A BEFORE
INSERT/UPDATE trigger keeps it in step with ``severity``, so no writer has to know about it. The
column is ``NOT NULL DEFAULT 1``: a load that bypasses the trigger (a data-only restore of an older
dump, ``--disable-triggers``, a replica) still succeeds, and ``repair_severity_rank`` corrects such
rows after the API starts serving.

Three places install it:

* ``FINDINGS_LIST_SCHEMA_STATEMENTS`` run inside the startup schema transaction. They are cheap and
  idempotent: the rank function, the column (a constant default is metadata only, no rewrite), the
  trigger, the planner statistics and the timestamp trigger's backfill switch.
* ``finish_findings_list_schema`` runs after that transaction, under the startup lock, once
  (marker-gated): it ranks the existing rows in short id-keyset batches, each its own
  transaction, never moving ``updated_at``. It builds no index: CREATE INDEX CONCURRENTLY waits for
  every open snapshot, and a process waiting for the startup lock holds one (a deadlock).
* ``FINDINGS_SCALE_INDEXES`` are built by the one background builder
  (``runtime/loop_scale_indexes.py``) after the API serves, CONCURRENTLY and try-locked; an
  interrupted build is dropped and rebuilt. db/init.sql carries the same column, function, trigger
  and statistics, and leaves the indexes to that builder too.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_RANK_MIGRATION = "2.11.0_findings_severity_rank"
BACKFILL_SETTING = "shakerscan.findings_backfill"
BACKFILL_BATCH = 5000

#: The sort expressions an index serves; the list specs use these exact texts.
EPOCH = "'1970-01-01 00:00:00+00'::timestamptz"
LAST_SEEN_SORT_SQL = f"COALESCE(f.last_seen_at, {EPOCH})"
FIRST_SEEN_SORT_SQL = f"COALESCE(f.first_seen_at, {EPOCH})"

SEVERITY_RANK_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION finding_severity_rank(severity TEXT) RETURNS SMALLINT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT (CASE severity
        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2
        ELSE 1 END)::smallint
$$"""

SEVERITY_RANK_TRIGGER_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION set_finding_severity_rank() RETURNS TRIGGER AS $$
BEGIN
    NEW.severity_rank := finding_severity_rank(NEW.severity);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql"""

# The existing BEFORE UPDATE trigger stamps updated_at on every update. A backfill is not an
# update anyone made, so it sets this transaction-local switch and the stamp is left alone.
FINDING_TIMESTAMPS_FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION update_finding_timestamps()
RETURNS TRIGGER AS $$
BEGIN
    IF current_setting('{BACKFILL_SETTING}', true) = 'on' THEN
        RETURN NEW;
    END IF;
    NEW.updated_at = NOW();
    IF NEW.status = 'resolved' AND OLD.status != 'resolved' THEN
        NEW.resolved_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql"""

SEVERITY_RANK_TRIGGER_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = 'findings'::regclass AND tgname = 'trg_finding_severity_rank'
    ) THEN
        CREATE TRIGGER trg_finding_severity_rank
        BEFORE INSERT OR UPDATE OF severity, severity_rank ON findings
        FOR EACH ROW EXECUTE FUNCTION set_finding_severity_rank();
    END IF;
END $$"""

FINDINGS_LIST_SCHEMA_STATEMENTS: tuple[str, ...] = (
    SEVERITY_RANK_FUNCTION_SQL,
    SEVERITY_RANK_TRIGGER_FUNCTION_SQL,
    FINDING_TIMESTAMPS_FUNCTION_SQL,
    # Checked first: ALTER TABLE takes an exclusive lock even when the column already exists.
    # A constant default is stored in the catalog: adding the column rewrites nothing.
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_attribute
            WHERE attrelid = 'findings'::regclass AND attname = 'severity_rank' AND NOT attisdropped
        ) THEN
            ALTER TABLE findings ADD COLUMN severity_rank SMALLINT NOT NULL DEFAULT 1;
        END IF;
    END $$""",
    SEVERITY_RANK_TRIGGER_SQL,
)

# The index predicate must be the very expression the queries add (proof_sql.verified_candidate_sql).
try:
    from .proof_sql import scan_time_proof_gate_sql, verified_candidate_sql
except ImportError:  # pragma: no cover - loaded as a top-level module
    from finding_routes.proof_sql import scan_time_proof_gate_sql, verified_candidate_sql
PROOF_CANDIDATE_PREDICATE = verified_candidate_sql(evidence="evidence", verdict="last_verification_verdict")
# Planner statistics for the evidence half of that predicate. Without them a JSON test is guessed
# at 50% and a verified filter walks the whole list index instead of the (normally tiny) partial
# index above.
PROOF_GATE_STATISTICS_SQL = (
    "CREATE STATISTICS IF NOT EXISTS findings_proof_gate_stats ON ("
    + scan_time_proof_gate_sql("evidence") + ") FROM findings"
)
# Checked first: CREATE STATISTICS takes a lock on findings even when the object exists, and that
# lock waits behind the background builder's CREATE INDEX CONCURRENTLY on findings.
FINDINGS_LIST_SCHEMA_STATEMENTS += (f"""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_statistic_ext WHERE stxname = 'findings_proof_gate_stats') THEN
            {PROOF_GATE_STATISTICS_SQL};
        END IF;
    END $$""",)

#: (name, definition after ``ON``), built by runtime/loop_scale_indexes.py.
FINDINGS_LIST_INDEXES: tuple[tuple[str, str], ...] = (
    # Keyset for the default list order: severity, then last seen, then id.
    ("idx_findings_severity_keyset", f"findings (severity_rank, (COALESCE(last_seen_at, {EPOCH})), id)"),
    ("idx_findings_last_seen_keyset", f"findings ((COALESCE(last_seen_at, {EPOCH})), id)"),
    ("idx_findings_first_seen_keyset", f"findings ((COALESCE(first_seen_at, {EPOCH})), id)"),
    # Per-asset active counts (exposure, inventory, dashboard).
    # Covering: severity and needs-verification counts read the index alone.
    ("idx_findings_active_target_counts",
     "findings (target_id, severity) INCLUDE (last_verification_verdict, analyst_verdict)"
     " WHERE status = 'active'"),
    ("idx_findings_active_ai_target_counts",
     "findings (ai_target_id, severity) INCLUDE (target_id, last_verification_verdict, analyst_verdict)"
     " WHERE status = 'active' AND ai_target_id IS NOT NULL"),
    ("idx_findings_target_created", "findings (target_id, created_at DESC)"),
    ("idx_findings_scan_severity", "findings (scan_id, severity)"),
    ("idx_findings_resolved_at", "findings (resolved_at DESC) WHERE status = 'resolved'"),
    # Rows that could be proven (proof_sql.verified_candidate_sql): the verified filter and the
    # per-asset verified counts read these instead of projecting proof on every row.
    ("idx_findings_proof_candidates", f"findings (target_id) WHERE {PROOF_CANDIDATE_PREDICATE}"),
    # The few rows whose proof the SQL projection cannot decide (proof_sql.triage_string_sql).
    ("idx_findings_triage_string", "findings (id) WHERE jsonb_typeof(evidence -> 'triage') = 'string'"),
)

#: Trigram indexes for the list's ILIKE search; skipped (with a warning) without pg_trgm.
FINDINGS_TRGM_INDEXES: tuple[tuple[str, str], ...] = (
    ("idx_findings_title_trgm", "findings USING gin (title gin_trgm_ops)"),
    ("idx_findings_url_trgm", "findings USING gin (url gin_trgm_ops)"),
)


#: What the background builder (runtime/loop_scale_indexes.py) builds: (name, table, definition);
#: the trigram ones only when pg_trgm is available.
FINDINGS_SCALE_INDEXES: tuple[tuple[str, str, str], ...] = tuple(
    (name, "findings", definition) for name, definition in (*FINDINGS_LIST_INDEXES, *FINDINGS_TRGM_INDEXES)
)


async def _migration_applied(conn: Any, name: str) -> bool:
    return bool(await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name = $1)", name,
    ))


async def backfill_severity_rank(conn: Any, *, batch: int = BACKFILL_BATCH) -> int:
    """Correct every row whose ``severity_rank`` is not its severity's, ``batch`` rows per
    transaction, in one pass over the primary key.

    Rows written meanwhile are ranked by the trigger, so one pass is enough. Each batch commits on
    its own (no long lock, resumable) and leaves ``updated_at`` as it was.
    """
    updated = 0
    last_id = None
    while True:
        ids = await conn.fetch(
            "SELECT id FROM findings WHERE ($1::uuid IS NULL OR id > $1::uuid)"
            " AND severity_rank IS DISTINCT FROM finding_severity_rank(severity)"
            " ORDER BY id LIMIT $2",
            last_id, batch,
        )
        if not ids:
            break
        last_id = ids[-1]["id"]
        async with conn.transaction():
            await conn.execute(f"SET LOCAL {BACKFILL_SETTING} = 'on'")
            status = await conn.execute(
                "UPDATE findings SET severity_rank = finding_severity_rank(severity)"
                " WHERE id = ANY($1::uuid[]) AND severity_rank IS DISTINCT FROM finding_severity_rank(severity)",
                [row["id"] for row in ids],
            )
        updated += int(str(status).rsplit(" ", 1)[-1] or 0)
        if len(ids) < batch:
            break
    return updated


async def finish_findings_list_schema(conn: Any) -> None:
    """The one-time rank of existing rows, under the startup lock. No index work here."""
    if await _migration_applied(conn, SEVERITY_RANK_MIGRATION):
        return
    filled = await backfill_severity_rank(conn)
    if filled:
        logger.info("findings.severity_rank backfilled for %d findings", filled)
    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
        SEVERITY_RANK_MIGRATION,
    )


_REPAIR_LOCK = (0x53534C50, 0x2B11_F1D)  # loop_leader's namespace, this repair's key


async def repair_severity_rank(pool: Any) -> int:
    """Rank rows a trigger-less load left at the default; try-locked, one pass, never fatal."""
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT pg_try_advisory_lock($1::int, $2::int)", *_REPAIR_LOCK):
            return 0
        try:
            repaired = await backfill_severity_rank(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1::int, $2::int)", *_REPAIR_LOCK)
    if repaired:
        logger.warning("findings.severity_rank repaired for %d findings", repaired)
    return repaired


async def repair_severity_rank_in_background(pool: Any, *, delay: float = 15.0) -> None:
    """The API lifespan's maintenance task: after serving starts; a failure is logged only."""
    import asyncio

    await asyncio.sleep(delay)
    try:
        await repair_severity_rank(pool)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # a rank repair never stops the API
        logger.warning("findings.severity_rank repair skipped: %s", type(exc).__name__)


__all__ = [
    "BACKFILL_SETTING",
    "FINDINGS_LIST_INDEXES",
    "FINDINGS_LIST_SCHEMA_STATEMENTS",
    "FINDINGS_SCALE_INDEXES",
    "FINDINGS_TRGM_INDEXES",
    "FIRST_SEEN_SORT_SQL",
    "LAST_SEEN_SORT_SQL",
    "SEVERITY_RANK_MIGRATION",
    "backfill_severity_rank",
    "finish_findings_list_schema",
    "repair_severity_rank",
    "repair_severity_rank_in_background",
]
