"""The assessment fields of ``scans.result`` as real columns (2.11).

List reads and the operational metrics needed four values buried in each Scan's report JSON:
``result.result.risk_assessment_state``, ``result.result.application_observed`` and
``result.coverage.grade_reliability.{reliable, reasons}``. Reading them decompressed the whole
report of every row the read touched (a page of the Scans list, every Scan for the metrics).
They are now columns on ``scans``:

* ``risk_assessment_state`` text, ``application_observed`` boolean (a JSON boolean only),
  ``grade_reliable`` boolean (the text ``true``/``false`` at that path, as the metrics compared
  it), ``grade_reliability_reasons`` text[] (the array's elements as text; empty otherwise);
* ``assessment_projected``: true once the four columns hold the projection of the row's current
  ``result``. NULL means "not projected yet" and every reader falls back to the JSON for that row
  (``assessment_sql``), so a read is the same before, during and after the backfill.

A BEFORE INSERT / UPDATE OF result trigger keeps the columns in step with ``result``, so no writer
has to know about them. Rows written before 2.11 are projected after the API serves, by
``project_scan_assessment_in_background``: try-locked, id-keyset batches each in its own short
transaction, resumable, and without moving ``scans.updated_at`` (``BACKFILL_SETTING``), so the
backfill never shows up as a change in ``/scans?since=``. A load that bypasses the trigger (a
data-only restore with triggers disabled) leaves ``assessment_projected`` as it was in the dump or
NULL; the next start's pass projects any NULL row again.

``install_scan_assessment_columns`` runs in the startup schema transaction under the startup lock
and is a catalog check on every later start: no table lock on a steady-state restart.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

ASSESSMENT_MIGRATION = "2.11.0_scans_assessment_columns"
#: Set (transaction-local) by the backfill: the scans change-time trigger leaves updated_at alone.
BACKFILL_SETTING = "shakerscan.scans_backfill"
BACKFILL_BATCH = 2000

#: Column -> (SQL type, projection of a ``result`` expression ``{r}``). The projections are the
#: exact expressions the readers used on the JSON, so a projected row reads the same value.
_REASONS_PATH = "{r} #> '{{coverage,grade_reliability,reasons}}'"
PROJECTIONS: tuple[tuple[str, str, str], ...] = (
    ("risk_assessment_state", "TEXT", "{r}->'result'->>'risk_assessment_state'"),
    ("application_observed", "BOOLEAN",
     "CASE WHEN jsonb_typeof({r}->'result'->'application_observed') = 'boolean' "
     "THEN ({r}->'result'->'application_observed')::text::boolean END"),
    ("grade_reliable", "BOOLEAN",
     "CASE {r} #>> '{{coverage,grade_reliability,reliable}}' "
     "WHEN 'true' THEN true WHEN 'false' THEN false END"),
    ("grade_reliability_reasons", "TEXT[]",
     "CASE WHEN jsonb_typeof(" + _REASONS_PATH + ") = 'array' "
     "THEN ARRAY(SELECT jsonb_array_elements_text(" + _REASONS_PATH + ")) "
     "ELSE '{{}}'::text[] END"),
)
COLUMNS = tuple(name for name, _type, _expr in PROJECTIONS) + ("assessment_projected",)


def projection(name: str, result_expr: str) -> str:
    for column, _type, expr in PROJECTIONS:
        if column == name:
            return expr.format(r=result_expr)
    raise KeyError(name)


def assessment_sql(name: str, alias: str = "s") -> str:
    """A NULL-tolerant read of one assessment field: the column once the row is projected, the
    JSON otherwise. CASE evaluates lazily, so a projected row never decompresses its report."""
    prefix = f"{alias}." if alias else ""
    return (f"(CASE WHEN {prefix}assessment_projected THEN {prefix}{name} "
            f"ELSE {projection(name, prefix + 'result')} END)")


#: The Scans list's assessment columns (scan/assessment.py ``project_scan_assessment_row`` reads
#: them). ``application_observed`` was the raw JSON value; it is now a boolean or NULL, which the
#: projection reads the same for every value an engine writes (true, false, null, absent).
SCAN_LIST_ASSESSMENT_COLUMNS = (
    f"{assessment_sql('risk_assessment_state')} AS risk_assessment_state, "
    f"{assessment_sql('application_observed')} AS application_observed"
)

TRIGGER_FUNCTION = "scans_project_assessment"
TRIGGER_NAME = "scans_project_assessment"
_TRIGGER_FUNCTION_SQL = (
    f"CREATE OR REPLACE FUNCTION {TRIGGER_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$\n"
    "BEGIN\n"
    + "".join(f"    NEW.{name} := {expr.format(r='NEW.result')};\n" for name, _type, expr in PROJECTIONS)
    + "    NEW.assessment_projected := true;\n"
    "    RETURN NEW;\n"
    "END $$"
)
_TRIGGER_SQL = (
    f"CREATE TRIGGER {TRIGGER_NAME} BEFORE INSERT OR UPDATE OF result ON scans "
    f"FOR EACH ROW EXECUTE FUNCTION {TRIGGER_FUNCTION}()"
)
#: The change-time trigger (scan/list_v1.py) with the backfill switch: a projection is not a
#: change anyone made.
TOUCH_FUNCTION_SQL = f"""CREATE OR REPLACE FUNCTION scans_touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'UPDATE' AND current_setting('{BACKFILL_SETTING}', true) = 'on' THEN
            RETURN NEW;
        END IF;
        NEW.updated_at := now();
        RETURN NEW;
    END $$"""


async def _function_source(conn: Any, name: str) -> str | None:
    return await conn.fetchval(
        "SELECT prosrc FROM pg_proc WHERE proname = $1 AND pronamespace = 'public'::regnamespace", name)


async def install_scan_assessment_columns(conn: Any) -> None:
    """Add the columns, the projection trigger and the backfill switch once.

    Every step reads the catalog first: on a steady-state restart nothing is executed that takes a
    lock on ``scans``. The columns have no default (metadata only, no rewrite)."""
    present = {row["attname"] for row in await conn.fetch(
        "SELECT attname FROM pg_attribute WHERE attrelid = 'scans'::regclass AND NOT attisdropped "
        "AND attname = ANY($1::text[])", list(COLUMNS))}
    for name, sql_type, _expr in (*PROJECTIONS, ("assessment_projected", "BOOLEAN", "")):
        if name not in present:
            await conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {sql_type}")
    expected_body = _TRIGGER_FUNCTION_SQL.split("$$", 2)[1]
    if (await _function_source(conn, TRIGGER_FUNCTION) or "").strip() != expected_body.strip():
        await conn.execute(_TRIGGER_FUNCTION_SQL)
    has_trigger = await conn.fetchval(
        "SELECT 1 FROM pg_trigger WHERE tgrelid = 'scans'::regclass AND tgname = $1 AND NOT tgisinternal",
        TRIGGER_NAME)
    if not has_trigger:
        await conn.execute(_TRIGGER_SQL)
    touch = await _function_source(conn, "scans_touch_updated_at")
    if touch is not None and BACKFILL_SETTING not in touch:
        await conn.execute(TOUCH_FUNCTION_SQL)


async def finish_scan_assessment_columns(conn: Any) -> None:
    """Under the startup lock, cheap on every start: with no Scans there is nothing to project."""
    if await _migration_applied(conn):
        return
    if await conn.fetchval("SELECT NOT EXISTS (SELECT 1 FROM scans)"):
        await _record_projected(conn)


async def _migration_applied(conn: Any) -> bool:
    return bool(await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name = $1)", ASSESSMENT_MIGRATION))


async def _record_projected(conn: Any) -> None:
    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING", ASSESSMENT_MIGRATION)


_BACKFILL_UPDATE_SQL = (
    "UPDATE scans SET "
    + ", ".join(f"{name} = {expr.format(r='result')}" for name, _type, expr in PROJECTIONS)
    + ", assessment_projected = true "
    "WHERE id = ANY($1::uuid[]) AND assessment_projected IS NULL"
)


async def backfill_scan_assessment(conn: Any, *, batch: int = BACKFILL_BATCH) -> int:
    """Project every row not projected yet, ``batch`` rows per transaction, in one pass over the
    primary key. Rows written meanwhile are projected by the trigger, so one pass is enough."""
    projected = 0
    last_id = None
    while True:
        ids = await conn.fetch(
            "SELECT id FROM scans WHERE ($1::uuid IS NULL OR id > $1::uuid) "
            "AND assessment_projected IS NULL ORDER BY id LIMIT $2",
            last_id, batch,
        )
        if not ids:
            break
        last_id = ids[-1]["id"]
        async with conn.transaction():
            await conn.execute(f"SET LOCAL {BACKFILL_SETTING} = 'on'")
            status = await conn.execute(_BACKFILL_UPDATE_SQL, [row["id"] for row in ids])
        projected += int(str(status).rsplit(" ", 1)[-1] or 0)
        if len(ids) < batch:
            break
        await asyncio.sleep(0)  # yield between batches; the API is serving
    return projected


_LOCK = (0x53534C50, 0x2B11_A55)  # loop_leader's namespace, this backfill's key


async def project_scan_assessment(pool: Any) -> int:
    """One try-locked pass; records the migration marker after the first complete pass."""
    async with pool.acquire() as conn:
        if not await conn.fetchval("SELECT pg_try_advisory_lock($1::int, $2::int)", *_LOCK):
            return 0
        try:
            first = not await _migration_applied(conn)
            count = await backfill_scan_assessment(conn)
            if first:
                await _record_projected(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1::int, $2::int)", *_LOCK)
    if first:
        logger.info("scans assessment columns projected for %d scans", count)
    elif count:
        logger.warning("scans assessment columns projected for %d scans written without the trigger", count)
    return count


async def project_scan_assessment_in_background(pool: Any, *, delay: float = 20.0) -> None:
    """The API lifespan's maintenance task; a failure is logged only (the next start continues).
    A first pass (an upgraded database) starts at once; the routine repair pass waits ``delay``."""
    try:
        async with pool.acquire() as conn:
            done = await _migration_applied(conn)
        await asyncio.sleep(delay if done else 0)
        await project_scan_assessment(pool)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # never stops the API: reads fall back to the JSON
        logger.warning("scans assessment projection skipped: %s", type(exc).__name__)


__all__ = [
    "ASSESSMENT_MIGRATION",
    "BACKFILL_SETTING",
    "COLUMNS",
    "PROJECTIONS",
    "SCAN_LIST_ASSESSMENT_COLUMNS",
    "assessment_sql",
    "backfill_scan_assessment",
    "finish_scan_assessment_columns",
    "install_scan_assessment_columns",
    "project_scan_assessment",
    "project_scan_assessment_in_background",
    "projection",
]
