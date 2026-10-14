"""Indexes the bounded background loops read through (2.11), built without blocking writers.

Each index is created with CREATE INDEX CONCURRENTLY, so a large table keeps taking writes while it
builds. That cannot run inside a transaction or under the startup schema lock (a process waiting
for that lock holds a snapshot the build would wait for), so it runs after the startup migrations,
under its own try-lock: the first process to start builds, the others carry on without waiting and
use the indexes once they exist. A build interrupted by a restart leaves an invalid index; the next
start drops and rebuilds it. A failed build is logged and never stops startup: the loops are
correct without these indexes, only slower. The API starts the build as a background task after it
begins serving (``build_loop_scale_indexes_in_background``), so a long build never delays startup.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# (index name, table, definition after "ON").
LOOP_SCALE_INDEXES: tuple[tuple[str, str, str], ...] = (
    # The settled-reservation repair walks Scan reservations by (updated_at, id) from a cursor.
    (
        "idx_budget_reservations_settled_scan_walk",
        "budget_reservations",
        "budget_reservations (updated_at, id) "
        "WHERE owner_kind = 'scan' AND status IN ('committed','released','failed')",
    ),
    # The lost-handoff sweep walks waiting Scans by (created_at, id) from a cursor.
    (
        "idx_scans_waiting_created_walk",
        "scans",
        "scans (created_at, id) WHERE status IN ('pending','queued')",
    ),
    # The research reconciler's stale two-phase handoffs (pending, confirmation still false).
    (
        "idx_scans_unconfirmed_handoff_created",
        "scans",
        "scans (created_at) WHERE status = 'pending' AND (options->>'queue_handoff_confirmed') = 'false'",
    ),
    # The ASM dispatcher's tested-in-the-last-day and per-root-domain rate counts.
    (
        "idx_target_endpoints_last_tested_at",
        "target_endpoints",
        "target_endpoints (last_tested_at) WHERE last_tested_at IS NOT NULL",
    ),
)

_LOCK_NAMESPACE = 0x53534C50  # loop_leader.LOOP_LOCK_NAMESPACE
_LOCK_KEY = 0x2B11_1D5  # this module's build lock within that namespace


async def _index_state(conn: Any, name: str) -> bool | None:
    """True valid, False present but invalid (an interrupted build), None absent."""
    valid = await conn.fetchval(
        """SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
           WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace""",
        name,
    )
    return None if valid is None else bool(valid)


async def ensure_loop_scale_indexes(pool: Any, *, progress: Any = None) -> list[str]:
    """Build any missing index concurrently; return the names built (or rebuilt)."""
    report = progress if callable(progress) else (lambda _message: None)
    built: list[str] = []
    async with pool.acquire() as conn:
        in_transaction = getattr(conn, "is_in_transaction", None)
        if callable(in_transaction) and in_transaction():
            return built  # a caller's transaction (a bound test connection): CONCURRENTLY cannot run
        if not await conn.fetchval("SELECT pg_try_advisory_lock($1::int, $2::int)", _LOCK_NAMESPACE, _LOCK_KEY):
            return built  # another process is building them
        previous_timeout = await conn.fetchval("SHOW statement_timeout")
        try:
            # A build on a large table may take longer than an interactive statement may.
            await conn.execute("SET statement_timeout = 0")
            for name, table, definition in LOOP_SCALE_INDEXES:
                try:
                    if not await conn.fetchval("SELECT to_regclass($1)", table):
                        continue
                    state = await _index_state(conn, name)
                    if state:
                        continue
                    if state is False:
                        report(f"dropping interrupted build of {name}")
                        await conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
                    report(f"building {name} concurrently")
                    await conn.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {definition}")
                    built.append(name)
                    report(f"built {name}")
                except Exception as exc:  # never stop startup over a performance index
                    logger.warning("Could not build index %s: %s", name, type(exc).__name__)
        finally:
            try:
                await conn.execute(f"SET statement_timeout = '{previous_timeout}'")
            finally:
                await conn.execute("SELECT pg_advisory_unlock($1::int, $2::int)", _LOCK_NAMESPACE, _LOCK_KEY)
    return built


BACKGROUND_START_DELAY_SECONDS = 10.0


async def build_loop_scale_indexes_in_background(pool: Any, *, delay: float = BACKGROUND_START_DELAY_SECONDS) -> None:
    """The API lifespan's background task: wait until the API serves, then build; never fatal."""
    import asyncio

    await asyncio.sleep(delay)
    print("[schema] loop index build: checking", flush=True)
    try:
        # It sets its own unbounded statement_timeout for the build session and restores it.
        built = await ensure_loop_scale_indexes(pool, progress=lambda message: print(f"[schema] {message}", flush=True))
    except asyncio.CancelledError:
        print("[schema] loop index build interrupted (an invalid index is rebuilt on the next start)", flush=True)
        raise
    except Exception as exc:  # performance indexes never stop the API
        print(f"[schema] loop index build skipped: {type(exc).__name__}", flush=True)
        return
    print(f"[schema] loop index build done ({len(built)} built)", flush=True)


__all__ = ["LOOP_SCALE_INDEXES", "build_loop_scale_indexes_in_background", "ensure_loop_scale_indexes"]
