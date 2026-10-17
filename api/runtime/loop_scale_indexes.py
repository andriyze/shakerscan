"""Indexes the bounded background loops read through (2.11), built without blocking writers.

Each index is created with CREATE INDEX CONCURRENTLY, so a large table keeps taking writes while it
builds. That cannot run inside a transaction or under the startup schema lock (a process waiting
for that lock holds a snapshot the build would wait for), so it runs after the startup migrations,
under its own try-lock: the first process to start builds, the others carry on without waiting and
use the indexes once they exist. A build interrupted by a restart leaves an invalid index; the next
start drops and rebuilds it. A failed build is logged and never stops startup: the loops are
correct without these indexes, only slower. The API starts the build as a background task after it
begins serving (``build_loop_scale_indexes_in_background``), so a long build never delays startup.

After the builds, the same run drops the indexes ``REDUNDANT_INDEXES`` names (DROP INDEX
CONCURRENTLY), each only once the declared index that covers it is valid. ``/health`` reports the
state as ``loop_indexes`` (``index_health``): an index still missing after the build gave up is
``failed`` there, not only in the log.
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
    # --- Read paths: targets, scans, Hunts, graph and ASM coverage (2.11 list/v1 and dashboard).
    # Keyset lists newest first (list/v1 orders both columns one way).
    ("idx_targets_updated_id", "targets", "targets (updated_at DESC, id DESC)"),
    ("idx_hunt_runs_updated_id", "hunt_runs", "hunt_runs (updated_at DESC, id DESC)"),
    # The grouped Targets order (root domain, root first, then URL).
    ("idx_targets_root_domain_root_url", "targets", "targets (root_domain, is_root DESC, url)"),
    # Scans of one target newest first; scans in a status newest first (dashboard recent/failed).
    ("idx_scans_target_created", "scans", "scans (target_id, created_at DESC)"),
    ("idx_scans_status_created", "scans", "scans (status, created_at DESC)"),
    # /scans list/v1: newest first by (created_at, id), and since= deltas on the change time.
    (
        "idx_scans_list_created_id",
        "scans",
        "scans ((COALESCE(created_at, '-infinity'::timestamptz)) DESC, id DESC)",
    ),
    ("idx_scans_changed_at", "scans", "scans ((COALESCE(updated_at, created_at)))"),
    # "Is anything queued or running on this asset" (inventory activity facet and filter).
    ("idx_scans_active_target", "scans", "scans (target_id) WHERE status IN ('pending', 'queued', 'running')"),
    # The dashboard's latest completed scan per URL (the latest_scans view) as an index-only scan.
    (
        "idx_scans_latest_completed_url",
        "scans",
        "scans (target_url, completed_at DESC) INCLUDE (score) WHERE status = 'completed' "
        "AND (scan_role IS NULL OR scan_role <> 'shard') "
        "AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')",
    ),
    # The latest ASM attempt per endpoint (coverage) without sorting every attempt.
    (
        "idx_asm_endpoint_attempts_latest",
        "asm_endpoint_attempts",
        "asm_endpoint_attempts (endpoint_id, (COALESCE(completed_at, started_at)) DESC, started_at DESC)",
    ),
    # The cross-Hunt permission-request feed (GET /hunts/permission-requests): oldest first by
    # (created_at, id), and its usual filter, pending requests.
    (
        "idx_hunt_permission_requests_feed",
        "hunt_permission_requests",
        "hunt_permission_requests (created_at, id)",
    ),
    (
        "idx_hunt_permission_requests_pending_feed",
        "hunt_permission_requests",
        "hunt_permission_requests (created_at, id) WHERE status = 'pending'",
    ),
    # Paged application-graph nodes and edges (list/v1 keyset on id within a target).
    ("idx_app_graph_nodes_target_id_walk", "application_graph_nodes", "application_graph_nodes (target_id, id)"),
    ("idx_app_graph_edges_target_id_walk", "application_graph_edges", "application_graph_edges (target_id, id)"),
    # Substring search (ILIKE '%term%'); built only when pg_trgm is available.
    ("idx_targets_url_trgm", "targets", "targets USING gin (url gin_trgm_ops)"),
    ("idx_targets_name_trgm", "targets", "targets USING gin (name gin_trgm_ops)"),
    ("idx_targets_root_domain_trgm", "targets", "targets USING gin (root_domain gin_trgm_ops)"),
    ("idx_scans_target_url_trgm", "scans", "scans USING gin (target_url gin_trgm_ops)"),
    ("idx_hunt_runs_objective_trgm", "hunt_runs", "hunt_runs USING gin (objective gin_trgm_ops)"),
)

#: Indexes an earlier schema created that a declared index above makes redundant: (name, table,
#: the one column it indexes, the declared index whose leading column serves every lookup it
#: served). A fresh install's frozen baseline (db/init.sql, the one-time asset conversion) still
#: creates them, as every release did; this builder drops them on fresh and upgraded databases
#: alike, after the covering index is valid, so both converge. An index under one of these names
#: with any other definition is left alone.
REDUNDANT_INDEXES: tuple[tuple[str, str, str, str], ...] = (
    ("idx_scans_target_id", "scans", "target_id", "idx_scans_target_created"),
    ("idx_scans_unified_target", "scans", "target_id", "idx_scans_target_created"),
    ("idx_scans_status", "scans", "status", "idx_scans_status_created"),
)

# The findings list's keyset, per-asset count, proof-candidate and search indexes
# (finding_routes/list_schema.py): one builder for every bounded read.
try:
    from finding_routes.list_schema import FINDINGS_SCALE_INDEXES
except ModuleNotFoundError:  # package import layout
    from api.finding_routes.list_schema import FINDINGS_SCALE_INDEXES
# The settled-findings count behind the Exposure asset list (exposure/scale_indexes.py).
try:
    from exposure.scale_indexes import EXPOSURE_SCALE_INDEXES
except ModuleNotFoundError:  # package import layout
    from api.exposure.scale_indexes import EXPOSURE_SCALE_INDEXES
LOOP_SCALE_INDEXES = (*LOOP_SCALE_INDEXES, *FINDINGS_SCALE_INDEXES, *EXPOSURE_SCALE_INDEXES)

#: Tables analyzed after one of their indexes is (re)built: the findings proof-gate statistics the
#: planner needs to choose the partial proof index.
ANALYZE_AFTER_BUILD = frozenset({"findings"})


def _needs_trgm(definition: str) -> bool:
    return "gin_trgm_ops" in definition


async def _ensure_trgm(conn: Any) -> bool:
    """pg_trgm (a trusted extension the database owner may create); without it, skip those."""
    if await conn.fetchval("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'"):
        return True
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        return True
    except Exception as exc:
        logger.warning("pg_trgm unavailable; substring-search indexes skipped: %s", type(exc).__name__)
        return False

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


#: A build that fails (a deadlock victim, a cancelled statement, a lock timeout) is tried again
#: in the same run after these pauses, then logged and left to the next start.
RETRY_DELAYS_SECONDS: tuple[float, ...] = (5.0, 30.0, 120.0)


async def _build_one(conn: Any, name: str, table: str, definition: str, trgm: dict[str, bool],
                     report: Any) -> bool | None:
    """True when built now, None when nothing was needed or possible; raises on a failed build."""
    if not await conn.fetchval("SELECT to_regclass($1)", table):
        return None
    state = await _index_state(conn, name)
    if state:
        return None
    if _needs_trgm(definition):
        if "available" not in trgm:
            trgm["available"] = await _ensure_trgm(conn)
        if not trgm["available"]:
            return None
    if state is False:
        report(f"dropping interrupted build of {name}")
        await conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
    report(f"building {name} concurrently")
    await conn.execute(f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {definition}")
    report(f"built {name}")
    return True


async def _is_plain_single_column_index(conn: Any, name: str, table: str, column: str) -> bool:
    """True when ``name`` is exactly a plain btree on ``table(column)``: what the old schema made."""
    return bool(await conn.fetchval(
        """SELECT 1 FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
                  JOIN pg_class t ON t.oid = i.indrelid
                  JOIN pg_am am ON am.oid = c.relam
                  JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
           WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace
             AND t.relname = $2 AND a.attname = $3 AND am.amname = 'btree'
             AND i.indnatts = 1 AND NOT i.indisunique AND NOT i.indisprimary
             AND i.indpred IS NULL AND i.indexprs IS NULL""",
        name, table, column,
    ))


async def _drop_redundant(conn: Any, name: str, table: str, column: str, covering: str, report: Any) -> bool:
    """Drop one redundant index once its covering index is valid; True when dropped now."""
    if not await _is_plain_single_column_index(conn, name, table, column):
        return False
    if not await _index_state(conn, covering):
        return False  # the covering index is not built (yet): keep serving lookups with this one
    report(f"dropping redundant {name} (covered by {covering}) concurrently")
    await conn.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
    report(f"dropped {name}")
    return True


#: What this process's builder did last (``index_health`` reads it; another process may be the
#: one building, which the catalog and the build lock show).
_RUN_STATE: dict[str, Any] = {"state": "pending", "failed": [], "finished_at": None}


def _set_run_state(state: str, *, failed: list[tuple[str, str]] | None = None) -> None:
    from datetime import datetime, timezone

    _RUN_STATE["state"] = state
    if failed is not None:
        _RUN_STATE["failed"] = [{"index": name, "error": error} for name, error in failed]
    if state not in ("pending", "running"):
        _RUN_STATE["finished_at"] = datetime.now(timezone.utc).isoformat()


async def ensure_loop_scale_indexes(pool: Any, *, progress: Any = None,
                                    retry_delays: tuple[float, ...] | None = None) -> list[str]:
    """Build any missing index concurrently; return the names built (or rebuilt)."""
    import asyncio

    report = progress if callable(progress) else (lambda _message: None)
    delays = RETRY_DELAYS_SECONDS if retry_delays is None else retry_delays
    built: list[str] = []
    async with pool.acquire() as conn:
        in_transaction = getattr(conn, "is_in_transaction", None)
        if callable(in_transaction) and in_transaction():
            return built  # a caller's transaction (a bound test connection): CONCURRENTLY cannot run
        if not await conn.fetchval("SELECT pg_try_advisory_lock($1::int, $2::int)", _LOCK_NAMESPACE, _LOCK_KEY):
            _set_run_state("locked_elsewhere", failed=[])
            return built  # another process is building them
        _set_run_state("running")
        previous_timeout = await conn.fetchval("SHOW statement_timeout")
        errors: dict[str, str] = {}
        try:
            # A build on a large table may take longer than an interactive statement may.
            await conn.execute("SET statement_timeout = 0")
            trgm: dict[str, bool] = {}
            # Builds first, then the drops their covering indexes make safe; a pending drop
            # is retried with the builds.
            pending: list[tuple[str, Any]] = [
                *(("build", item) for item in LOOP_SCALE_INDEXES),
                *(("drop", item) for item in REDUNDANT_INDEXES),
            ]
            for attempt in range(len(delays) + 1):
                if attempt:
                    report(f"retrying {len(pending)} failed index change(s) in {delays[attempt - 1]:g} s")
                    await asyncio.sleep(delays[attempt - 1])
                failed = []
                for kind, item in pending:
                    name = item[0]
                    try:
                        if kind == "build":
                            if await _build_one(conn, *item, trgm, report):
                                built.append(name)
                        else:
                            await _drop_redundant(conn, *item, report)
                        errors.pop(name, None)
                    except Exception as exc:  # never stop startup over a performance index
                        logger.warning("Could not %s index %s (attempt %d): %s",
                                       kind, name, attempt + 1, type(exc).__name__)
                        errors[name] = type(exc).__name__
                        failed.append((kind, item))
                pending = failed
                if not pending:
                    break
            for _kind, item in pending:
                logger.warning("Index %s still not built after %d attempts; the next start retries it",
                               item[0], len(delays) + 1)
            for table in dict.fromkeys(table for name, table, _definition in LOOP_SCALE_INDEXES
                                       if name in built and table in ANALYZE_AFTER_BUILD):
                try:
                    await conn.execute(f"ANALYZE {table}")
                except Exception as exc:
                    logger.warning("Could not analyze %s: %s", table, type(exc).__name__)
            _set_run_state("failed" if pending else "done",
                           failed=[(item[0], errors.get(item[0], "unknown")) for _kind, item in pending])
        except BaseException:
            _set_run_state("interrupted", failed=sorted(errors.items()))
            raise
        finally:
            try:
                await conn.execute(f"SET statement_timeout = '{previous_timeout}'")
            finally:
                await conn.execute("SELECT pg_advisory_unlock($1::int, $2::int)", _LOCK_NAMESPACE, _LOCK_KEY)
    return built


#: At most this many names per list in the health report.
HEALTH_NAME_LIMIT = 20


async def index_health(conn: Any) -> dict[str, Any]:
    """The ``loop_indexes`` field of /health: are the declared indexes built, and if not, why.

    ``status`` is ``ok`` (every declared index valid), ``building`` (a builder holds the build
    lock, or this process has not finished its first run), ``failed`` (indexes are missing or
    invalid and nobody is building them: the last build gave up, the next start retries) or
    ``unavailable`` (the catalog could not be read). Substring-search indexes count only where
    pg_trgm is installed; without it they are listed as ``skipped``.
    """
    names = [name for name, _table, _definition in LOOP_SCALE_INDEXES]
    rows = await conn.fetch(
        """SELECT c.relname, i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
           WHERE c.relname = ANY($1::text[]) AND c.relnamespace = current_schema()::regnamespace""",
        [*names, *(name for name, *_rest in REDUNDANT_INDEXES)],
    )
    state = {row["relname"]: bool(row["indisvalid"]) for row in rows}
    trgm = bool(await conn.fetchval("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'"))
    tables = {str(row["relname"]) for row in await conn.fetch(
        "SELECT relname FROM pg_class WHERE relname = ANY($1::text[]) AND relkind IN ('r', 'p') "
        "AND relnamespace = current_schema()::regnamespace",
        sorted({table for _name, table, _definition in LOOP_SCALE_INDEXES}))}
    missing, invalid, skipped = [], [], []
    for name, table, definition in LOOP_SCALE_INDEXES:
        if table not in tables:
            continue  # an optional module's table that this install does not have
        if _needs_trgm(definition) and not trgm:
            skipped.append(name)
        elif name not in state:
            missing.append(name)
        elif not state[name]:
            invalid.append(name)
    building = bool(await conn.fetchval(
        """SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted
              AND classid = $1::int::oid AND objid = $2::int::oid AND objsubid = 2""",
        _LOCK_NAMESPACE, _LOCK_KEY,
    ))
    if not missing and not invalid:
        status = "ok"
    elif building or _RUN_STATE["state"] in ("pending", "running"):
        status = "building"
    else:
        status = "failed"
    report: dict[str, Any] = {
        "status": status,
        "declared": len(names),
        "missing": missing[:HEALTH_NAME_LIMIT],
        "invalid": invalid[:HEALTH_NAME_LIMIT],
        "redundant_present": [name for name, *_rest in REDUNDANT_INDEXES if name in state],
        "last_run": {"state": _RUN_STATE["state"], "finished_at": _RUN_STATE["finished_at"],
                     "failed": list(_RUN_STATE["failed"])[:HEALTH_NAME_LIMIT]},
    }
    if skipped:
        report["skipped"] = skipped[:HEALTH_NAME_LIMIT]
        report["skipped_reason"] = "pg_trgm is not installed"
    return report


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
        if _RUN_STATE["state"] in ("pending", "running"):
            _set_run_state("interrupted")
        print("[schema] loop index build interrupted (an invalid index is rebuilt on the next start)", flush=True)
        raise
    except Exception as exc:  # performance indexes never stop the API
        if _RUN_STATE["state"] in ("pending", "running"):
            _set_run_state("error", failed=[("*", type(exc).__name__)])
        print(f"[schema] loop index build skipped: {type(exc).__name__}", flush=True)
        return
    print(f"[schema] loop index build done ({len(built)} built)", flush=True)


__all__ = [
    "LOOP_SCALE_INDEXES",
    "REDUNDANT_INDEXES",
    "build_loop_scale_indexes_in_background",
    "ensure_loop_scale_indexes",
    "index_health",
]
