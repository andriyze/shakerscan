"""Dashboard inputs that stay cheap at scale: summary counts and a single-flight cache.

Every finding and scan count on the dashboard comes from the trigger-maintained summary
(``targets/scale_summary.py``) instead of counting ``findings``/``scans`` per request, and the
assembled response is cached for ``DASHBOARD_CACHE_SECONDS`` (default 15). Concurrent requests
for an expired entry share one computation, so N open dashboards cost one computation per
interval rather than N full passes.

The predicates below mirror the SQL they replace (db/init.sql ``dashboard_metrics`` and the
product-status / action-center queries). The summary stores a NULL ``status``/``source`` as '',
and every predicate here treats NULL and '' the same way the SQL did (``COALESCE(source,
'scan') <> 'device'`` and ``COALESCE(source, '') <> 'device'`` both keep a NULL source).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import time
from typing import Any, Awaitable, Callable

try:
    from list_contract import SqlParams
    from target_cohort_sql import COHORT_VIEWS, cohort_filter_sql, fill_url_classes, row_cohorts
    from targets.scale_summary import FINDING_TOTALS_SQL, SCAN_TOTALS_SQL, compact
except ModuleNotFoundError:  # package import layout
    from ..list_contract import SqlParams
    from ..target_cohort_sql import COHORT_VIEWS, cohort_filter_sql, fill_url_classes, row_cohorts
    from ..targets.scale_summary import FINDING_TOTALS_SQL, SCAN_TOTALS_SQL, compact

DEVICE_RUN_KINDS = frozenset({"device_posture", "device_probe", "device_web_dast"})
AI_RUN_KINDS = frozenset({"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp", "model_intake"})
NON_DAST_SOURCES = frozenset({"ai_gate", "ai_session", "model_intake", "asm", "manual"})


@dataclass(frozen=True)
class DashboardCounts:
    """Current finding and scan totals by bucket, read once per dashboard computation."""

    findings: tuple[tuple[str, str, str, bool, bool, int], ...] = ()
    scans: tuple[tuple[str, str, bool, int], ...] = ()
    recent_failed_dast_scans: int = 0

    def _findings(self, predicate: Callable[[str, str, str, bool, bool], bool]) -> int:
        return sum(n for status, severity, source, mi_tool, ai_target, n in self.findings
                   if predicate(status, severity, source, mi_tool, ai_target))

    def _scans(self, predicate: Callable[[str, str, bool], bool]) -> int:
        return sum(n for status, run_kind, shard, n in self.scans if predicate(status, run_kind, shard))

    # db/init.sql dashboard_metrics: active findings outside the device plane.
    def active_findings(self, severity: str | None = None) -> int:
        return self._findings(lambda st, sev, src, _mi, _ai: st == "active" and src != "device"
                              and (severity is None or sev == severity))

    # Active findings in every plane (the deployment-gate card).
    def active_any_source(self, severity: str) -> int:
        return self._findings(lambda st, sev, _src, _mi, _ai: st == "active" and sev == severity)

    def dast_active(self, *, blockers: bool) -> int:
        return self._findings(lambda st, sev, src, mi, ai: st == "active" and src not in NON_DAST_SOURCES
                              and not ai and not mi and (not blockers or sev in ("critical", "high")))

    def ai_gate_active(self) -> int:
        return self._findings(lambda st, _sev, src, _mi, ai: st == "active" and (src == "ai_gate" or ai))

    def model_intake_active(self) -> int:
        return self._findings(lambda st, _sev, src, mi, _ai: st == "active" and (src == "model_intake" or mi))

    # dashboard_metrics: completed/running scans, shards and device run kinds excluded.
    def scans_in(self, status: str) -> int:
        return self._scans(lambda st, kind, shard: st == status and not shard and kind not in DEVICE_RUN_KINDS)

    def dast_active_scans(self) -> int:
        return self._scans(lambda st, kind, shard: st in ("pending", "queued", "running") and not shard
                           and kind not in AI_RUN_KINDS)


async def load_dashboard_counts(conn: Any) -> DashboardCounts:
    findings = await conn.fetch(
        f"SELECT status, severity, source, model_intake_tool, ai_target, n FROM {FINDING_TOTALS_SQL} totals"
    )
    scans = await conn.fetch(f"SELECT status, run_kind, shard, n FROM {SCAN_TOTALS_SQL} totals")
    # Time-windowed, so not a summary bucket; (status, created_at) bounds it to the window.
    recent_failed = await conn.fetchval("""
        SELECT COUNT(*) FROM scans
        WHERE status = 'failed' AND created_at >= NOW() - INTERVAL '7 days'
          AND (scan_role IS NULL OR scan_role <> 'shard')
          AND COALESCE(run_kind, 'dast') NOT IN ('ai_api', 'ai_widget', 'ai_rag', 'ai_trace', 'ai_mcp', 'model_intake')
    """)
    return DashboardCounts(
        findings=tuple((str(r["status"]), str(r["severity"]), str(r["source"]), bool(r["model_intake_tool"]),
                        bool(r["ai_target"]), int(r["n"])) for r in findings or ()),
        scans=tuple((str(r["status"]), str(r["run_kind"]), bool(r["shard"]), int(r["n"])) for r in scans or ()),
        recent_failed_dast_scans=int(recent_failed or 0),
    )


async def dashboard_metrics(conn: Any, counts: DashboardCounts) -> dict[str, Any]:
    """The ``dashboard_metrics`` view's columns, from the summary instead of seven table scans."""
    total_targets = await conn.fetchval(
        "SELECT COUNT(*) FROM targets WHERE is_active = true "
        "AND COALESCE(discovery_source, 'manual') <> 'model-intake'"
    )
    # latest_scans (newest completed scan per URL) as an index-only walk of
    # idx_scans_latest_completed_url; the predicate repeats the view's so that index applies.
    avg_score = await conn.fetchval("""
        SELECT AVG(score) FROM (
            SELECT DISTINCT ON (target_url) score
            FROM scans
            WHERE status = 'completed' AND (scan_role IS NULL OR scan_role <> 'shard')
              AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')
            ORDER BY target_url, completed_at DESC
        ) latest
    """)
    return {
        "total_targets": int(total_targets or 0),
        "total_scans": counts.scans_in("completed"),
        "running_scans": counts.scans_in("running"),
        "active_findings": counts.active_findings(),
        "critical_findings": counts.active_findings("critical"),
        "high_findings": counts.active_findings("high"),
        "avg_score": avg_score,
    }


_RECENT_SCAN_COLUMNS = ("id, target_id, ai_target_id, target_url, status, score, grade, "
                        "scan_type, run_kind, findings_count, created_at, completed_at")
_RECENT_SCAN_FILTER = """status = 'completed'
          AND (scan_role IS NULL OR scan_role <> 'shard')
          AND COALESCE(run_kind, '') <> 'model_intake'
          AND COALESCE(scan_type, '') <> 'model_intake'
          AND device_target_id IS NULL
          AND COALESCE(scan_role, '') <> 'device_web_origin'
          AND COALESCE(run_kind, '') NOT IN ('device_posture','device_probe','device_web_dast')"""


def _recent_scan_key(row: Any) -> str | None:
    if row["target_id"] is not None:
        return f"target:{row['target_id']}"
    if row["ai_target_id"] is not None:
        return f"ai:{row['ai_target_id']}"
    return None if row["target_url"] is None else f"url:{row['target_url']}"


#: The dashboard's cohort selections other than "all" (``recent_scans`` serves "all").
DASHBOARD_COHORT_VIEWS = ("operational", "production", "staging", "non_operational")


async def recent_latest_scans(conn: Any, limit: int = 10, *,
                              cohorts: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """The newest completed scan of each of the ``limit`` most recently scanned subjects.

    Equivalent to DISTINCT ON (subject) ... ORDER BY created_at DESC LIMIT n, without sorting
    every completed scan: walking completed scans newest first, the first scan seen for a
    subject is its latest, so the walk stops after ``limit`` subjects (index on status, created_at).

    Every row carries ``target_cohort``, its subject's cohort (``target_cohort_sql.row_cohorts``:
    the target's, else the AI target's, else the URL host's). ``cohorts`` keeps only subjects of
    those cohorts: SQL narrows the walk to targets of the cohorts (and rows without a target), and
    the Python label decides.
    """
    found: list[dict[str, Any]] = []
    seen: set[str | None] = set()
    base = SqlParams()
    cohort_sql = ""
    if cohorts:
        await fill_url_classes(conn)
        cohort_sql = (" AND (target_id IS NULL OR target_id IN (SELECT t.id FROM targets t WHERE "
                      f"{cohort_filter_sql('t', cohorts, base)}))")
    where = f"{_RECENT_SCAN_FILTER}{cohort_sql}"

    async def take(rows: Any) -> bool:
        batch_rows = [dict(row) for row in rows]
        labels = await row_cohorts(conn, batch_rows)
        for row, label in zip(batch_rows, labels):
            key = _recent_scan_key(row)
            if key in seen:
                continue
            seen.add(key)
            if cohorts and (label or "unclassified") not in cohorts:
                continue
            row["target_cohort"] = label
            found.append(row)
            if len(found) >= limit:
                return True
        return False

    # PostgreSQL sorts NULL first descending; a NULL created_at (never written by the engine)
    # is still honoured before the keyset walk.
    if await take(await conn.fetch(
        f"SELECT {_RECENT_SCAN_COLUMNS} FROM scans WHERE {where} AND created_at IS NULL "
        "ORDER BY id DESC", *base.values,
    )):
        return found
    position: tuple[Any, Any] | None = None
    batch = 100
    while True:
        params = SqlParams(base.values)
        if position is None:
            rows = await conn.fetch(
                f"SELECT {_RECENT_SCAN_COLUMNS} FROM scans WHERE {where} AND created_at IS NOT NULL "
                f"ORDER BY created_at DESC, id DESC LIMIT {params.add(batch)}", *params.values,
            )
        else:
            rows = await conn.fetch(
                f"SELECT {_RECENT_SCAN_COLUMNS} FROM scans WHERE {where} "
                f"AND (created_at, id) < ({params.add(position[0])}, {params.add(position[1])}) "
                f"ORDER BY created_at DESC, id DESC LIMIT {params.add(batch)}", *params.values,
            )
        if await take(rows) or len(rows) < batch:
            return found
        position = (rows[-1]["created_at"], rows[-1]["id"])
        batch = min(batch * 4, 5000)


async def recent_scans_by_cohort(conn: Any, limit: int = 10) -> dict[str, list[dict[str, Any]]]:
    """``recent_latest_scans`` for each dashboard cohort view (the view's own walk, so a scoped
    view lists its own latest results rather than the slice of the global list that matched)."""
    return {view: await recent_latest_scans(conn, limit=limit, cohorts=COHORT_VIEWS[view])
            for view in DASHBOARD_COHORT_VIEWS}


async def recent_blocker_findings(conn: Any, limit: int = 10) -> list[dict[str, Any]]:
    """Newest active critical, then high, findings outside the device plane (first_seen_at index)."""
    found: list[dict[str, Any]] = []
    for severity in ("critical", "high"):
        if len(found) >= limit:
            break
        rows = await conn.fetch("""
            SELECT id, title, severity, status, tool, first_seen_at
            FROM findings
            WHERE status = 'active' AND severity = $1 AND COALESCE(source, '') <> 'device'
            ORDER BY first_seen_at DESC
            LIMIT $2
        """, severity, limit - len(found))
        found.extend(dict(row) for row in rows)
    return found


# --- Single-flight cache -----------------------------------------------------------------------


def cache_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("DASHBOARD_CACHE_SECONDS", "15")))
    except ValueError:
        return 15.0


@dataclass
class SingleFlightCache:
    """One value, recomputed at most once per ``ttl`` however many callers ask at once."""

    ttl: Callable[[], float] = cache_seconds
    _value: Any = None
    _stored_at: float = 0.0
    _task: "asyncio.Future[Any] | None" = None
    _loop: Any = None
    _lock: Any = field(default=None, repr=False)

    def clear(self) -> None:
        self._value, self._stored_at, self._task, self._loop = None, 0.0, None, None

    async def get(self, compute: Callable[[], Awaitable[Any]]) -> Any:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:  # a new event loop (tests, a restarted server) starts empty
            self.clear()
            self._loop = loop
        ttl = self.ttl()
        if self._value is not None and ttl > 0 and time.monotonic() - self._stored_at < ttl:
            return self._value
        if self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._refresh(compute))
        # A caller that disconnects must not cancel the computation the others are waiting for.
        return await asyncio.shield(self._task)

    async def _refresh(self, compute: Callable[[], Awaitable[Any]]) -> Any:
        value = await compute()
        self._value, self._stored_at = value, time.monotonic()
        return value


def generated_at() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "DashboardCounts",
    "SingleFlightCache",
    "cache_seconds",
    "compact",
    "dashboard_metrics",
    "generated_at",
    "load_dashboard_counts",
    "recent_blocker_findings",
    "DASHBOARD_COHORT_VIEWS",
    "recent_latest_scans",
    "recent_scans_by_cohort",
]
