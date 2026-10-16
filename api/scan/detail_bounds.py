"""Bounds on ``GET /scans/{id}`` (2.11): its findings list and its parallel children.

The detail answered every persisted finding of the Scan with its evidence, however many there
were, and read every child Scan's whole report and options to compute a few contribution facts.

* Findings: at most ``findings_limit`` rows (default and maximum ``MAX_DETAIL_FINDINGS``, in the
  same severity order, then most recently seen), with ``findings_total`` and
  ``findings_truncated``; the complete set stays available from ``GET /findings?scan_id=``.
  ``findings_limit=0`` leaves them out (a poller that only needs the status).
* Children: only the report and option keys ``_parallel_shard_contribution`` reads are
  transferred. The two potentially long lists are reduced to what it counts: each endpoint attempt
  to its status, each assigned endpoint to a placeholder (only their number is used).
"""
from __future__ import annotations

from typing import Any
import uuid

MAX_DETAIL_FINDINGS = 5000

_ACTIVE = "s.result -> 'active_checks'"
_ACTIVE_KEYS = (
    "check_family_scope", "active_worklist_total", "active_endpoints_selected",
    "active_endpoint_budget", "endpoint_attempts_total", "per_endpoint_telemetry",
)
_OPTION_KEYS = (
    "asm_check_family", "check_family", "custom_budget", "budget_profile", "auth_state",
    "auth_header", "auth_cookies", "auth_headers_json", "login_username",
)


def _keys(column: str, keys: tuple[str, ...]) -> str:
    names = ", ".join(f"'{key}'" for key in keys)
    return (f"COALESCE((SELECT jsonb_object_agg(k.key, k.value) FROM jsonb_each({column}) k "
            f"WHERE k.key IN ({names})), '{{}}'::jsonb)")


SHARD_RESULT_SQL = f"""(CASE WHEN jsonb_typeof(s.result) = 'object' AND jsonb_typeof({_ACTIVE}) = 'object'
    THEN jsonb_build_object('active_checks', {_keys(_ACTIVE, _ACTIVE_KEYS)} || CASE
        WHEN jsonb_typeof({_ACTIVE} -> 'endpoint_attempts') = 'array' THEN jsonb_build_object(
            'endpoint_attempts', (SELECT COALESCE(jsonb_agg(CASE WHEN jsonb_typeof(a.value) = 'object'
                                      THEN jsonb_build_object('status', a.value -> 'status') ELSE a.value END
                                      ORDER BY a.ordinality), '[]'::jsonb)
                                  FROM jsonb_array_elements({_ACTIVE} -> 'endpoint_attempts')
                                       WITH ORDINALITY a(value, ordinality)))
        ELSE '{{}}'::jsonb END)
    ELSE '{{}}'::jsonb END)"""
SHARD_OPTIONS_SQL = f"""(CASE WHEN jsonb_typeof(s.options) = 'object'
    THEN {_keys('s.options', _OPTION_KEYS)} || CASE
        WHEN jsonb_typeof(s.options -> 'custom_endpoints') = 'array' THEN jsonb_build_object(
            'custom_endpoints', (SELECT COALESCE(jsonb_agg(0), '[]'::jsonb)
                                 FROM jsonb_array_elements(s.options -> 'custom_endpoints')))
        ELSE '{{}}'::jsonb END
    ELSE '{{}}'::jsonb END)"""

PARALLEL_CHILDREN_SQL = f"""
    SELECT s.id, s.scan_role, s.shard_index, s.status, s.score, s.grade,
           s.findings_count, s.current_phase, s.progress, s.duration_seconds,
           s.executing_node_id, s.worker_id, s.execution_context,
           {SHARD_RESULT_SQL} AS result, {SHARD_OPTIONS_SQL} AS options
    FROM scans s
    WHERE s.parent_scan_id = $1
    ORDER BY s.shard_index
"""


async def scan_detail_findings(conn: Any, base_sql: str, scan_id: uuid.UUID, limit: int) -> tuple[list[Any], int]:
    """At most ``limit`` of the Scan's findings in the detail order, and how many it has."""
    if limit <= 0:
        rows: list[Any] = []
    else:
        rows = list(await conn.fetch(
            f"{base_sql.rstrip()}, f.last_seen_at DESC NULLS LAST, f.id LIMIT {int(limit) + 1}", scan_id,
        ))
        if len(rows) <= limit:
            return rows, len(rows)
        rows = rows[:limit]
    total = await conn.fetchval("SELECT count(*) FROM findings WHERE scan_id = $1", scan_id)
    return rows, int(total or 0)


__all__ = ["MAX_DETAIL_FINDINGS", "PARALLEL_CHILDREN_SQL", "scan_detail_findings"]
