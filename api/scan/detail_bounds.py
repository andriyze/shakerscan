"""Bounds on ``GET /scans/{id}`` (2.11): its report, its findings list and its parallel children.

The detail answered every persisted finding of the Scan with its evidence, however many there
were, and read every child Scan's whole report and options to compute a few contribution facts.

* Findings: at most ``findings_limit`` rows (default ``DEFAULT_DETAIL_FINDINGS``, at most
  ``MAX_DETAIL_FINDINGS``, in the same severity order, then most recently seen), with
  ``findings_total`` and ``findings_truncated``; the complete set stays available from
  ``GET /findings?scan_id=``. ``findings_limit=0`` leaves them out (a poller that only needs the
  status). ``verified_only`` is applied in SQL before the limit: a row passes when its stored
  verdict is ``exploited`` or this run's report proves its fingerprint; the exact merged verdict
  then decides, so a page can hold fewer rows than the limit, never rows the filter excludes.
* Report: ``include_result=false`` does not transfer or decode the report. Only the parts the
  answer still needs are selected: the execution explanation's inputs (``coverage``,
  ``canonical_action_execution``, ``parallel.canonical_action_execution``) and, when findings are
  returned, the report's ``findings`` (their scan-time proof reaches the persisted rows).
* Children: only the report and option keys ``_parallel_shard_contribution`` reads are
  transferred. The two potentially long lists are reduced to what it counts: each endpoint attempt
  to its status, each assigned endpoint to a placeholder (only their number is used).
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Optional
import uuid

from fastapi import Query

from .finding_verification_overrides import matching_verification_override, scan_result_verification_overrides

try:
    from list_compat import direct
    from scan_finding_proof import SCAN_DETAIL_FINDINGS_SQL, project_scan_finding_proof
    from scan_verification_state import scan_time_verification_fields
except ModuleNotFoundError:  # package import in host-side tests
    from ..list_compat import direct
    from ..scan_finding_proof import SCAN_DETAIL_FINDINGS_SQL, project_scan_finding_proof
    from ..scan_verification_state import scan_time_verification_fields

MAX_DETAIL_FINDINGS = 5000
#: Rows a detail carries unless it asks for more: enough to link a report's findings to their
#: records on a typical Scan; the Findings list (``?scan_id=``) pages the rest.
DEFAULT_DETAIL_FINDINGS = 500

FINDINGS_LIMIT_QUERY = Query(
    DEFAULT_DETAIL_FINDINGS, ge=0, le=MAX_DETAIL_FINDINGS,
    description="persisted findings to include (0 leaves them out); findings_total says how many there are",
)
INCLUDE_RESULT_QUERY = Query(True, description="false leaves the report body out (result is null)")

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


_REPORT_SUMMARY_KEYS = ("canonical_action_execution", "coverage")
_PARALLEL_EXECUTION = "s.result -> 'parallel' -> 'canonical_action_execution'"


def report_select_sql(*, include_result: bool, with_findings: bool) -> str:
    """The detail's ``result`` column: the report, or only the parts the answer reads from it."""
    if include_result:
        return "s.result"
    keys = _REPORT_SUMMARY_KEYS + (("findings",) if with_findings else ())
    return f"""(CASE WHEN jsonb_typeof(s.result) = 'object' THEN {_keys('s.result', keys)} || CASE
        WHEN jsonb_typeof(s.result -> 'parallel') = 'object' AND {_PARALLEL_EXECUTION} IS NOT NULL
        THEN jsonb_build_object('parallel', jsonb_build_object('canonical_action_execution', {_PARALLEL_EXECUTION}))
        ELSE '{{}}'::jsonb END END)"""


_SCAN_COLUMNS: Optional[tuple[str, ...]] = None


async def _scan_columns(conn: Any) -> Optional[tuple[str, ...]]:
    """The scans table's columns (read once per process), or None when the catalog says nothing."""
    global _SCAN_COLUMNS
    if _SCAN_COLUMNS is None:
        rows = await conn.fetch(
            "SELECT attname FROM pg_attribute WHERE attrelid = 'scans'::regclass AND attnum > 0 "
            "AND NOT attisdropped ORDER BY attnum")
        names = tuple(str(row["attname"]) for row in rows or ())
        if not names:
            return None
        _SCAN_COLUMNS = names
    return _SCAN_COLUMNS


async def fetch_scan_detail_row(conn: Any, scan_id: uuid.UUID, *, include_result: bool, with_findings: bool) -> Any:
    """The Scan row of the detail (with its target names), its report as ``report_select_sql``."""
    columns = await _scan_columns(conn) if not include_result else None
    if columns is None:
        select = "s.*"  # the whole row (the result is dropped after the read when not wanted)
    else:
        report = report_select_sql(include_result=False, with_findings=with_findings)
        select = ", ".join(report + " AS result" if name == "result" else f's."{name}"' for name in columns)
    return await conn.fetchrow(f"""
        SELECT {select},
               COALESCE(t.name, ait.name) as target_name,
               ait.target_type as ai_target_type
        FROM scans s
        LEFT JOIN targets t ON s.target_id = t.id
        LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
        WHERE s.id = $1
    """, scan_id)


def detail_params(findings_limit: Any, include_result: Any) -> tuple[int, bool]:
    """The detail's paging parameters, whether the route or a direct caller passed them."""
    return int(direct(findings_limit)), bool(direct(include_result))


_SCAN_FILTER = "WHERE f.scan_id = $1"
_VERIFIED_FILTER = "(f.last_verification_verdict = 'exploited' OR f.fingerprint = ANY($2::text[]))"


async def scan_detail_findings(
    conn: Any, base_sql: str, scan_id: uuid.UUID, limit: int, *, proven_fingerprints: Optional[list[str]] = None,
) -> tuple[list[Any], int]:
    """At most ``limit`` of the Scan's findings in the detail order, and how many it has.

    With ``proven_fingerprints`` only rows that can be verified pass (verified_only).
    """
    assert _SCAN_FILTER in base_sql
    args: list[Any] = [scan_id]
    where = "scan_id = $1"
    if proven_fingerprints is not None:
        base_sql = base_sql.replace(_SCAN_FILTER, f"{_SCAN_FILTER} AND {_VERIFIED_FILTER}", 1)
        where = f"f.{where} AND {_VERIFIED_FILTER}"
        args.append(proven_fingerprints)
    if limit <= 0:
        rows: list[Any] = []
    else:
        rows = list(await conn.fetch(
            f"{base_sql.rstrip()}, f.last_seen_at DESC NULLS LAST, f.id LIMIT {int(limit) + 1}", *args,
        ))
        if len(rows) <= limit:
            return rows, len(rows)
        rows = rows[:limit]
    total = await conn.fetchval(f"SELECT count(*) FROM findings f WHERE {where}", *args)
    return rows, int(total or 0)


async def read_detail_findings(
    conn: Any, scan_id: uuid.UUID, report: Any, *, limit: int, verified_only: bool,
    project: Callable[[dict[str, Any]], dict[str, Any]], identities: Callable[[dict[str, Any]], Iterable[str]],
) -> tuple[list[dict[str, Any]], int, bool]:
    """The detail's persisted findings with this run's scan-time proof merged and projected.

    Returns ``(findings, findings_total, findings_truncated)``. ``report`` is the decoded report
    (or its findings part); its findings gain the canonical projection in place.
    """
    overrides = scan_result_verification_overrides(report, scan_time_verification_fields)
    proven = None
    if verified_only:
        # A stale stored verdict must not hide a row this run proved: its fingerprint passes too.
        proven = sorted({key[0] for key, fields in overrides.items()
                         if fields.get("last_verification_verdict") == "exploited" and key[0]})
    rows, total = await scan_detail_findings(conn, SCAN_DETAIL_FINDINGS_SQL, scan_id, limit,
                                             proven_fingerprints=proven)
    merged = []
    for row in rows:
        finding = dict(row)
        finding.update(matching_verification_override(overrides, finding))
        if verified_only and finding.get("last_verification_verdict") != "exploited":
            continue
        merged.append(finding)
    findings = project_scan_finding_proof(report, merged, project=project, identities=identities)
    return findings, total, len(rows) < total


__all__ = [
    "DEFAULT_DETAIL_FINDINGS",
    "FINDINGS_LIMIT_QUERY",
    "INCLUDE_RESULT_QUERY",
    "MAX_DETAIL_FINDINGS",
    "PARALLEL_CHILDREN_SQL",
    "detail_params",
    "fetch_scan_detail_row",
    "read_detail_findings",
    "report_select_sql",
    "scan_detail_findings",
]
