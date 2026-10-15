"""``GET /targets/grouped``: targets grouped by root domain, paged over groups (list/v1).

The legacy response (every group with every target, sorted in Python) stays for the 2.11.x line.
list/v1 pages the groups themselves: the group summary (counts, findings total, the root's score
and last scan, earliest creation) is aggregated in SQL over the filtered targets, keyset-paged on
the chosen sort, and only the page's groups are read in detail, with at most ``member_limit``
subdomains each (``subdomain_count`` keeps the true number). Group values follow the legacy
definitions exactly: the root target is the last ``is_root`` row in URL order, a missing root
domain groups as ``unknown``, and the group's ASM coverage rolls up every member, not only the
members on the page.

Tie order differs from legacy only where legacy kept ascending domain order for a descending
sort; list/v1 breaks ties by domain in the sort's direction, as every keyset list does.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

try:
    from list_contract import ListPlan, ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListPlan, ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time

DEFAULT_MEMBER_LIMIT = 20
MAX_MEMBER_LIMIT = 200
GROUP_KEY = "COALESCE(NULLIF(LEFT(t.root_domain, 253), ''), 'unknown')"
_EARLIEST = "'0001-01-01T00:00:00+00:00'::timestamptz"

_GROUP_FIELDS = {
    "root_domain": "g.root_domain",
    "subdomain_count": "g.subdomain_count",
    "total_count": "g.total_count",
    "total_findings": "g.total_findings",
    "best_score": "g.best_score",
    "latest_scan": "g.latest_scan",
    "earliest_created": "g.earliest_created",
    "root_id": "g.root_id",
}


def _spec(descending: bool) -> ListSpec:
    # Legacy sorts a missing score last in both directions; the sort expression must be NOT NULL.
    score = "COALESCE(g.best_score, -1)" if descending else "COALESCE(g.best_score, 101)"
    return ListSpec(
        scope="targets.grouped",
        sorts={
            "root_domain": SortKey('lower(g.root_domain) COLLATE "C"', "text"),
            "last_scanned_at": SortKey(f"COALESCE(g.latest_scan, {_EARLIEST})", "datetime"),
            "active_findings_count": SortKey("g.total_findings", "int"),
            "last_score": SortKey(score, "int"),
            "created_at": SortKey(f"COALESCE(g.earliest_created, {_EARLIEST})", "datetime"),
        },
        default_sort="root_domain",
        fields=_GROUP_FIELDS,
        id_expr='g.root_domain COLLATE "C"',
        id_kind="text",
    )


GROUPED_ASC = _spec(False)
GROUPED_DESC = _spec(True)


def filter_clauses(params: SqlParams, *, include_inactive: bool, search: str | None,
                   discovery_source: str | None, grade: str | None,
                   has_findings: bool | None) -> list[str]:
    """The legacy grouped filters, unchanged in meaning."""
    where: list[str] = []
    if not include_inactive:
        where.append("t.is_active = true")
    # Model Intake subjects have their own workflow; host rows are assets, not web targets.
    if discovery_source != "model-intake":
        where.append("COALESCE(t.discovery_source, 'manual') NOT IN ('model-intake','host')")
    if search:
        term = params.add(search)
        where.append(f"(t.url ILIKE '%' || {term} || '%' OR t.name ILIKE '%' || {term} || '%' "
                     f"OR t.root_domain ILIKE '%' || {term} || '%')")
    if discovery_source:
        where.append(f"t.discovery_source = {params.add(discovery_source)}")
    if grade:
        where.append(f"UPPER(t.last_grade) = UPPER({params.add(grade)})")
    if has_findings is not None:
        where.append("t.active_findings_count > 0" if has_findings else "t.active_findings_count = 0")
    return where or ["true"]


def groups_sql(where: Sequence[str]) -> str:
    """One row per domain group over the filtered targets (the legacy group values)."""
    return f"""(
        WITH filtered AS (
            SELECT t.id, t.url, t.is_root, t.active_findings_count, t.last_score, t.last_scanned_at,
                   t.created_at, {GROUP_KEY} AS group_key
            FROM targets t WHERE {' AND '.join(where)}
        ),
        roots AS (
            SELECT DISTINCT ON (group_key) group_key, id, active_findings_count, last_score,
                   last_scanned_at, created_at
            FROM filtered WHERE is_root
            ORDER BY group_key, url DESC
        ),
        members AS (
            SELECT group_key,
                   COUNT(*) FILTER (WHERE NOT is_root) AS subdomain_count,
                   COALESCE(SUM(active_findings_count) FILTER (WHERE NOT is_root), 0) AS sub_findings,
                   MIN(created_at) FILTER (WHERE NOT is_root) AS sub_earliest
            FROM filtered GROUP BY group_key
        )
        SELECT m.group_key AS root_domain, r.id AS root_id,
               m.subdomain_count::bigint AS subdomain_count,
               (m.subdomain_count + CASE WHEN r.id IS NULL THEN 0 ELSE 1 END)::bigint AS total_count,
               (COALESCE(r.active_findings_count, 0) + m.sub_findings)::bigint AS total_findings,
               r.last_score AS best_score,
               r.last_scanned_at AS latest_scan,
               CASE WHEN r.id IS NOT NULL THEN r.created_at ELSE m.sub_earliest END AS earliest_created
        FROM members m LEFT JOIN roots r ON r.group_key = m.group_key
    ) g"""


# --- Per-target enrichment shared with the legacy response -------------------------------------

# AI Investigator trust tiers per target, counted per set (one grouped read each) rather than
# with two correlated counts per target: verified = active findings an investigator exploited,
# suspected = open web candidates.
INVESTIGATOR_VERIFIED_SQL = """
    SELECT target_id, COUNT(*) AS n
    FROM findings
    WHERE target_id = ANY($1::uuid[]) AND status='active'
      AND last_verification_verdict='exploited'
      AND tool IN ('autonomous_workflow','bola')
    GROUP BY target_id
"""
INVESTIGATOR_SUSPECTED_SQL = """
    SELECT target_id, COUNT(*) AS n
    FROM investigation_candidates
    WHERE target_id = ANY($1::uuid[]) AND plane='web'
      AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
    GROUP BY target_id
"""

# Per-target ASM coverage over the targets ``ids_sql`` selects. The latest attempt per live
# endpoint is read with a per-endpoint LIMIT 1 (idx_asm_endpoint_attempts_latest) rather than
# DISTINCT ON over every attempt; the result is the legacy one.
def asm_coverage_sql(ids_sql: str) -> str:
    return f"""
    WITH inventory AS (
        SELECT target_id,
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE test_status <> 'gone') AS testable,
               COUNT(*) FILTER (WHERE test_status = 'tested') AS status_tested
        FROM target_endpoints
        WHERE target_id IN ({ids_sql})
        GROUP BY target_id
    ),
    latest_attempt AS (
        SELECT te.target_id,
               CASE
                   WHEN la.status = 'completed'
                    AND lower(COALESCE(la.scanner_telemetry_json->>'per_endpoint_telemetry', 'false')) <> 'true'
                   THEN 'partial'
                   ELSE la.status
               END AS status
        FROM target_endpoints te
        CROSS JOIN LATERAL (
            SELECT aea.status, aea.scanner_telemetry_json
            FROM asm_endpoint_attempts aea
            WHERE aea.endpoint_id = te.id
            ORDER BY COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
            LIMIT 1
        ) la
        WHERE te.target_id IN ({ids_sql}) AND te.test_status <> 'gone'
    ),
    attempts AS (
        SELECT target_id,
               COUNT(*) AS attempted,
               COUNT(*) FILTER (WHERE status = 'completed') AS completed
        FROM latest_attempt
        GROUP BY target_id
    )
    SELECT i.target_id, i.total, i.testable, i.status_tested,
           COALESCE(a.attempted, 0) AS attempted,
           COALESCE(a.completed, 0) AS attempt_completed
    FROM inventory i
    LEFT JOIN attempts a ON a.target_id = i.target_id
"""


ASM_COVERAGE_SQL = asm_coverage_sql("SELECT unnest($1::uuid[])")


async def investigator_counts(conn: Any, target_ids: Sequence[Any]) -> dict[str, dict[str, int]]:
    if not target_ids:
        return {}
    ids = list(target_ids)
    verified = {str(row['target_id']): int(row['n'] or 0)
                for row in await conn.fetch(INVESTIGATOR_VERIFIED_SQL, ids)}
    suspected = {str(row['target_id']): int(row['n'] or 0)
                 for row in await conn.fetch(INVESTIGATOR_SUSPECTED_SQL, ids)}
    return {
        str(target_id): {
            'investigator_verified_count': verified.get(str(target_id), 0),
            'investigator_suspected_count': suspected.get(str(target_id), 0),
        }
        for target_id in ids
    }


async def asm_coverage_by_target(conn: Any, target_ids: Sequence[Any]) -> dict[str, dict[str, Any]]:
    if not target_ids:
        return {}
    coverage: dict[str, dict[str, Any]] = {}
    for ar in await conn.fetch(ASM_COVERAGE_SQL, list(target_ids)):
        total = int(ar['total'] or 0)
        testable = int(ar['testable'] or total)
        attempted = int(ar['attempted'] or 0)
        tested = int(ar['attempt_completed'] if attempted > 0 else (ar['status_tested'] or 0))
        denominator = testable
        coverage[str(ar['target_id'])] = {
            'total': total,
            'tested': tested,
            'untested': max(0, denominator - tested),
            'coverage': round(tested / denominator, 4) if denominator else 0.0,
            'coverage_basis': 'attempt_ledger' if attempted > 0 else 'endpoint_status',
            'attempted': attempted,
        }
    return coverage


def group_asm_rollup(coverages: Sequence[Mapping[str, Any] | None]) -> dict[str, Any] | None:
    cov_total = sum((item or {}).get('total', 0) for item in coverages)
    cov_tested = sum((item or {}).get('tested', 0) for item in coverages)
    if not cov_total:
        return None
    return {
        'total': cov_total,
        'tested': cov_tested,
        'untested': cov_total - cov_tested,
        'coverage': round(cov_tested / cov_total, 4),
    }


# --- list/v1 -----------------------------------------------------------------------------------


def plan_for(page: Page, filters: Mapping[str, Any]) -> ListPlan:
    descending = (page.sort or "").startswith("-")
    return (GROUPED_DESC if descending else GROUPED_ASC).plan(page, filters=filters)


async def grouped_page(
    conn: Any,
    page: Page,
    *,
    filters: Mapping[str, Any],
    member_limit: int,
    member_columns: str,
    public_row: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    """One list/v1 page of domain groups. ``member_columns`` is the legacy target projection."""
    plan = plan_for(page, filters)
    params = SqlParams()
    where = filter_clauses(
        params, include_inactive=bool(filters.get("include_inactive")), search=filters.get("search"),
        discovery_source=filters.get("discovery_source"), grade=filters.get("grade"),
        has_findings=filters.get("has_findings"),
    )
    filter_values = params.snapshot()
    groups_from = groups_sql(where)
    page_where = plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)  # before the page query
    rows = await conn.fetch(
        f"SELECT {plan.select_list} FROM {groups_from}"
        f"{' WHERE ' + ' AND '.join(page_where) if page_where else ''} "
        f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}",
        *params.values,
    )
    total, total_kind = await count_total(conn, page.count, from_sql=groups_from, values=filter_values)
    page_rows = list(rows[: page.limit])
    keys = [row["root_domain"] for row in page_rows]
    root_ids = [row["root_id"] for row in page_rows if row["root_id"] is not None]

    members_by_group: dict[str, list[Any]] = {key: [] for key in keys}
    roots: dict[str, Any] = {}
    group_rollups: dict[str, dict[str, int]] = {}
    if keys:
        member_params = SqlParams(filter_values)
        keys_ref = member_params.add(keys)
        roots_ref = member_params.add(root_ids)
        limit_ref = member_params.add(member_limit)
        member_rows = await conn.fetch(f"""
            SELECT * FROM (
                SELECT {member_columns}, {GROUP_KEY} AS group_key,
                       row_number() OVER (PARTITION BY {GROUP_KEY}, t.is_root ORDER BY t.url) AS member_rank
                FROM targets t
                WHERE {' AND '.join(where)} AND {GROUP_KEY} = ANY({keys_ref}::text[])
                  AND (NOT t.is_root OR t.id = ANY({roots_ref}::uuid[]))
            ) ranked
            WHERE is_root OR member_rank <= {limit_ref}
            ORDER BY group_key, url
        """, *member_params.values)
        for row in member_rows:
            if row["is_root"]:
                roots[row["group_key"]] = row
            else:
                members_by_group[row["group_key"]].append(row)
        # The group-level ASM rollup covers every member, not only those on the page; it is
        # summed in SQL, one row per group.
        rollup_params = SqlParams(filter_values)
        rollup_keys = rollup_params.add(keys)
        rollup_roots = rollup_params.add(root_ids)
        members_sql = (f"SELECT t.id FROM targets t WHERE {' AND '.join(where)} "
                       f"AND {GROUP_KEY} = ANY({rollup_keys}::text[]) "
                       f"AND (NOT t.is_root OR t.id = ANY({rollup_roots}::uuid[]))")
        for row in await conn.fetch(f"""
            WITH per_target AS ({asm_coverage_sql(members_sql)})
            SELECT {GROUP_KEY} AS group_key,
                   SUM(p.total)::bigint AS total,
                   SUM(CASE WHEN p.attempted > 0 THEN p.attempt_completed ELSE p.status_tested END)::bigint AS tested
            FROM per_target p JOIN targets t ON t.id = p.target_id
            GROUP BY 1
        """, *rollup_params.values):
            group_rollups[row["group_key"]] = {"total": int(row["total"] or 0), "tested": int(row["tested"] or 0)}

    shown_ids = [row["id"] for row in roots.values()] + [
        row["id"] for rows_ in members_by_group.values() for row in rows_
    ]
    asm = await asm_coverage_by_target(conn, shown_ids)
    investigator = await investigator_counts(conn, shown_ids)

    def target_item(row: Any) -> dict[str, Any]:
        data = public_row({key: row[key] for key in row.keys() if key not in ("group_key", "member_rank")})
        data['asm_coverage'] = asm.get(str(data['id']))
        data.update(investigator.get(str(data['id']), {
            'investigator_verified_count': 0,
            'investigator_suspected_count': 0,
        }))
        return data

    def group_item(item: dict[str, Any]) -> dict[str, Any]:
        key = item["root_domain"]
        root = roots.get(key)
        subdomains = [target_item(row) for row in members_by_group.get(key, [])]
        group = {
            "root_domain": key,
            "root_target": target_item(root) if root is not None else None,
            "subdomains": subdomains,
            "subdomain_count": int(item["subdomain_count"]),
            "subdomains_truncated": int(item["subdomain_count"]) > len(subdomains),
            "total_count": int(item["total_count"]),
            "total_findings": int(item["total_findings"]),
            "best_score": item["best_score"],
            "latest_scan": item["latest_scan"].isoformat() if item["latest_scan"] is not None else None,
            "earliest_created": (item["earliest_created"].isoformat()
                                 if item["earliest_created"] is not None else None),
            "asm_coverage": group_asm_rollup([group_rollups.get(key)]),
        }
        return group

    return plan.envelope(rows, total=total, total_kind=total_kind, transform=group_item,
                         generated_at=generated_at)


__all__ = [
    "ASM_COVERAGE_SQL",
    "asm_coverage_sql",
    "DEFAULT_MEMBER_LIMIT",
    "GROUPED_ASC",
    "GROUPED_DESC",
    "INVESTIGATOR_SUSPECTED_SQL",
    "INVESTIGATOR_VERIFIED_SQL",
    "MAX_MEMBER_LIMIT",
    "asm_coverage_by_target",
    "filter_clauses",
    "group_asm_rollup",
    "grouped_page",
    "groups_sql",
    "investigator_counts",
    "plan_for",
]
