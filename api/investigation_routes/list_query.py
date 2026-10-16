"""``GET /investigation/candidates``: bounded candidate lists (2.11).

The list counted every match with ``COUNT(*) OVER()`` (materialising all of them) and computed a
per-row observation count for every row an offset skipped. Now the page's rows are chosen first
and only they are enriched; the total is its own filter-only count.

* Legacy limit/offset response: unchanged rows (``Deprecation: true``).
* list/v1 (``cursor``/``count``/``fields``/``since``; ``api/list_compat.py``): keyset pages by last
  seen, newest first, of summary rows: the record without its evidence references and verifier
  context (the detail endpoint serves both), with ``evidence_ref_count`` instead.
"""
from __future__ import annotations

from typing import Any, Mapping

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time

#: Summary columns of a list/v1 row (the heavy JSON stays on the detail endpoint).
SUMMARY_FIELDS = {
    name: f"c.{name}" for name in (
        "id", "plane", "target_id", "device_target_id", "research_episode_id", "agent_hunt_run_id",
        "device_agent_run_id", "hunt_run_id", "family", "canonical_locus", "title", "claim",
        "claimed_severity", "verifier_contract_id", "source_kind", "fingerprint", "status",
        "latest_verification_id", "created_by", "first_seen_at", "last_seen_at", "created_at",
        "updated_at",
    )
}
SUMMARY_FIELDS["evidence_ref_count"] = (
    "(CASE WHEN jsonb_typeof(c.evidence_refs) = 'array' THEN jsonb_array_length(c.evidence_refs) ELSE 0 END)"
)
SUMMARY_FIELDS["observation_count"] = (
    "(SELECT COUNT(*) FROM investigation_candidate_observations o WHERE o.candidate_id = c.id)"
)

CANDIDATES_V1 = ListSpec(
    scope="investigation_candidates",
    sorts={"last_seen_at": SortKey("c.last_seen_at", "datetime")},
    default_sort="-last_seen_at",
    fields=SUMMARY_FIELDS,
    id_expr="c.id",
    since_expr="c.updated_at",
    table="investigation_candidates",
)


def candidate_filters(*, plane: str | None, target_id: Any, device_target_id: Any, status: str | None,
                      params: SqlParams) -> list[str]:
    where = []
    if plane:
        where.append(f"c.plane = {params.add(plane)}")
    if target_id:
        where.append(f"c.target_id = {params.add(target_id)}")
    if device_target_id:
        where.append(f"c.device_target_id = {params.add(device_target_id)}")
    if status:
        where.append(f"c.status = {params.add(status)}")
    return where or ["true"]


async def legacy_candidates(conn: Any, *, where: list[str], params: SqlParams, limit: int,
                            offset: int) -> tuple[list[Any], int]:
    """The deprecated page: ``c.*`` plus the observation count, for the page's rows only."""
    values = params.snapshot()
    where_sql = " AND ".join(where)
    rows = await conn.fetch(
        f"""SELECT c.*,
                   (SELECT COUNT(*) FROM investigation_candidate_observations o
                    WHERE o.candidate_id = c.id) AS observation_count
            FROM (SELECT c.id, c.last_seen_at FROM investigation_candidates c WHERE {where_sql}
                  ORDER BY c.last_seen_at DESC, c.id DESC LIMIT {int(limit)} OFFSET {int(offset)}) page
            JOIN investigation_candidates c ON c.id = page.id
            ORDER BY page.last_seen_at DESC, page.id DESC""",
        *values,
    )
    total = await conn.fetchval(f"SELECT COUNT(*) FROM investigation_candidates c WHERE {where_sql}", *values)
    return list(rows), int(total or 0)


async def candidates_page(conn: Any, page: Page, *, where: list[str], params: SqlParams,
                          filters: Mapping[str, Any], transform: Any) -> dict[str, Any]:
    plan = CANDIDATES_V1.plan(page, filters=filters)
    where = where + plan.filter_clauses(params)
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)
    rows = await conn.fetch(
        f"SELECT {plan.select_list} FROM investigation_candidates c WHERE {' AND '.join(page_where)} "
        f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}",
        *params.values,
    )
    filtered = [clause for clause in where if clause != "true"]
    total, total_kind = await count_total(conn, page.count, from_sql="investigation_candidates c",
                                          where=filtered, values=count_values,
                                          table=CANDIDATES_V1.table)
    return plan.envelope(rows, total=total, total_kind=total_kind, generated_at=generated_at,
                         transform=transform)


__all__ = ["CANDIDATES_V1", "candidate_filters", "candidates_page", "legacy_candidates"]
