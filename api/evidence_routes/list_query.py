"""``GET /evidence/instances``: every evidence instance reachable, summaries projected in SQL (2.11).

The list returned the newest ``limit`` (at most 200) rows with no way to page further, so older
evidence was unreachable, and it sorted the whole table (no index on the order) and transferred
every row's full proof observation even when the caller asked for summaries.

* Legacy response (``evidence_instances``/``count``/``execution_enabled``): unchanged, now in the
  order of an index (``created_at DESC, id DESC``); with ``summary_only=true`` the summary is
  projected in SQL first, so the bulky observation never leaves the database.
* list/v1 (``cursor``/``count``; ``api/list_compat.py``): keyset pages newest first,
  every row reachable, rows in the summary shape (the detail endpoint serves the full
  observation).
"""
from __future__ import annotations

from typing import Any, Mapping

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time

#: The proof-observation keys a summary keeps (``_public_evidence_instance_summary`` picks the same
#: keys again after redaction; ``family_proof`` is reduced there).
SUMMARY_PROOF_KEYS = (
    "objective", "expected_signal", "falsifier", "family", "cwe", "verdict", "reason", "promotable",
    "proof_basis", "contract_id", "schema_version", "family_proof",
)
_SUMMARY_COLUMNS = (
    "id", "finding_id", "evidence_object_id", "scan_id", "target_id", "concrete_url", "object_id",
    "payload_variant", "campaign_action_id", "tool_receipt_id", "redaction_profile", "hash",
    "retention_policy", "proof_state", "evidence_strength", "created_by", "created_at", "candidate_id",
    "device_target_id", "research_episode_id", "device_agent_run_id", "contract_id", "contract_version",
    "proof_basis",
)
_KEYS = ", ".join(f"'{key}'" for key in SUMMARY_PROOF_KEYS)
PROJECTED_PROOF_SQL = f"""(CASE WHEN jsonb_typeof(e.proof_observation) = 'object' THEN
    COALESCE((SELECT jsonb_object_agg(k.key, k.value) FROM jsonb_each(e.proof_observation) k
              WHERE k.key IN ({_KEYS})), '{{}}'::jsonb)
    ELSE e.proof_observation END)"""
COMPARISON_COUNT_SQL = (
    "(CASE WHEN jsonb_typeof(e.proof_observation -> 'comparisons') = 'array' "
    "THEN jsonb_array_length(e.proof_observation -> 'comparisons') ELSE 0 END)"
)
SUMMARY_FIELDS = {name: f"e.{name}" for name in _SUMMARY_COLUMNS}
SUMMARY_FIELDS["proof_observation"] = PROJECTED_PROOF_SQL
SUMMARY_FIELDS["comparison_count"] = COMPARISON_COUNT_SQL
SUMMARY_SELECT = ", ".join(f"{expr} AS {name}" for name, expr in SUMMARY_FIELDS.items())

EVIDENCE_V1 = ListSpec(
    scope="evidence_instances",
    sorts={"created_at": SortKey("e.created_at", "datetime")},
    default_sort="-created_at",
    fields=SUMMARY_FIELDS,
    id_expr="e.id",
    since_expr=None,  # no change time: a promotion rewrites a row in place, so since= is refused
    table="evidence_instances",
)


def evidence_filters(*, finding_id: Any, tool_receipt_id: Any, params: SqlParams) -> list[str]:
    where = []
    if finding_id:
        where.append(f"e.finding_id = {params.add(finding_id)}")
    if tool_receipt_id:
        where.append(f"e.tool_receipt_id = {params.add(tool_receipt_id)}")
    return where


async def legacy_evidence(conn: Any, *, where: list[str], params: SqlParams, limit: int,
                          summary_only: bool) -> list[Any]:
    columns = SUMMARY_SELECT if summary_only else "e.*"
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return list(await conn.fetch(
        f"SELECT {columns} FROM evidence_instances e {where_sql} "
        f"ORDER BY e.created_at DESC, e.id DESC LIMIT {int(limit)}",
        *params.values,
    ))


async def evidence_page(conn: Any, page: Page, *, where: list[str], params: SqlParams,
                        filters: Mapping[str, Any], transform: Any) -> dict[str, Any]:
    plan = EVIDENCE_V1.plan(page, filters=filters)
    where = where + plan.filter_clauses(params)
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    where_sql = f"WHERE {' AND '.join(page_where)}" if page_where else ""
    generated_at = await snapshot_time(conn)
    rows = await conn.fetch(
        f"SELECT {plan.select_list} FROM evidence_instances e {where_sql} "
        f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}",
        *params.values,
    )
    total, total_kind = await count_total(conn, page.count, from_sql="evidence_instances e", where=where,
                                          values=count_values, table=EVIDENCE_V1.table)
    return plan.envelope(rows, total=total, total_kind=total_kind, generated_at=generated_at,
                         transform=transform)


__all__ = ["EVIDENCE_V1", "SUMMARY_PROOF_KEYS", "evidence_filters", "evidence_page", "legacy_evidence"]
