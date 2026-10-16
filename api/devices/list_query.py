"""``GET /devices``: the connected-device list, bounded (2.11).

The list read every row of the page with ``d.*`` and three correlated subqueries into the last
posture Scan's report, each decompressing the whole report, plus a services count; and it computed
them for every row an offset skipped. Now:

* the page's ids are chosen first (filter, order, limit/offset or keyset) and only those rows are
  enriched, the report's ``device_posture`` object read once per row;
* the legacy limit/offset response keeps its shape (``Deprecation: true``);
* list/v1 (``cursor``/``count``/``fields``/``since``, ``api/list_compat.py``): keyset pages by the
  same order (last change first, a device without a change time last, then id) with the same rows.

``device_targets`` is a view over targets and their device profiles, so its change time is not an
indexable column: a page sorts the filtered devices (a device inventory is thousands of rows, not
millions) but never enriches more than the page.
"""
from __future__ import annotations

from typing import Any, Mapping

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time

CHANGED_AT = "COALESCE(d.updated_at, '-infinity'::timestamptz)"

DEVICES_V1 = ListSpec(
    scope="devices",
    sorts={"updated_at": SortKey(CHANGED_AT, "datetime")},
    default_sort="-updated_at",
    fields={"id": "d.id"},
    id_expr="d.id",
    since_expr="d.updated_at",
)

#: The legacy row: every device column, the policy name, the open-service count and the last
#: posture Scan's completeness, decision and reachability (without its bulky attempt lists), for the
#: rows of ``{page}`` only (a subquery yielding ``id`` and ``position``), in one statement.
_ENRICH_SQL = """
SELECT d.*, p.name AS policy_name,
       (SELECT COUNT(*) FROM device_services ds WHERE ds.device_target_id=d.id AND ds.state='open')
           AS services_count,
       (posture.value->'completeness'->>'complete')::boolean AS last_posture_complete,
       posture.value->'decision'->>'decision' AS last_posture_decision,
       (posture.value->'reachability') - 'attempts' - 'nmap_host_discovery' AS last_reachability,
       page.*
FROM ({page}) page
JOIN device_targets d ON d.id = page.__page_id
LEFT JOIN device_policies p ON p.id = d.policy_id
LEFT JOIN LATERAL (
    SELECT s.result->'device_posture' AS value FROM scans s WHERE s.id = d.last_scan_id
) posture ON true
ORDER BY page.__page_position
"""


def _legacy_row(row: Any) -> dict[str, Any]:
    return {key: row[key] for key in row.keys() if not key.startswith("__")}


def device_filters(*, include_inactive: bool, device_class: str | None, search: str | None,
                   params: SqlParams) -> list[str]:
    """The list's SQL filters (the legacy ones, unchanged)."""
    where = [f"({params.add(bool(include_inactive))}::boolean = true OR d.is_active = true)"]
    if device_class:
        where.append(f"d.device_class={params.add(device_class.strip().lower())}")
    if search:
        pattern = params.add(f"%{search.strip()}%")
        where.append(f"(d.name ILIKE {pattern} OR d.primary_locator ILIKE {pattern} "
                     f"OR COALESCE(d.manufacturer,'') ILIKE {pattern})")
    return where


async def legacy_devices(conn: Any, *, where: list[str], params: SqlParams, limit: int,
                         offset: int) -> tuple[list[dict[str, Any]], int]:
    """The deprecated limit/offset page (rows as the old query returned them) and its exact total."""
    values = params.snapshot()
    # The list/v1 order: the id only breaks ties the old order left arbitrary, and a device without
    # a change time sorts last in both (the old ``updated_at DESC`` put it first).
    order = f"{CHANGED_AT} DESC, d.id DESC"
    page = (f"SELECT d.id AS __page_id, row_number() OVER (ORDER BY {order}) AS __page_position "
            f"FROM device_targets d WHERE {' AND '.join(where)} "
            f"ORDER BY {order} LIMIT {int(limit)} OFFSET {int(offset)}")
    rows = await conn.fetch(_ENRICH_SQL.format(page=page), *values)
    total = await conn.fetchval(f"SELECT COUNT(*) FROM device_targets d WHERE {' AND '.join(where)}", *values)
    return [_legacy_row(row) for row in rows], int(total or 0)


async def devices_page(conn: Any, page: Page, *, where: list[str], params: SqlParams,
                       filters: Mapping[str, Any], decode: Any) -> dict[str, Any]:
    """One list/v1 page, rows in the legacy row shape."""
    plan = DEVICES_V1.plan(page, filters=filters)
    where = where + plan.filter_clauses(params)
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)
    page_sql = (f"SELECT {plan.keyset_select}, d.id AS __page_id, "
                f"row_number() OVER (ORDER BY {plan.order_by}) AS __page_position "
                f"FROM device_targets d WHERE {' AND '.join(page_where)} "
                f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}")
    rows = await conn.fetch(_ENRICH_SQL.format(page=page_sql), *params.values)
    total, total_kind = await count_total(conn, page.count, from_sql="device_targets d", where=where,
                                          values=count_values)
    by_id = {row["id"]: row for row in rows}
    return plan.envelope(rows, total=total, total_kind=total_kind, generated_at=generated_at,
                         transform=lambda item: decode(_legacy_row(by_id[item["id"]])))


__all__ = ["DEVICES_V1", "device_filters", "devices_page", "legacy_devices"]
