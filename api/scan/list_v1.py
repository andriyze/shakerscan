"""``GET /scans`` list/v1: keyset pages newest first and ``since=`` deltas for pollers.

The legacy limit/offset response stays for the 2.11.x line (``list_compat.py``); a request that
sends ``cursor``, ``count``, ``fields`` or ``since`` gets this envelope instead. Rows keep the
legacy list row shape (summary columns, list options, no report body), so a client switches
envelopes without re-mapping rows.

``since`` needs a change time on every scan: ``scans.updated_at`` is set by a trigger on insert
and update (``install_scan_updated_at``, run under the startup lock, a no-op once installed).
Rows written before 2.11 have none and use ``created_at``; the delta key is
``COALESCE(updated_at, created_at)``, indexed by the background builder
(``runtime/loop_scale_indexes.py``).
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time

UPDATED_AT_MIGRATION_SQL = (
    "ALTER TABLE scans ADD COLUMN updated_at TIMESTAMPTZ",
    """CREATE OR REPLACE FUNCTION scans_touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        NEW.updated_at := now();
        RETURN NEW;
    END $$""",
    """CREATE TRIGGER scans_touch_updated_at BEFORE INSERT OR UPDATE ON scans
        FOR EACH ROW EXECUTE FUNCTION scans_touch_updated_at()""",
)
#: The delta key: the last change, or the creation for a row no 2.11 engine has touched.
CHANGED_AT = "COALESCE(s.updated_at, s.created_at)"
_NEWEST = "COALESCE(s.created_at, '-infinity'::timestamptz)"

SCANS_V1 = ListSpec(
    scope="scans",
    sorts={"created_at": SortKey(_NEWEST, "datetime")},
    default_sort="-created_at",
    fields={"id": "s.id"},
    id_expr="s.id",
    since_expr=CHANGED_AT,
    table="scans",
)


async def install_scan_updated_at(conn: Any) -> None:
    """Add ``scans.updated_at`` and its trigger once; a restart reads the catalog and changes nothing.

    No default: a volatile default would rewrite the table, so existing rows keep NULL (read as
    their ``created_at``) and the trigger stamps every row written from now on.
    """
    column, function, trigger = UPDATED_AT_MIGRATION_SQL
    has_column = await conn.fetchval(
        "SELECT 1 FROM pg_attribute WHERE attrelid = 'scans'::regclass AND attname = 'updated_at' "
        "AND NOT attisdropped")
    if not has_column:
        await conn.execute(column)
    has_function = await conn.fetchval(
        "SELECT 1 FROM pg_proc WHERE proname = 'scans_touch_updated_at' "
        "AND pronamespace = 'public'::regnamespace")
    if not has_function:
        await conn.execute(function)
    has_trigger = await conn.fetchval(
        "SELECT 1 FROM pg_trigger WHERE tgrelid = 'scans'::regclass AND tgname = 'scans_touch_updated_at' "
        "AND NOT tgisinternal")
    if not has_trigger:
        await conn.execute(trigger)


async def scans_page(
    conn: Any,
    page: Page,
    *,
    columns: str,
    from_sql: str,
    where_sql: str,
    params: Sequence[Any],
    filters: Mapping[str, Any],
    row_to_item: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """One list/v1 page. ``where_sql`` is the legacy filter (``WHERE 1=1 ...``, its ``$n`` bound
    to ``params``); ``row_to_item`` the legacy row projection."""
    plan = SCANS_V1.plan(page, filters=filters)
    sql_params = SqlParams(params)
    where = [where_sql] + plan.filter_clauses(sql_params)
    count_values = sql_params.snapshot()
    page_where = where + plan.keyset_clauses(sql_params)
    generated_at = await snapshot_time(conn)  # before the page query
    rows = await conn.fetch(
        f"SELECT {columns}, {plan.select_list} FROM {from_sql} WHERE {' AND '.join(page_where)} "
        f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}",
        *sql_params.values,
    )
    total, total_kind = await count_total(conn, page.count, from_sql=from_sql, where=where,
                                          values=count_values, table=SCANS_V1.table)
    by_id = {row["__list_id"]: row for row in rows}

    def item(selected: dict[str, Any]) -> dict[str, Any]:
        row = by_id[selected["id"]]
        return row_to_item({key: row[key] for key in row.keys() if not key.startswith("__list_")})

    return plan.envelope(rows, total=total, total_kind=total_kind, transform=item, generated_at=generated_at)


__all__ = ["CHANGED_AT", "SCANS_V1", "install_scan_updated_at", "scans_page"]
