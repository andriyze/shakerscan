"""``GET /credential-profiles``: bounded profile lists (2.11).

The library list counted every match with ``COUNT(*) OVER()`` and computed each row's share count
for every row an offset skipped; the per-target list had no bound at all. Now:

* legacy library page (``PostgresCredentialProfileStore.list_library``): the page's profiles are
  chosen first and only they get a share count; the total is its own count (same rows, same order);
* list/v1 (``cursor``/``count``; ``api/list_compat.py``) for both lists: keyset pages in the same
  order as the legacy list, rows in the same shape. The per-target list orders the target's own
  profiles first, then shared ones; its legacy response stays unbounded (deprecated).

Order keys are all ascending: active first is ``CASE WHEN is_active THEN 0 ELSE 1 END``, and the
per-target list's own-first key is ``CASE WHEN p.target_id = <target> THEN 0 ELSE 1 END``.
"""
from __future__ import annotations

from typing import Any, Mapping
import uuid

try:
    from list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
except ModuleNotFoundError:  # package import layout
    from ..list_contract import ListSpec, Page, SortKey, SqlParams, count_total, snapshot_time
from .credential_store import _KIND_COMPATIBLE_SQL as KIND_COMPATIBLE_SQL
from .credential_store import SHARED_TARGET_COUNT_SQL as SHARED_COUNT_SQL

INACTIVE_LAST = "(CASE WHEN p.is_active THEN 0 ELSE 1 END)"
NAME_KEY = "lower(p.name)"

LIBRARY_V1 = ListSpec(
    scope="credential_profiles",
    sorts={"name": SortKey(INACTIVE_LAST, "int", then=((NAME_KEY, "text"),))},
    default_sort="name",
    fields={"id": "p.id"},
    id_expr="p.id",
    table="credential_profiles",
)


def library_filters(*, include_inactive: bool, search: str | None, params: SqlParams) -> list[str]:
    pattern = f"%{str(search).strip()}%" if search and str(search).strip() else None
    where = [f"({params.add(bool(include_inactive))}::boolean OR p.is_active=true)"]
    if pattern is not None:
        value = params.add(pattern)
        where.append(f"(p.name ILIKE {value} OR COALESCE(p.principal_label,'') ILIKE {value})")
    return where


async def library_page(conn: Any, page: Page, *, include_inactive: bool, search: str | None) -> tuple[dict[str, Any], dict[Any, Any]]:
    """One list/v1 library page: the envelope (items are ids) and the full rows by id."""
    plan = LIBRARY_V1.plan(page, filters={"include_inactive": bool(include_inactive), "search": search})
    params = SqlParams()
    where = library_filters(include_inactive=include_inactive, search=search, params=params)
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)
    rows = await conn.fetch(
        f"""SELECT p.*, hb.allowed_capabilities, {SHARED_COUNT_SQL} AS shared_target_count,
                   {plan.keyset_select}
            FROM credential_profiles p
            LEFT JOIN credential_profile_bindings hb
              ON hb.profile_id=p.id AND hb.binding_kind='target' AND hb.binding_id=p.target_id::text
            WHERE {' AND '.join(page_where)}
            ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}""",
        *params.values,
    )
    total, total_kind = await count_total(conn, page.count, from_sql="credential_profiles p", where=where,
                                          values=count_values)
    return plan.envelope(rows, total=total, total_kind=total_kind, generated_at=generated_at), {
        row["id"]: row for row in rows
    }


def _target_spec(target_uuid: uuid.UUID) -> ListSpec:
    own_first = f"(CASE WHEN p.target_id = '{uuid.UUID(str(target_uuid))}'::uuid THEN 0 ELSE 1 END)"
    return ListSpec(
        scope="credential_profiles_for_target",
        sorts={"name": SortKey(own_first, "int", then=((INACTIVE_LAST, "int"), (NAME_KEY, "text")))},
        default_sort="name",
        fields={"id": "p.id"},
        id_expr="p.id",
    )


async def target_page(conn: Any, page: Page, *, target_kind: str, target_uuid: uuid.UUID,
                      include_inactive: bool) -> tuple[dict[str, Any], dict[Any, Any]]:
    """One list/v1 page of the profiles a target can use (the store's per-target list, bounded)."""
    spec = _target_spec(target_uuid)
    plan = spec.plan(page, filters={"target_kind": target_kind, "target_id": str(target_uuid),
                                    "include_inactive": bool(include_inactive)})
    params = SqlParams([target_kind, str(target_uuid), target_uuid, bool(include_inactive)])
    from_sql = """credential_profiles p
        LEFT JOIN credential_profile_bindings b
          ON b.profile_id=p.id AND b.binding_kind='target' AND b.binding_id=$2::text"""
    where = [
        KIND_COMPATIBLE_SQL.format(kind="$1"),
        "(p.target_id=$3 OR (b.id IS NOT NULL AND b.revoked_at IS NULL))",
        "($4::boolean OR (p.is_active=true AND (b.id IS NULL OR b.is_active=true)))",
    ]
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    generated_at = await snapshot_time(conn)
    rows = await conn.fetch(
        f"""SELECT p.*, b.allowed_capabilities, $2::text AS granted_target_id, {plan.keyset_select}
            FROM {from_sql} WHERE {' AND '.join(page_where)}
            ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}""",
        *params.values,
    )
    total, total_kind = await count_total(conn, page.count, from_sql=from_sql, where=where, values=count_values)
    return plan.envelope(rows, total=total, total_kind=total_kind, generated_at=generated_at), {
        row["id"]: row for row in rows
    }


def page_items(body: dict[str, Any], rows: Mapping[Any, Any], render: Any) -> dict[str, Any]:
    """Replace the envelope's id items with rendered rows (``render(row)``)."""
    body["items"] = [render(rows[uuid.UUID(str(item["id"]))]) for item in body["items"]]
    return body


__all__ = ["LIBRARY_V1", "library_page", "page_items", "target_page"]
