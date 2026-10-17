"""The shared list contract: bounded pages, opaque keyset cursors and honest counts.

Every new or reworked list endpoint uses this module, so a list can never be unbounded by
omission and every list answers the same way. The previous ``limit``/``offset`` responses stay
as they are for one minor line (``LEGACY_LIST_CONTRACT`` in ``public_api_contract.py``).

Request (``page_params``, or the ``PageDep`` annotation, as a FastAPI dependency)::

    ?limit=50          1..200, default 50; anything above 200 is a 422, never a silent clamp
    &cursor=<opaque>   the previous response's ``next_cursor``; bound to scope+filters+sort
    &sort=-created_at  one declared sort key, ``-`` for descending; the spec's default otherwise
    &fields=id,name    a subset of the declared fields; the spec's default projection otherwise
    &count=none        none | estimate | exact (exact stops at 10,000 and says "at_least")
    &since=<ISO-8601>  rows whose ``since_expr`` (normally ``updated_at``) is >= since

Response (``ListPlan.envelope``)::

    {"items": [...], "next_cursor": "..." | null, "has_more": bool,
     "total": int (omitted when count=none), "total_kind": "none|estimate|exact|at_least",
     "generated_at": "2026-10-14T12:00:00.000000+00:00"}

``total_kind == "at_least"`` means there are more than ``EXACT_COUNT_CAP`` matches and
``total`` is the cap: render it as "10,000+". ``estimate`` comes from planner statistics and is
for "about N" displays only. ``generated_at`` is the value a poller passes back as ``since``;
take it from ``snapshot_time(conn)`` BEFORE the page query (see there), never from the API clock
after it, or a delta poll can miss rows written by transactions that were still open.

Applying it to an endpoint::

    from list_contract import ListSpec, PageDep, SortKey, SqlParams, count_total

    SCANS = ListSpec(
        scope="scans",                                 # unique per endpoint
        sorts={
            "created_at": SortKey("s.created_at", "datetime"),
            "status": SortKey("s.status", "text"),
        },
        default_sort="-created_at",
        fields={"id": "s.id", "status": "s.status", "created_at": "s.created_at"},
        id_expr="s.id",                                 # unique tiebreaker, same direction
        since_expr="s.updated_at",                      # None: the endpoint refuses ``since``
        table="scans",                                  # unfiltered estimate from pg_class
    )

    @router.get("/scans/page")
    async def list_scans(page: PageDep, status: str | None = None):
        plan = SCANS.plan(page, filters={"status": status})   # 400 on a bad sort/fields/cursor
        params = SqlParams()
        where = ["NOT s.hidden"]
        if status:
            where.append(f"s.status = {params.add(status)}")
        where += plan.filter_clauses(params)            # ``since``: part of the filter
        count_values = params.snapshot()                # count query: filters only
        page_where = where + plan.keyset_clauses(params)
        async with pool.acquire() as conn:
            generated_at = await snapshot_time(conn)   # before the page query
            rows = await conn.fetch(
                f"SELECT {plan.select_list} FROM scans s WHERE {' AND '.join(page_where)} "
                f"ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}",
                *params.values,
            )
            total, kind = await count_total(
                conn, page.count, from_sql="scans s", where=where, values=count_values,
                table=SCANS.table,
            )
        return plan.envelope(rows, total=total, total_kind=kind, generated_at=generated_at)

Rules the helpers rely on:

* Every value that reaches SQL goes through ``SqlParams.add``. Sort and field names come from
  the spec, never from the request; the request only chooses among them.
* Filters are added before the keyset clause, so ``params.snapshot()`` taken between the two
  is exactly the count query's argument list.
* A sort expression must be NOT NULL (wrap a nullable column in ``COALESCE``) and should have a
  btree index over ``(sort expression, id)`` so the keyset clause is an index range scan. A
  ``SortKey`` may add further keys (``then=((expr, kind), ...)``, same direction, before the id):
  the cursor carries every key and the index is ``(expr, then..., id)``.
* A ``text`` sort key is ordered by its first ``max_chars`` (default 200) characters,
  ``left(expr, max_chars)``, everywhere: in ``order_by``, the keyset clause and the cursor. That
  bound keeps every cursor the server issues within the accepted cursor length whatever the
  column holds; index ``left(expr, max_chars)`` (plus id), not the bare column.
* Pass every filter that changes the result to ``plan(filters=...)``: a cursor issued for one
  filter set is refused (400 ``cursor_mismatch``) under another instead of skipping rows.
* List projections never include the heavy record bodies in ``LIST_HEAVY_FIELDS``; a spec that
  declares one fails at import time. Serve those from the detail endpoint.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
import threading
from typing import Annotated, Any, Callable, Literal, Mapping, Sequence
import uuid

from fastapi import Depends, HTTPException, Query

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
EXACT_COUNT_CAP = 10_000
CURSOR_MAX_LENGTH = 2048
MAX_FIELDS = 64
#: Worst case for a text key: every character a 6-character JSON escape still fits the cursor.
MAX_TEXT_SORT_CHARS = 200
#: ``snapshot_time``: clock margin, and the oldest open transaction it waits for.
SNAPSHOT_MARGIN = timedelta(seconds=2)
SNAPSHOT_MAX_LOOKBACK = timedelta(minutes=10)
LIST_CONTRACT_VERSION = "list/v1"

#: Record bodies a list view never returns; the detail endpoint serves them.
LIST_HEAVY_FIELDS = frozenset({
    "evidence", "request", "response", "result", "context_pack", "configuration_json",
    "replay_spec", "scan_job_payload",
})

CountMode = Literal["none", "estimate", "exact"]
TotalKind = Literal["none", "estimate", "exact", "at_least"]
SortKind = Literal["datetime", "int", "float", "numeric", "text", "uuid"]

_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SORT = re.compile(r"^-?[a-z][a-z0-9_]{0,63}$")
_SORT_COLUMN = "__list_sort"
_ID_COLUMN = "__list_id"
_CURSOR_PURPOSE = "list-cursor/v1"


# --- The request -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Page:
    """One list request's paging parameters, already shape-validated."""

    limit: int = DEFAULT_LIMIT
    cursor: str | None = None
    sort: str | None = None
    fields: tuple[str, ...] | None = None
    count: CountMode = "none"
    since: datetime | None = None


def _bad_request(error: str, message: str) -> HTTPException:
    return HTTPException(status_code=400, detail={"error": error, "message": message})


def page_params(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Page size, 1..200"),
    cursor: str | None = Query(
        None, max_length=CURSOR_MAX_LENGTH, description="next_cursor from the previous page",
    ),
    sort: str | None = Query(None, max_length=65, description="sort key, '-' prefix descends"),
    fields: str | None = Query(None, max_length=2048, description="comma-separated projection"),
    count: CountMode = Query("none", description="none | estimate | exact (capped at 10,000)"),
    since: datetime | None = Query(None, description="only rows updated at or after this time"),
) -> Page:
    """The FastAPI dependency behind ``PageDep``."""
    if sort is not None and not _SORT.fullmatch(sort):
        raise _bad_request("invalid_sort", "sort must be a declared key, optionally prefixed with '-'")
    parsed_fields: tuple[str, ...] | None = None
    if fields is not None:
        names = [name.strip() for name in fields.split(",") if name.strip()]
        if not names or len(names) > MAX_FIELDS or not all(_NAME.fullmatch(n) for n in names):
            raise _bad_request("invalid_fields", "fields must be a comma-separated list of field names")
        parsed_fields = tuple(dict.fromkeys(names))
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return Page(limit=limit, cursor=cursor or None, sort=sort, fields=parsed_fields,
                count=count, since=since)


PageDep = Annotated[Page, Depends(page_params)]


# --- The endpoint declaration ------------------------------------------------------------------


@dataclass(frozen=True)
class SortKey:
    """A declared sort: a NOT NULL SQL expression and the type its cursor value decodes to.

    ``then`` adds further NOT NULL ``(expression, kind)`` keys, ordered in the same direction
    before the id tiebreaker (severity, then last seen); the cursor carries every key.
    """

    expr: str
    kind: SortKind
    then: tuple[tuple[str, SortKind], ...] = ()
    max_chars: int = 200

    def __post_init__(self) -> None:
        kinds = [self.kind, *(kind for _expr, kind in self.then)]
        if "text" in kinds and not 1 <= self.max_chars <= MAX_TEXT_SORT_CHARS:
            raise ValueError(f"a text sort key is bounded to 1..{MAX_TEXT_SORT_CHARS} characters")

    def _bounded(self, expr: str, kind: SortKind) -> str:
        return f"left(({expr}), {int(self.max_chars)})" if kind == "text" else expr

    @property
    def sql(self) -> str:
        """The ordering expression: text keys are bounded so their cursor always fits."""
        return self._bounded(self.expr, self.kind)

    @property
    def columns(self) -> tuple[tuple[str, SortKind], ...]:
        """Every ordering expression (bounded like ``sql``) with its kind, before the id."""
        return ((self.sql, self.kind), *((self._bounded(expr, kind), kind) for expr, kind in self.then))


class SqlParams:
    """Positional ``$n`` parameters in the order they are added."""

    def __init__(self, values: Sequence[Any] = ()) -> None:
        self.values: list[Any] = list(values)

    def add(self, value: Any) -> str:
        self.values.append(value)
        return f"${len(self.values)}"

    def snapshot(self) -> list[Any]:
        return list(self.values)


@dataclass(frozen=True)
class ListSpec:
    """What one list endpoint allows: its sorts, projection, tiebreaker and delta column."""

    scope: str
    sorts: Mapping[str, SortKey]
    default_sort: str
    fields: Mapping[str, str]
    default_fields: tuple[str, ...] | None = None
    id_expr: str = "id"
    id_kind: SortKind = "uuid"
    since_expr: str | None = None
    table: str | None = None

    def __post_init__(self) -> None:
        if not self.scope or not self.sorts or not self.fields:
            raise ValueError("a list spec needs a scope, at least one sort and at least one field")
        for name in (*self.sorts, *self.fields):
            if not _NAME.fullmatch(name):
                raise ValueError(f"list field or sort name {name!r} is not a plain identifier")
        heavy = LIST_HEAVY_FIELDS.intersection(self.fields)
        if heavy:
            raise ValueError(f"list projections never include {sorted(heavy)}")
        if self.default_sort.lstrip("-") not in self.sorts:
            raise ValueError(f"default sort {self.default_sort!r} is not declared")
        unknown = set(self.default_fields or ()) - set(self.fields)
        if unknown:
            raise ValueError(f"default fields {sorted(unknown)} are not declared")

    def plan(self, page: Page, filters: Mapping[str, Any] | None = None) -> "ListPlan":
        """Resolve one request against this spec; raise 400 for anything it does not allow."""
        sort = page.sort or self.default_sort
        descending = sort.startswith("-")
        name = sort.lstrip("-")
        if name not in self.sorts:
            raise _bad_request("invalid_sort", f"unsupported sort {name!r}; use one of {sorted(self.sorts)}")
        if page.fields is None:
            chosen = tuple(self.default_fields or self.fields)
        else:
            unknown = [n for n in page.fields if n not in self.fields]
            if unknown:
                raise _bad_request("invalid_fields", f"unsupported fields {unknown}; use {sorted(self.fields)}")
            chosen = page.fields
        if page.since is not None and self.since_expr is None:
            raise _bad_request("since_unsupported", "this list does not support since=")
        fingerprint = _fingerprint(self.scope, sort, filters or {}, page.since)
        position = None
        if page.cursor is not None:
            position = _decode_cursor(page.cursor, fingerprint, self.sorts[name].columns, self.id_kind)
        return ListPlan(self, page, name, descending, chosen, fingerprint, position)


@dataclass(frozen=True)
class ListPlan:
    """One validated request: SQL fragments for the page query and the response envelope."""

    spec: ListSpec
    page: Page
    sort_name: str
    descending: bool
    fields: tuple[str, ...]
    fingerprint: str
    #: The previous page's last row: every sort key value, then the id.
    position: tuple[Any, ...] | None = field(default=None)

    @property
    def sort_expr(self) -> str:
        return self.spec.sorts[self.sort_name].sql

    @property
    def _sort_columns(self) -> tuple[tuple[str, SortKind], ...]:
        return self.spec.sorts[self.sort_name].columns

    @staticmethod
    def _sort_alias(index: int) -> str:
        return _SORT_COLUMN if index == 0 else f"{_SORT_COLUMN}_{index}"

    @property
    def select_list(self) -> str:
        """The requested fields plus the keyset columns ``envelope`` reads and strips."""
        columns = [f"{self.spec.fields[name]} AS {name}" for name in self.fields]
        for index, (expr, _kind) in enumerate(self._sort_columns):
            columns.append(f"{expr} AS {self._sort_alias(index)}")
        columns.append(f"{self.spec.id_expr} AS {_ID_COLUMN}")
        return ", ".join(columns)

    @property
    def order_by(self) -> str:
        direction = "DESC" if self.descending else "ASC"
        keys = [expr for expr, _kind in self._sort_columns] + [self.spec.id_expr]
        return ", ".join(f"{key} {direction}" for key in keys)

    @property
    def fetch_limit(self) -> int:
        """One more than the page: the extra row only proves ``has_more``."""
        return self.page.limit + 1

    def after(self, row: Mapping[str, Any]) -> "ListPlan":
        """This plan positioned after ``row`` (a row fetched with ``select_list``).

        For an endpoint that drops some fetched rows in Python and fetches again to fill the
        page; the cursor ``envelope`` issues still comes from the last row it returns.
        """
        values = [row[self._sort_alias(index)] for index in range(len(self._sort_columns))]
        return replace(self, position=(*values, row[_ID_COLUMN]))

    def filter_clauses(self, params: SqlParams) -> list[str]:
        """Contract-level filters (``since``) that the count must also honour."""
        if self.page.since is None:
            return []
        return [f"{self.spec.since_expr} >= {params.add(self.page.since)}"]

    def keyset_clauses(self, params: SqlParams) -> list[str]:
        """The position after the previous page; empty on the first page."""
        if self.position is None:
            return []
        operator = "<" if self.descending else ">"
        keys = [expr for expr, _kind in self._sort_columns] + [self.spec.id_expr]
        values = [params.add(value) for value in self.position]
        return [f"({', '.join(keys)}) {operator} ({', '.join(values)})"]

    def envelope(
        self, rows: Sequence[Mapping[str, Any]], *, total: int | None = None,
        total_kind: TotalKind = "none", transform: Callable[[dict[str, Any]], Any] | None = None,
        generated_at: datetime | None = None,
    ) -> dict[str, Any]:
        """The response body for rows fetched with ``fetch_limit``."""
        has_more = len(rows) > self.page.limit
        page_rows = list(rows[: self.page.limit])
        next_cursor = None
        if has_more and page_rows:
            last = page_rows[-1]
            key = self.spec.sorts[self.sort_name]
            sort_values = [last[self._sort_alias(index)] for index in range(len(self._sort_columns))]
            for value, (_expr, kind) in zip(sort_values, self._sort_columns):
                if kind == "text" and value is not None and len(str(value)) > key.max_chars:
                    raise ValueError("a text sort value is longer than its bound; select plan.select_list")
            next_cursor = _encode_cursor(
                self.fingerprint, sort_values, last[_ID_COLUMN], self._sort_columns, self.spec.id_kind,
            )
        items = []
        for row in page_rows:
            item = {name: row[name] for name in self.fields}
            items.append(transform(item) if transform else item)
        body: dict[str, Any] = {
            "items": items, "next_cursor": next_cursor, "has_more": has_more,
            "total_kind": total_kind,
            "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
        }
        if total_kind != "none":
            body["total"] = total
        return body


# --- The delta watermark -----------------------------------------------------------------------


async def snapshot_time(
    conn: Any, *, margin: timedelta = SNAPSHOT_MARGIN, max_lookback: timedelta = SNAPSHOT_MAX_LOOKBACK,
) -> datetime:
    """The ``generated_at`` for a page: call it on the page's connection BEFORE the page query.

    A row's ``updated_at`` is normally ``now()``, its writer's transaction start, but the row
    becomes visible only when that transaction commits. A watermark taken from the API clock
    after the query would be later than the ``updated_at`` of rows still being written, and the
    next ``since=`` poll would skip them for good. This returns the database time minus
    ``margin``, moved back to the start of the oldest transaction open in this database (as far
    as ``pg_stat_activity`` shows it to this role), but never more than ``max_lookback``: a
    transaction open longer than that can still be missed. Rows written after the watermark come
    back on the next poll (``since`` is inclusive), so clients must treat items as upserts.
    """
    value = await conn.fetchval(
        """
        SELECT LEAST(
            clock_timestamp() - $1::interval,
            GREATEST(
                clock_timestamp() - $2::interval,
                COALESCE((SELECT min(xact_start) FROM pg_stat_activity
                          WHERE datname = current_database() AND pid <> pg_backend_pid()
                            AND backend_type = 'client backend'
                            AND xact_start IS NOT NULL), clock_timestamp())
            ) - $1::interval
        )
        """,
        margin, max_lookback,
    )
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# --- Counts ------------------------------------------------------------------------------------


async def count_total(
    conn: Any, mode: CountMode, *, from_sql: str, where: Sequence[str] = (),
    values: Sequence[Any] = (), table: str | None = None,
) -> tuple[int | None, TotalKind]:
    """``(total, total_kind)`` for ``count=`` over the filter-only query (never the keyset).

    ``exact`` counts at most ``EXACT_COUNT_CAP + 1`` rows and reports ``at_least`` beyond the cap.
    ``estimate`` reads ``pg_class.reltuples`` for an unfiltered ``table`` and the planner's row
    estimate (``EXPLAIN``) otherwise: no rows are read either way.
    """
    if mode == "none":
        return None, "none"
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    if mode == "exact":
        found = await conn.fetchval(
            f"SELECT count(*) FROM (SELECT 1 FROM {from_sql}{where_sql} "
            f"LIMIT {EXACT_COUNT_CAP + 1}) AS capped",
            *values,
        )
        found = int(found or 0)
        if found > EXACT_COUNT_CAP:
            return EXACT_COUNT_CAP, "at_least"
        return found, "exact"
    if mode != "estimate":
        raise ValueError(f"unknown count mode {mode!r}")
    if table and not where:
        reltuples = await conn.fetchval(
            "SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass($1)", table,
        )
        if reltuples is not None and reltuples >= 0:
            return int(reltuples), "estimate"
    plan = await conn.fetchval(f"EXPLAIN (FORMAT JSON) SELECT 1 FROM {from_sql}{where_sql}", *values)
    if isinstance(plan, str):
        plan = json.loads(plan)
    return max(0, int(round(float(plan[0]["Plan"]["Plan Rows"])))), "estimate"


# --- Cursors -----------------------------------------------------------------------------------

_key_lock = threading.Lock()
_cursor_key: bytes | None = None


def configure_cursor_key(key: bytes | None) -> None:
    """Pin the cursor MAC key (tests, or a composition root with its own secret)."""
    global _cursor_key
    with _key_lock:
        _cursor_key = key


def _key() -> bytes:
    """The installation-derived key, so cursors survive restarts; a process key otherwise."""
    global _cursor_key
    with _key_lock:
        if _cursor_key is None:
            derived = None
            try:
                try:
                    from secret_store import derived_installation_key
                except ModuleNotFoundError:  # package import layout
                    from .secret_store import derived_installation_key
                derived = derived_installation_key(_CURSOR_PURPOSE)
            except Exception:
                derived = None
            # Without a stable key a restart only invalidates open cursors (a 400, then page 1).
            _cursor_key = derived or secrets.token_bytes(32)
        return _cursor_key


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def _fingerprint(scope: str, sort: str, filters: Mapping[str, Any], since: datetime | None) -> str:
    canonical = json.dumps(
        {"scope": scope, "sort": sort, "filters": dict(filters),
         "since": since.isoformat() if since else None},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _encode_value(value: Any, kind: SortKind) -> Any:
    if value is None:
        raise ValueError("a keyset sort value is NULL; wrap the sort expression in COALESCE")
    if kind == "datetime":
        return value.isoformat()
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    return str(value)  # numeric, text, uuid


def _decode_value(raw: Any, kind: SortKind) -> Any:
    if kind == "datetime":
        if not isinstance(raw, str):
            raise ValueError("datetime")
        return datetime.fromisoformat(raw)
    if kind == "int":
        if type(raw) is not int:
            raise ValueError("int")
        return raw
    if kind == "float":
        if type(raw) not in (int, float):
            raise ValueError("float")
        return float(raw)
    if not isinstance(raw, str) or len(raw) > 1024:
        raise ValueError("text")
    if kind == "uuid":
        return uuid.UUID(raw)
    if kind == "numeric":
        from decimal import Decimal, InvalidOperation
        try:
            return Decimal(raw)
        except InvalidOperation as exc:
            raise ValueError("numeric") from exc
    return raw


def _mac(payload: str) -> str:
    return _b64(hmac.new(_key(), payload.encode("ascii"), hashlib.sha256).digest()[:16])


def _encode_cursor(fingerprint: str, sort_values: Sequence[Any], id_value: Any,
                   sort_columns: Sequence[tuple[str, SortKind]], id_kind: SortKind) -> str:
    keys = [_encode_value(value, kind) for value, (_expr, kind) in zip(sort_values, sort_columns, strict=True)]
    payload = _b64(json.dumps(
        {"v": 1, "q": fingerprint, "k": [*keys, _encode_value(id_value, id_kind)]},
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))
    return f"{payload}.{_mac(payload)}"


def _decode_cursor(cursor: str, fingerprint: str, sort_columns: Sequence[tuple[str, SortKind]],
                   id_kind: SortKind) -> tuple[Any, ...]:
    invalid = _bad_request("invalid_cursor", "the cursor is malformed or was not issued by this server")
    if not cursor.isascii():
        raise invalid
    payload, _, tag = cursor.partition(".")
    if not payload or not tag or len(cursor) > CURSOR_MAX_LENGTH:
        raise invalid
    if not hmac.compare_digest(tag, _mac(payload)):
        raise invalid
    try:
        body = json.loads(_unb64(payload))
        if not isinstance(body, dict) or body.get("v") != 1:
            raise ValueError("version")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise invalid from exc
    if body.get("q") != fingerprint:
        raise _bad_request(
            "cursor_mismatch",
            "the cursor belongs to a different filter, sort or since; restart without a cursor",
        )
    try:
        raw = body["k"]
        if not isinstance(raw, list) or len(raw) != len(sort_columns) + 1:
            raise ValueError("key count")
        values = [_decode_value(value, kind) for value, (_expr, kind) in zip(raw, sort_columns)]
        return (*values, _decode_value(raw[-1], id_kind))
    except (KeyError, TypeError, ValueError) as exc:
        raise invalid from exc


__all__ = [
    "CURSOR_MAX_LENGTH",
    "DEFAULT_LIMIT",
    "EXACT_COUNT_CAP",
    "LIST_CONTRACT_VERSION",
    "LIST_HEAVY_FIELDS",
    "MAX_LIMIT",
    "ListPlan",
    "ListSpec",
    "Page",
    "PageDep",
    "SortKey",
    "SqlParams",
    "MAX_TEXT_SORT_CHARS",
    "configure_cursor_key",
    "count_total",
    "page_params",
    "snapshot_time",
]
