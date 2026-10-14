"""The shared list contract on real PostgreSQL: keyset pages, index use and counts.

Only LIST_CONTRACT_TEST_DATABASE_URL on localhost/shakerscan_list_contract_test is permitted.
The tests create and drop their own ``list_contract_widgets`` table there.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("LIST_CONTRACT_TEST_DATABASE_URL")
REQUIRED = os.environ.get("LIST_CONTRACT_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable list-contract PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import HTTPException  # noqa: E402

import list_contract as lc  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
ROWS = 10_050  # past the exact-count cap

SPEC = lc.ListSpec(
    scope="widgets",
    sorts={"created_at": lc.SortKey("w.created_at", "datetime"),
           "rank": lc.SortKey("w.rank", "int"),
           "name": lc.SortKey("w.name", "text")},
    default_sort="-created_at",
    fields={"id": "w.id", "name": "w.name", "kind": "w.kind", "rank": "w.rank"},
    id_expr="w.id",
    since_expr="w.updated_at",
    table="list_contract_widgets",
)


@pytest.fixture(autouse=True)
def _cursor_key():
    lc.configure_cursor_key(b"p" * 32)
    yield
    lc.configure_cursor_key(None)


async def _connect():
    return await asyncpg.connect(require_disposable_database(DSN, "shakerscan_list_contract_test"))


@pytest.fixture(scope="module", autouse=True)
def _table():
    async def setup():
        conn = await _connect()
        try:
            await conn.execute("DROP TABLE IF EXISTS list_contract_widgets")
            await conn.execute("""
                CREATE TABLE list_contract_widgets (
                    id uuid PRIMARY KEY,
                    name text NOT NULL,
                    kind text NOT NULL,
                    rank integer NOT NULL,
                    created_at timestamptz NOT NULL,
                    updated_at timestamptz NOT NULL
                )""")
            # Many equal sort values: the id tiebreaker must carry the position.
            await conn.copy_records_to_table("list_contract_widgets", records=[
                (uuid.UUID(int=i + 1), f"w{i:05d}", "even" if i % 2 == 0 else "odd", i % 7,
                 T0 - timedelta(minutes=i // 3), T0 + timedelta(seconds=i))
                for i in range(ROWS)
            ])
            await conn.execute("CREATE INDEX ON list_contract_widgets (created_at, id)")
            await conn.execute("CREATE INDEX ON list_contract_widgets (kind, rank, id)")
            await conn.execute("ANALYZE list_contract_widgets")
        finally:
            await conn.close()

    async def teardown():
        conn = await _connect()
        try:
            await conn.execute("DROP TABLE IF EXISTS list_contract_widgets")
        finally:
            await conn.close()

    asyncio.run(setup())
    yield
    asyncio.run(teardown())


async def _page(conn, page: lc.Page, *, kind: str | None = None):
    plan = SPEC.plan(page, {"kind": kind})
    params = lc.SqlParams()
    where = ["TRUE"]
    if kind:
        where.append(f"w.kind = {params.add(kind)}")
    where += plan.filter_clauses(params)
    count_values = params.snapshot()
    page_where = where + plan.keyset_clauses(params)
    sql = (f"SELECT {plan.select_list} FROM list_contract_widgets w "
           f"WHERE {' AND '.join(page_where)} ORDER BY {plan.order_by} LIMIT {plan.fetch_limit}")
    rows = await conn.fetch(sql, *params.values)
    total, total_kind = await lc.count_total(
        conn, page.count, from_sql="list_contract_widgets w",
        where=[c for c in where if c != "TRUE"], values=count_values, table=SPEC.table,
    )
    return plan.envelope(rows, total=total, total_kind=total_kind), sql, params.values


async def _walk(conn, page: lc.Page, *, kind: str | None = None, mutate=None):
    seen, cursor, pages = [], None, 0
    while True:
        body, _, _ = await _page(conn, lc.Page(limit=page.limit, sort=page.sort, since=page.since,
                                               fields=page.fields, cursor=cursor), kind=kind)
        seen.extend(body["items"])
        pages += 1
        if mutate and pages == 2:
            await mutate(conn)
        if not body["has_more"]:
            assert body["next_cursor"] is None
            return seen, pages
        cursor = body["next_cursor"]


def _run(coro_fn):
    async def wrapper():
        conn = await _connect()
        try:
            return await coro_fn(conn)
        finally:
            await conn.close()
    return asyncio.run(wrapper())


def test_descending_keyset_walk_returns_every_row_once_in_order():
    async def check(conn):
        seen, pages = await _walk(conn, lc.Page(limit=200, fields=("id", "name")))
        expected = await conn.fetch(
            "SELECT id, name FROM list_contract_widgets ORDER BY created_at DESC, id DESC")
        assert [r["id"] for r in seen] == [r["id"] for r in expected]
        assert pages == -(-ROWS // 200)
    _run(check)


def test_ascending_walk_over_a_filtered_low_cardinality_sort():
    async def check(conn):
        seen, _ = await _walk(conn, lc.Page(limit=137, sort="rank", fields=("id", "rank")), kind="odd")
        expected = await conn.fetch(
            "SELECT id FROM list_contract_widgets WHERE kind = 'odd' ORDER BY rank, id")
        assert [r["id"] for r in seen] == [r["id"] for r in expected]
    _run(check)


def test_text_sort_and_rows_inserted_mid_walk_never_duplicate_or_skip_existing_rows():
    async def insert(conn):
        await conn.execute(
            "INSERT INTO list_contract_widgets VALUES ($1, 'a-new', 'even', 0, $2, $2)",
            uuid.uuid4(), T0)

    async def check(conn):
        before = {r["id"] for r in await conn.fetch("SELECT id FROM list_contract_widgets")}
        seen, _ = await _walk(conn, lc.Page(limit=200, sort="-name", fields=("id",)), mutate=insert)
        ids = [r["id"] for r in seen]
        assert len(ids) == len(set(ids))
        assert before <= set(ids)
        await conn.execute("DELETE FROM list_contract_widgets WHERE name = 'a-new'")
    _run(check)


def test_keyset_page_is_an_index_range_scan_without_a_sort():
    async def check(conn):
        first, _, _ = await _page(conn, lc.Page(limit=50))
        _, sql, values = await _page(conn, lc.Page(limit=50, cursor=first["next_cursor"]))
        plan = await conn.fetchval(f"EXPLAIN (FORMAT JSON) {sql}", *values)
        text = json.dumps(json.loads(plan) if isinstance(plan, str) else plan)
        assert "Index Scan" in text and "list_contract_widgets_created_at_id_idx" in text
        assert '"Node Type": "Sort"' not in text
    _run(check)


def test_since_returns_only_rows_updated_at_or_after_and_binds_the_cursor():
    async def check(conn):
        since = T0 + timedelta(seconds=ROWS - 120)
        seen, _ = await _walk(conn, lc.Page(limit=50, since=since, sort="created_at"))
        assert len(seen) == 120
        body, _, _ = await _page(conn, lc.Page(limit=50, since=since, count="exact"))
        assert (body["total"], body["total_kind"]) == (120, "exact")
        with pytest.raises(HTTPException) as caught:
            await _page(conn, lc.Page(limit=50, cursor=body["next_cursor"]))
        assert caught.value.detail["error"] == "cursor_mismatch"
    _run(check)


def test_exact_count_is_capped_and_small_counts_are_exact():
    async def check(conn):
        everything, _, _ = await _page(conn, lc.Page(count="exact"))
        assert (everything["total"], everything["total_kind"]) == (10_000, "at_least")
        assert len(everything["items"]) == 50 and everything["has_more"] is True
        filtered, _, _ = await _page(conn, lc.Page(count="exact"), kind="odd")
        assert (filtered["total"], filtered["total_kind"]) == (ROWS // 2, "exact")
    _run(check)


def test_estimates_come_from_statistics():
    async def check(conn):
        unfiltered, _, _ = await _page(conn, lc.Page(count="estimate"))
        assert unfiltered["total_kind"] == "estimate"
        assert unfiltered["total"] == ROWS  # reltuples after ANALYZE
        filtered, _, _ = await _page(conn, lc.Page(count="estimate"), kind="odd")
        assert filtered["total_kind"] == "estimate"
        assert abs(filtered["total"] - ROWS // 2) < ROWS * 0.1
        none, _, _ = await _page(conn, lc.Page())
        assert "total" not in none and none["total_kind"] == "none"
    _run(check)


def test_estimate_falls_back_to_the_planner_for_a_never_analyzed_table():
    async def check(conn):
        await conn.execute("DROP TABLE IF EXISTS list_contract_fresh")
        await conn.execute("CREATE TABLE list_contract_fresh (id int)")
        try:
            total, kind = await lc.count_total(
                conn, "estimate", from_sql="list_contract_fresh", table="list_contract_fresh")
            assert kind == "estimate" and total >= 0
        finally:
            await conn.execute("DROP TABLE list_contract_fresh")
    _run(check)
