"""The 2.11 legacy (deprecated) list shapes are bounded: /targets/grouped, /targets/inventory
grouped by domain and /exposure/assets. Unit level, no database: the routes clamp to their
bounds and mark what they left out; a read classifies a bounded number of exposure facts.

The bounded shapes themselves are proven against the unbounded oracles on PostgreSQL in
tests/test_targets_dashboard_scale_postgres.py and tests/test_exposure_assets_rank_postgres.py.
"""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from exposure import asset_rank  # noqa: E402
import exposure.router as exposure_router  # noqa: E402
from list_contract import Page, SqlParams  # noqa: E402
from targets import asset_inventory, grouped_list  # noqa: E402
from targets import router as targets_router  # noqa: E402


class _Response:
    def __init__(self):
        self.headers = {}


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


_GROUPED = dict(include_inactive=False, search=None, discovery_source=None, grade=None, has_findings=None,
                sort_by="last_score", sort_order="desc", limit=1000, cursor=None, sort=None, fields=None,
                count=None, since=None, member_limit=200, cohort=None, has_inventory=None, summary=None)


def test_legacy_grouped_is_clamped_to_the_bounded_first_page(monkeypatch):
    seen = {}

    async def legacy(conn, page, *, filters, member_limit, member_columns, public_row):
        seen.update(page=page, filters=filters, member_limit=member_limit)
        return {"domains": []}

    monkeypatch.setattr(grouped_list, "legacy_grouped", legacy)
    monkeypatch.setattr(targets_router, "_pool", lambda: _Pool(object()))
    response = _Response()
    asyncio.run(targets_router.list_targets_grouped(response, **_GROUPED))
    assert response.headers["Deprecation"] == "true"
    assert (seen["page"].limit, seen["page"].sort, seen["page"].count) == (50, "-last_score", "none")
    assert seen["member_limit"] == 20
    # The list/v1 route's own filters, so the legacy next_cursor continues there.
    assert seen["filters"] == {"include_inactive": False, "search": None, "discovery_source": None, "grade": None,
                               "has_findings": None, "member_limit": 20, "cohort": "all", "has_inventory": False}
    asyncio.run(targets_router.list_targets_grouped(_Response(), **{**_GROUPED, "limit": None, "member_limit": 5}))
    assert (seen["page"].limit, seen["member_limit"]) == (50, 5)


def test_legacy_grouped_envelope_marks_what_was_left_out(monkeypatch):
    async def page(conn, page, **_kwargs):
        return {"items": [{"root_domain": "a.invalid", "subdomains": [], "subdomains_truncated": True}],
                "has_more": False, "next_cursor": None}

    class Conn:
        async def fetchrow(self, sql, *args):
            self.sql = sql
            return {"groups": 7, "targets": 900}

    monkeypatch.setattr(grouped_list, "grouped_page", page)
    conn = Conn()
    body = asyncio.run(grouped_list.legacy_grouped(
        conn, Page(limit=50), filters={"search": "a"}, member_limit=20,
        member_columns="t.id", public_row=dict))
    assert (body["total_root_domains"], body["total_targets"]) == (7, 900)
    assert body["truncated"] is True and body["has_more"] is False and body["next_cursor"] is None
    assert (body["limit"], body["member_limit"]) == (50, 20) and "list/v1" in body["list_v1_hint"]
    assert "sum(g.total_count)" in conn.sql and "ILIKE" in conn.sql


def test_inventory_group_members_rank_on_keys_and_stop_at_the_budget():
    class Conn:
        calls = []

        async def fetch(self, sql, *args):
            self.calls.append((sql, args))
            return []

    query = asset_inventory._scope_query(search="", connected_only=False, include_inactive=False,
                                         include_services=False)
    conn = Conn()
    assert asyncio.run(asset_inventory._group_members(
        conn, query, from_sql=asset_inventory.ROOT_FROM, sort="name", descending=False, domains=[],
        member_limit=20)) == {}
    assert conn.calls == []
    members = asyncio.run(asset_inventory._group_members(
        conn, query, from_sql=asset_inventory.ROOT_FROM, sort="risk", descending=True,
        domains=["a.invalid", "b.invalid"], member_limit=20, budget=asset_inventory.LEGACY_GROUPED_ASSETS))
    assert members == {"a.invalid": [], "b.invalid": []}
    sql, args = conn.calls[-1]
    # The ranking reads keys only; the per-asset detail is computed for the chosen rows alone.
    ranked, final = sql.split("SELECT t.id,t.name", 1)
    assert "AS MATERIALIZED" in ranked and "DETAIL" not in ranked and "origin_count" not in ranked
    assert "origin_count" in final
    assert args[-1] == asset_inventory.LEGACY_GROUPED_ASSETS and 20 in args
    assert asset_inventory.LEGACY_GROUPED_ASSETS == 200


def test_inventory_legacy_hint_names_the_list_v1_parameters():
    assert "count=none" in asset_inventory.LEGACY_GROUPS_HINT and "member_limit" in asset_inventory.LEGACY_GROUPS_HINT


def _head_row():
    row = {name: 0 for name in asset_rank.METRIC_NAMES}
    row.update(cohort_counts="{}", id=None)
    return row


def test_exposure_legacy_limit_is_clamped_and_says_so(monkeypatch):
    seen = {}

    def offset_page_sql(params, **kwargs):
        seen.update(kwargs)
        return "SELECT 1"

    async def ranked_rows(conn, build, *, kind):
        build(SqlParams(), {})
        return [_head_row()], True

    monkeypatch.setattr(exposure_router, "offset_page_sql", offset_page_sql)
    monkeypatch.setattr(exposure_router, "_ranked_rows", ranked_rows)
    monkeypatch.setattr(exposure_router, "_pool", lambda: _Pool(object()))
    params = dict(root_domain=None, kind=None, cohort=None, offset=0, cursor=None, sort=None, fields=None,
                  count=None, since=None)
    response = _Response()
    body = asyncio.run(exposure_router.exposure_assets(response, limit=2000, **params))
    assert seen["limit"] == body["limit"] == exposure_router.LEGACY_ASSETS_LIMIT == 500
    assert body["classification_pending"] is True and "list/v1" in body["list_v1_hint"]
    assert response.headers["Deprecation"] == "true"
    asyncio.run(exposure_router.exposure_assets(_Response(), limit=None, **params))
    assert seen["limit"] == 500
    asyncio.run(exposure_router.exposure_assets(_Response(), limit=7, **params))
    assert seen["limit"] == 7


class _Tx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class _BacklogConn:
    def transaction(self):
        return _Tx()


def test_a_read_refreshes_at_most_its_budget_of_facts(monkeypatch):
    batches = []

    async def endless(conn, kind):
        batches.append(kind)
        return asset_rank.FACTS_BATCH, 0

    monkeypatch.setattr(asset_rank, "_refresh_kind", endless)
    written = asyncio.run(asset_rank.refresh_facts(_BacklogConn(), max_rows=asset_rank.FACTS_READ_BUDGET))
    assert written == asset_rank.FACTS_READ_BUDGET == 1000
    assert batches == ["target"] * (1000 // asset_rank.FACTS_BATCH)


def test_an_unbounded_refresh_finishes_a_finite_backlog(monkeypatch):
    left = {"target": 250, "ai": 30}

    async def finite(conn, kind):
        done = min(left[kind], asset_rank.FACTS_BATCH)
        left[kind] -= done
        return done, 0

    monkeypatch.setattr(asset_rank, "_refresh_kind", finite)
    assert asyncio.run(asset_rank.refresh_facts(_BacklogConn())) == 280
    assert left == {"target": 0, "ai": 0}


def test_background_completion_is_single_flight(monkeypatch):
    runs = []

    async def scenario():
        gate = asyncio.Event()

        async def refresh(conn, **_kwargs):
            runs.append(conn)
            await gate.wait()
            return 0

        monkeypatch.setattr(asset_rank, "refresh_facts", refresh)
        monkeypatch.setitem(asset_rank._BACKGROUND, "task", None)
        pool = _Pool("conn")
        assert asset_rank.complete_facts_in_background(pool) is True
        assert asset_rank.complete_facts_in_background(pool) is False
        await asyncio.sleep(0)
        gate.set()
        await asset_rank._BACKGROUND["task"]
        assert asset_rank.complete_facts_in_background(pool) is True
        await asset_rank._BACKGROUND["task"]

    asyncio.run(scenario())
    assert runs == ["conn", "conn"]
