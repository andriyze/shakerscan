"""The shared list contract: the Page dependency, cursor integrity and the response envelope."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import FastAPI  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import list_contract as lc  # noqa: E402
import public_api_contract  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)

SPEC = lc.ListSpec(
    scope="widgets",
    sorts={"created_at": lc.SortKey("w.created_at", "datetime"),
           "name": lc.SortKey("w.name", "text"),
           "rank": lc.SortKey("w.rank", "int")},
    default_sort="-created_at",
    fields={"id": "w.id", "name": "w.name", "created_at": "w.created_at", "rank": "w.rank"},
    default_fields=("id", "name"),
    id_expr="w.id",
    since_expr="w.updated_at",
    table="widgets",
)


@pytest.fixture(autouse=True)
def _cursor_key():
    lc.configure_cursor_key(b"k" * 32)
    yield
    lc.configure_cursor_key(None)


def _app() -> TestClient:
    app = FastAPI()

    @app.get("/widgets")
    def widgets(page: lc.PageDep):
        return {"limit": page.limit, "cursor": page.cursor, "sort": page.sort,
                "fields": page.fields, "count": page.count,
                "since": page.since.isoformat() if page.since else None}

    return TestClient(app)


def _rows(n: int, *, start: int = 0) -> list[dict]:
    rows = []
    for i in range(start, start + n):
        ident = uuid.UUID(int=i + 1)
        created = T0 - timedelta(minutes=i)
        rows.append({"id": ident, "name": f"w{i}", "created_at": created, "rank": i,
                     "__list_sort": created, "__list_id": ident})
    return rows


# --- The dependency ----------------------------------------------------------------------------


def test_page_defaults_to_fifty_and_no_count():
    body = _app().get("/widgets").json()
    assert body == {"limit": 50, "cursor": None, "sort": None, "fields": None,
                    "count": "none", "since": None}


@pytest.mark.parametrize("limit", ["0", "201", "100000", "-1", "x"])
def test_page_refuses_limits_outside_one_to_two_hundred(limit):
    assert _app().get(f"/widgets?limit={limit}").status_code == 422


def test_page_accepts_the_maximum():
    assert _app().get("/widgets?limit=200").json()["limit"] == 200


def test_page_refuses_unknown_count_mode():
    assert _app().get("/widgets?count=all").status_code == 422


@pytest.mark.parametrize("sort", ["name;drop", "Name", "--name", "a b", "-"])
def test_page_refuses_malformed_sort(sort):
    response = _app().get("/widgets", params={"sort": sort})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_sort"


def test_page_parses_fields_and_dedupes():
    body = _app().get("/widgets?fields=id,%20name,id").json()
    assert body["fields"] == ["id", "name"]


@pytest.mark.parametrize("fields", [",", "id,na-me", "id,NAME", ",".join(f"f{i}" for i in range(65))])
def test_page_refuses_malformed_fields(fields):
    response = _app().get("/widgets", params={"fields": fields})
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_fields"


def test_page_treats_naive_since_as_utc():
    body = _app().get("/widgets?since=2026-10-01T00:00:00").json()
    assert body["since"] == "2026-10-01T00:00:00+00:00"


def test_page_refuses_overlong_cursor():
    assert _app().get("/widgets", params={"cursor": "a" * 2049}).status_code == 422


# --- The spec ----------------------------------------------------------------------------------


@pytest.mark.parametrize("heavy", sorted(lc.LIST_HEAVY_FIELDS))
def test_spec_refuses_heavy_fields(heavy):
    with pytest.raises(ValueError, match="never include"):
        lc.ListSpec(scope="x", sorts={"id": lc.SortKey("id", "uuid")}, default_sort="id",
                    fields={"id": "id", heavy: heavy})


def test_spec_refuses_undeclared_default_sort_and_fields():
    with pytest.raises(ValueError):
        lc.ListSpec(scope="x", sorts={"id": lc.SortKey("id", "uuid")}, default_sort="name",
                    fields={"id": "id"})
    with pytest.raises(ValueError):
        lc.ListSpec(scope="x", sorts={"id": lc.SortKey("id", "uuid")}, default_sort="id",
                    fields={"id": "id"}, default_fields=("name",))


def test_plan_defaults_and_sql_fragments():
    plan = SPEC.plan(lc.Page())
    assert (plan.sort_name, plan.descending, plan.fields) == ("created_at", True, ("id", "name"))
    assert plan.order_by == "w.created_at DESC, w.id DESC"
    assert plan.select_list == ("w.id AS id, w.name AS name, w.created_at AS __list_sort, "
                                "w.id AS __list_id")
    assert plan.fetch_limit == 51
    params = lc.SqlParams()
    assert plan.filter_clauses(params) == [] and plan.keyset_clauses(params) == []


def test_plan_refuses_undeclared_sort_and_fields():
    for page, error in ((lc.Page(sort="secret"), "invalid_sort"),
                        (lc.Page(fields=("id", "evidence")), "invalid_fields")):
        with pytest.raises(HTTPException) as caught:
            SPEC.plan(page)
        assert caught.value.status_code == 400
        assert caught.value.detail["error"] == error


def test_plan_refuses_since_when_the_spec_has_no_delta_column():
    spec = lc.ListSpec(scope="x", sorts={"id": lc.SortKey("id", "uuid")}, default_sort="id",
                       fields={"id": "id"})
    with pytest.raises(HTTPException) as caught:
        spec.plan(lc.Page(since=T0))
    assert caught.value.detail["error"] == "since_unsupported"


def test_since_is_a_filter_clause_with_its_own_parameter():
    plan = SPEC.plan(lc.Page(since=T0))
    params = lc.SqlParams(["existing"])
    assert plan.filter_clauses(params) == ["w.updated_at >= $2"]
    assert params.values == ["existing", T0]


# --- The envelope and the cursor ---------------------------------------------------------------


def test_envelope_without_more_rows():
    plan = SPEC.plan(lc.Page(limit=5))
    body = plan.envelope(_rows(3), generated_at=T0)
    assert body == {
        "items": [{"id": r["id"], "name": r["name"]} for r in _rows(3)],
        "next_cursor": None, "has_more": False, "total_kind": "none",
        "generated_at": "2026-10-01T00:00:00+00:00",
    }


def test_envelope_reports_total_and_kind_when_counted():
    body = SPEC.plan(lc.Page(limit=5)).envelope(_rows(2), total=10_000, total_kind="at_least")
    assert (body["total"], body["total_kind"]) == (10_000, "at_least")


def test_envelope_applies_transform_and_strips_keyset_columns():
    plan = SPEC.plan(lc.Page(limit=2, fields=("name", "rank")))
    body = plan.envelope(_rows(3), transform=lambda item: {**item, "label": item["name"].upper()})
    assert body["items"] == [{"name": "w0", "rank": 0, "label": "W0"},
                             {"name": "w1", "rank": 1, "label": "W1"}]
    assert body["has_more"] is True


def test_cursor_round_trip_resumes_after_the_last_item():
    plan = SPEC.plan(lc.Page(limit=2))
    cursor = plan.envelope(_rows(3))["next_cursor"]
    nxt = SPEC.plan(lc.Page(limit=2, cursor=cursor))
    assert nxt.position == (_rows(2)[1]["created_at"], _rows(2)[1]["id"])
    params = lc.SqlParams(["f"])
    assert nxt.keyset_clauses(params) == ["(w.created_at, w.id) < ($2, $3)"]
    assert params.values[1:] == [nxt.position[0], nxt.position[1]]


def test_ascending_cursor_uses_greater_than_and_typed_values():
    plan = SPEC.plan(lc.Page(limit=1, sort="rank"))
    rows = [{**r, "__list_sort": r["rank"]} for r in _rows(2)]
    cursor = plan.envelope(rows)["next_cursor"]
    nxt = SPEC.plan(lc.Page(limit=1, sort="rank", cursor=cursor))
    assert nxt.position == (0, uuid.UUID(int=1))
    assert nxt.keyset_clauses(lc.SqlParams()) == ["(w.rank, w.id) > ($1, $2)"]


def _first_cursor(filters=None, page=None):
    page = page or lc.Page(limit=1)
    return SPEC.plan(page, filters).envelope(_rows(2))["next_cursor"]


@pytest.mark.parametrize("change", [
    {"filters": {"status": "closed"}},
    {"page": lc.Page(limit=1, sort="created_at")},
    {"page": lc.Page(limit=1, since=T0)},
])
def test_cursor_is_bound_to_filters_sort_and_since(change):
    cursor = _first_cursor({"status": "open"})
    page = change.get("page", lc.Page(limit=1))
    page = lc.Page(limit=page.limit, sort=page.sort, since=page.since, cursor=cursor)
    with pytest.raises(HTTPException) as caught:
        SPEC.plan(page, change.get("filters", {"status": "open"}))
    assert caught.value.status_code == 400
    assert caught.value.detail["error"] == "cursor_mismatch"


def test_cursor_survives_a_projection_or_limit_change():
    cursor = _first_cursor({"status": "open"})
    plan = SPEC.plan(lc.Page(limit=7, fields=("rank",), cursor=cursor), {"status": "open"})
    assert plan.position is not None


def test_cursor_is_bound_to_the_endpoint_scope():
    other = lc.ListSpec(scope="gadgets", sorts=SPEC.sorts, default_sort=SPEC.default_sort,
                        fields=SPEC.fields, id_expr="w.id")
    with pytest.raises(HTTPException) as caught:
        other.plan(lc.Page(cursor=_first_cursor()))
    assert caught.value.detail["error"] == "cursor_mismatch"


def _tamper(cursor: str) -> list[str]:
    payload, tag = cursor.split(".")
    body = lc._unb64(payload).replace(b"T00:", b"T01:")
    return [
        lc._b64(body) + "." + tag,                       # edited position, old tag
        payload + "." + tag[:-2] + ("AA" if tag[-2:] != "AA" else "BB"),
        payload, "." + tag, "garbage", payload + ".",
    ]


def test_tampered_or_foreign_cursors_are_refused():
    cursor = _first_cursor()
    for bad in _tamper(cursor):
        with pytest.raises(HTTPException) as caught:
            SPEC.plan(lc.Page(cursor=bad))
        assert caught.value.detail["error"] == "invalid_cursor", bad
    lc.configure_cursor_key(b"x" * 32)  # another installation's key
    with pytest.raises(HTTPException) as caught:
        SPEC.plan(lc.Page(cursor=cursor))
    assert caught.value.detail["error"] == "invalid_cursor"


def test_validly_signed_cursor_with_wrong_types_is_refused():
    fingerprint = SPEC.plan(lc.Page()).fingerprint
    payload = lc._b64(b'{"v":1,"q":"%s","k":[5,"not-a-uuid"]}' % fingerprint.encode())
    with pytest.raises(HTTPException) as caught:
        SPEC.plan(lc.Page(cursor=f"{payload}.{lc._mac(payload)}"))
    assert caught.value.detail["error"] == "invalid_cursor"


def test_null_sort_value_is_a_programming_error():
    plan = SPEC.plan(lc.Page(limit=1))
    rows = [{**r, "__list_sort": None} for r in _rows(2)]
    with pytest.raises(ValueError, match="COALESCE"):
        plan.envelope(rows)


# --- Counts against a recording connection -----------------------------------------------------


class _Conn:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    async def fetchval(self, sql, *args):
        self.calls.append((sql, args))
        return self.answers.pop(0)


def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_count_none_runs_no_query():
    conn = _Conn([])
    assert _run(lc.count_total(conn, "none", from_sql="widgets w")) == (None, "none")
    assert conn.calls == []


def test_exact_count_is_capped():
    conn = _Conn([10_001])
    assert _run(lc.count_total(conn, "exact", from_sql="widgets w", where=["w.a = $1"],
                               values=[1])) == (10_000, "at_least")
    sql, args = conn.calls[0]
    assert "LIMIT 10001" in sql and "WHERE w.a = $1" in sql and args == (1,)
    assert _run(lc.count_total(_Conn([42]), "exact", from_sql="widgets w")) == (42, "exact")


def test_unfiltered_estimate_reads_reltuples_and_falls_back_to_explain():
    conn = _Conn([1234])
    assert _run(lc.count_total(conn, "estimate", from_sql="widgets w", table="widgets")) == (1234, "estimate")
    assert "pg_class" in conn.calls[0][0]
    never_analyzed = _Conn([-1, '[{"Plan": {"Plan Rows": 7}}]'])
    assert _run(lc.count_total(never_analyzed, "estimate", from_sql="widgets w",
                               table="widgets")) == (7, "estimate")
    filtered = _Conn([[{"Plan": {"Plan Rows": 99.6}}]])
    assert _run(lc.count_total(filtered, "estimate", from_sql="widgets w", where=["w.a = $1"],
                               values=[2], table="widgets")) == (100, "estimate")
    assert filtered.calls[0][0].startswith("EXPLAIN (FORMAT JSON) SELECT 1 FROM widgets w WHERE")


def test_legacy_list_contract_is_marked_deprecated():
    legacy = public_api_contract.LEGACY_LIST_CONTRACT
    assert legacy["status"] == "deprecated"
    assert legacy["replacement"] == public_api_contract.LIST_CONTRACT == lc.LIST_CONTRACT_VERSION
