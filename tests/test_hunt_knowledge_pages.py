"""Execute the real query builder over a populated in-memory relational fixture."""

import asyncio
from datetime import datetime, timezone
import re
import sqlite3
import uuid

import pytest

from api.hunt.knowledge import KnowledgeQueryError, QUERIES, query_knowledge_page


TARGET = uuid.UUID(int=1)
OTHER = uuid.UUID(int=2)
STAMP = datetime(2026, 9, 4, tzinfo=timezone.utc).isoformat()


class KnowledgeDB:
    def __init__(self, *, check_same_thread=True):
        self.db = sqlite3.connect(":memory:", check_same_thread=check_same_thread)
        self.db.row_factory = sqlite3.Row
        self.calls = []
        for table in {s.table for s in QUERIES.values()}:
            fields = {"id", "target_id", "device_target_id", "is_active", "target_scope"}
            for spec in QUERIES.values():
                if spec.table == table:
                    fields.update(spec.columns.split(", "))
            if table == "target_endpoints":
                fields.update({"last_http_status", "param_location"})  # grouped projection
            self.db.execute(f"CREATE TABLE {table} ({', '.join(fields)})")

    def insert(self, kind, **values):
        self.db.execute(f"INSERT INTO {QUERIES[kind].table} ({', '.join(values)}) VALUES ({','.join('?' for _ in values)})", list(values.values()))

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        sql = re.sub(r"TIMESTAMPTZ '([^']*)'", r"'\1'", sql).replace(" ILIKE ", " LIKE ")
        params = {str(i): v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v for i, v in enumerate(args, 1)}
        return self.db.execute(sql, params).fetchall()


def page(db, kind="endpoints", **kwargs):
    return asyncio.run(query_knowledge_page(db, target_id=TARGET, kind=kind, **kwargs))


@pytest.fixture
def inventory():
    db = KnowledgeDB()
    for i in range(1, 126):
        db.insert("endpoints", id=str(uuid.UUID(int=i + 100)), target_id=str(TARGET), method="GET", path=f"/item/{i}", auth_state="anonymous", test_status="untested", priority_score=10, last_seen_at=STAMP)
    db.insert("endpoints", id=str(uuid.UUID(int=1000)), target_id=str(OTHER), method="GET", path="/foreign", test_status="untested", priority_score=100, last_seen_at=STAMP)
    return db


def test_all_125_rows_are_reachable_without_duplicates(inventory):
    first = page(inventory)
    assert first["count"] == 100 and first["has_more"]
    second = page(inventory, cursor=first["next_cursor"])
    assert second["count"] == 25 and not second["has_more"]
    assert second["next_cursor"] is None
    assert len({r["id"] for r in first["rows"] + second["rows"]}) == 125
    assert all("last_seen_at" in row for row in first["rows"])
    assert page(inventory, limit=500)["count"] == 125


def test_exact_id_filters_and_untested_frontier(inventory):
    wanted = str(uuid.UUID(int=103))
    result = page(inventory, filters={"id": wanted, "test_status": "UNTESTED", "auth_state": "anonymous", "method": "get", "path_contains": "/item/"})
    assert [r["id"] for r in result["rows"]] == [wanted]
    assert page(inventory, filters={"test_status": "tested"})["count"] == 0


def test_cursor_cannot_change_target_or_filters(inventory):
    cursor = page(inventory)["next_cursor"]
    with pytest.raises(KnowledgeQueryError):
        page(inventory, cursor=cursor, filters={"method": "POST"})
    with pytest.raises(KnowledgeQueryError):
        asyncio.run(query_knowledge_page(inventory, target_id=OTHER, kind="endpoints", cursor=cursor))


@pytest.mark.parametrize("cursor", ["not a cursor", "e30", "W10", "a" * 2049])
def test_malformed_cursors_fail_explicitly(inventory, cursor):
    with pytest.raises(KnowledgeQueryError):
        page(inventory, cursor=cursor)


@pytest.mark.parametrize("device", [False, True])
def test_scan_history_and_finding_ids_exist_for_both_target_kinds(device):
    db = KnowledgeDB()
    scope = "device_target_id" if device else "target_id"
    fid = str(uuid.UUID(int=10))
    db.insert("scans", id=fid, **{scope: str(TARGET)}, status="completed", created_at=STAMP)
    db.insert("findings", id=fid, **{scope: str(TARGET)}, title="Fixture", severity="high", status="active", last_verification_verdict="exploited", last_seen_at=STAMP)
    assert page(db, "scans", device=device)["rows"][0]["id"] == fid
    assert page(db, "findings", device=device, filters={"verified_only": True, "status": "active"})["rows"][0]["id"] == fid
    assert page(db, "findings", device=device, filters={"status": "resolved"})["count"] == 0


def test_unsupported_surface_is_not_a_clean_empty_result(inventory):
    assert page(inventory, device=True)["supported"] is False


@pytest.mark.parametrize("filters", [{"offset": 100}, {"verified_only": "false"}, {"id": "not-a-uuid"}])
def test_invalid_filters_are_not_silently_ignored(inventory, filters):
    with pytest.raises(KnowledgeQueryError):
        page(inventory, "findings", filters=filters)


# --- Grouped endpoint frontier (opt-in) ------------------------------------------------
# The raw frontier is dominated by repeated samples of a few handlers. The grouped view
# collapses them into route templates without discarding any sample.


def _grouped(db, **kwargs):
    return asyncio.run(query_knowledge_page(db, target_id=TARGET, kind="endpoint_groups", **kwargs))


def _endpoint(db, ident, path, *, method="GET", auth="anonymous", status=401):
    db.insert("endpoints", id=str(uuid.UUID(int=ident)), target_id=str(TARGET), method=method,
              path=path, auth_state=auth, test_status="untested", priority_score=10,
              last_seen_at=STAMP, last_http_status=status)


def test_the_grouped_page_collapses_identifier_samples_but_keeps_the_collection():
    db = KnowledgeDB()
    _endpoint(db, 1, "/api/Cards")
    for i, name in enumerate(("1", "2", "3", "4", "5"), start=2):
        _endpoint(db, i, f"/api/Cards/{name}")
    page_result = _grouped(db)
    templates = {row["route_template"]: row for row in page_result["rows"]}
    assert "/api/Cards/{id}" in templates
    assert templates["/api/Cards/{id}"]["sample_count"] == 5
    assert "/api/Cards" in templates          # the real collection survives
    assert page_result["group_count"] == 2
    assert page_result["sampled_requests"] == 6


def test_the_grouped_page_never_discards_a_sample():
    db = KnowledgeDB()
    _endpoint(db, 1, "/api/Cards")
    for i, name in enumerate(("1", "2", "3", "4"), start=2):
        _endpoint(db, i, f"/api/Cards/{name}")
    row = next(r for r in _grouped(db)["rows"] if r["route_template"] == "/api/Cards/{id}")
    assert len(row["sample_ids"]) == 4        # every member retained for drill-down
    assert row["grouping_evidence"] == "id_shaped_segment"
    assert row["grouping_inferred"] is True
    assert row["representatives"]


def test_the_grouped_page_pages_without_losing_or_repeating_groups():
    db = KnowledgeDB()
    for i in range(1, 31):
        _endpoint(db, i, f"/svc{i}/thing")
    first = _grouped(db, limit=10)
    second = _grouped(db, limit=10, cursor=first["next_cursor"])
    assert first["count"] == 10 and first["has_more"]
    seen = [r["route_template"] for r in first["rows"] + second["rows"]]
    assert len(seen) == len(set(seen)) == 20


def test_the_raw_endpoint_view_is_unchanged_by_the_grouped_one(inventory):
    """Grouping is opt-in: kind="endpoints" still returns individual samples."""
    assert page(inventory)["kind"] == "endpoints"
    assert page(inventory)["count"] == 100


def test_a_device_target_has_no_grouped_endpoint_surface():
    db = KnowledgeDB()
    result = asyncio.run(query_knowledge_page(
        db, target_id=TARGET, kind="endpoint_groups", device=True))
    assert result["supported"] is False


@pytest.mark.parametrize("filters,expected", [
    ({"method": "post"}, {2}), ({"auth_state": "user1"}, {3}),
    ({"test_status": "TESTED"}, {4}), ({"path_contains": "Two"}, {2}),
    ({"id": str(uuid.UUID(int=3))}, {3}),
    ({"method": "GET", "auth_state": "user1", "path_contains": "three"}, {3}),
])
def test_grouped_filters_are_applied_before_projection(filters, expected):
    db = KnowledgeDB()
    _endpoint(db, 1, "/one")
    _endpoint(db, 2, "/two", method="POST")
    _endpoint(db, 3, "/three", auth="user1")
    _endpoint(db, 4, "/four")
    db.db.execute("UPDATE target_endpoints SET test_status='tested' WHERE path='/four'")
    result = _grouped(db, filters=filters)
    ids = {sample for group in result["rows"] for sample in group["sample_ids"]}
    assert ids == {str(uuid.UUID(int=i)) for i in expected}
    assert result["grouping_scope"] == "filtered_inventory"


@pytest.mark.parametrize("filters", [{"method": True}, {"offset": "1"},
                                     {"id": "bad"}, {"verified_only": True}])
def test_grouped_invalid_filters_are_not_ignored(filters):
    with pytest.raises(KnowledgeQueryError):
        _grouped(KnowledgeDB(), filters=filters)


def test_grouped_filter_sql_remains_parameterized():
    db = KnowledgeDB()
    _endpoint(db, 1, "/one")
    value = "' OR 1=1 --"
    assert _grouped(db, filters={"path_contains": value})["count"] == 0
    sql, args = db.calls[-1]
    assert value not in sql and value in args


def test_grouped_pages_and_drill_down_are_target_scoped(inventory):
    result = _grouped(inventory)
    ids = {sample for group in result["rows"] for sample in group["sample_ids"]}
    assert str(uuid.UUID(int=1000)) not in ids
    for sample in sorted(ids)[:3]:
        assert page(inventory, filters={"id": sample})["rows"][0]["id"] == sample


def test_grouped_read_preserves_body_variants_and_duplicate_evidence():
    db = KnowledgeDB()
    for i, location, content_type, verdict in (
        (1, "json", "application/json", "clean"),
        (2, "form", "application/x-www-form-urlencoded", "findings"),
        (3, "json", "application/json", "findings"),
    ):
        db.insert("endpoints", id=str(uuid.UUID(int=i)), target_id=str(TARGET),
                  method="POST", path="/login", auth_state="user1", param_shape="email,password",
                  param_location=location, content_type=content_type, last_verdict=verdict,
                  test_status="tested", priority_score=10, last_seen_at=STAMP)
    result = _grouped(db)
    assert result["count"] == 2 and result["sampled_requests"] == 2
    assert result["inventory_rows_read"] == 3
    assert sorted(sample for group in result["rows"] for sample in group["sample_ids"]) == [
        str(uuid.UUID(int=i)) for i in range(1, 4)
    ]
    json_group = next(g for g in result["rows"] if g["param_location"] == "json")
    assert json_group["prior_results"] == {"clean": 1, "findings": 1}
    assert json_group["representatives"][0]["id"] == str(uuid.UUID(int=3))


def test_grouped_capped_read_is_ordered_and_filters_precede_the_cap(monkeypatch):
    from api.hunt import knowledge

    monkeypatch.setattr(knowledge, "MAX_GROUPING_ROWS", 3)
    db = KnowledgeDB()
    for i in range(10, 0, -1):
        _endpoint(db, i, f"/route{i}", auth="user1" if i > 7 else "anonymous")
    db.db.execute("PRAGMA reverse_unordered_selects=ON")
    result = _grouped(db)
    assert result["inventory_truncated"] is True
    assert {s for g in result["rows"] for s in g["sample_ids"]} == {
        str(uuid.UUID(int=i)) for i in (1, 2, 3)
    }
    filtered = _grouped(db, filters={"auth_state": "user1"})
    assert filtered["inventory_truncated"] is False
    assert filtered["inventory_rows_read"] == 3
    assert all(g["auth_state"] == "user1" for g in filtered["rows"])


def test_grouped_page_walk_is_stable_across_storage_order_and_page_sizes():
    db = KnowledgeDB()
    for i in range(20, 0, -1):
        _endpoint(db, i, f"/route{i}")
    result = _grouped(db, limit=3)
    ids = [g["group_id"] for g in result["rows"]]
    db.db.execute("PRAGMA reverse_unordered_selects=ON")
    while result["has_more"]:
        result = _grouped(db, limit=4, cursor=result["next_cursor"])
        ids.extend(g["group_id"] for g in result["rows"])
    assert len(ids) == len(set(ids)) == 20


def test_grouped_cursors_bind_target_filters_and_kind():
    db = KnowledgeDB()
    for i in range(1, 4):
        _endpoint(db, i, f"/route{i}")
    cursor = _grouped(db, limit=1, filters={"method": "get"})["next_cursor"]
    # Equivalent normalized filters are accepted, different filters are not.
    assert _grouped(db, limit=1, cursor=cursor, filters={"method": "GET"})["count"] == 1
    for kwargs in ({"method": "POST"}, {"auth_state": "user1"}, {}):
        with pytest.raises(KnowledgeQueryError):
            _grouped(db, cursor=cursor, filters=kwargs)
    with pytest.raises(KnowledgeQueryError):
        asyncio.run(query_knowledge_page(db, target_id=OTHER, kind="endpoint_groups",
                                        cursor=cursor, filters={"method": "GET"}))
    with pytest.raises(KnowledgeQueryError):
        page(db, cursor=cursor)


@pytest.mark.parametrize("change", ["insert", "delete", "verdict", "body", "auth"])
def test_changed_grouped_inventory_requires_restart_instead_of_skipping(change):
    db = KnowledgeDB()
    for i in range(1, 5):
        _endpoint(db, i, f"/route{i}")
    cursor = _grouped(db, limit=1)["next_cursor"]
    if change == "insert":
        _endpoint(db, 5, "/new")
    elif change == "delete":
        db.db.execute("DELETE FROM target_endpoints WHERE path='/route1'")
    else:
        column, value = {"verdict": ("last_verdict", "findings"),
                         "body": ("param_shape", "email"), "auth": ("auth_state", "user1")}[change]
        db.db.execute(f"UPDATE target_endpoints SET {column}=? WHERE path='/route4'", (value,))
    with pytest.raises(KnowledgeQueryError, match="restart"):
        _grouped(db, cursor=cursor)
    assert _grouped(db)["ok"] is True


@pytest.mark.parametrize("offset", [True, False, "1", 1.5, -1, None, {}, 20001])
def test_grouped_cursor_offset_requires_a_bounded_integer(offset):
    from api.hunt.knowledge import _decode, _encode

    db = KnowledgeDB()
    _endpoint(db, 1, "/one")
    _endpoint(db, 2, "/two")
    position = _decode(_grouped(db, limit=1)["next_cursor"])
    position["offset"] = offset
    with pytest.raises(KnowledgeQueryError):
        _grouped(db, cursor=_encode(position))


@pytest.mark.parametrize("cursor", ["", "invalid", "e30", "W10", "a" * 2049])
def test_grouped_malformed_cursor_is_a_query_error(cursor):
    with pytest.raises(KnowledgeQueryError):
        _grouped(KnowledgeDB(), cursor=cursor)


@pytest.mark.parametrize("limit", [True, 0, 501, "10"])
def test_grouped_limits_are_validated(limit):
    with pytest.raises(KnowledgeQueryError):
        _grouped(KnowledgeDB(), limit=limit)


def test_grouped_empty_inventory_is_explicit_and_has_no_cursor():
    result = _grouped(KnowledgeDB())
    assert result["rows"] == [] and result["group_count"] == 0
    assert not result["has_more"] and result["next_cursor"] is None
    assert not result["inventory_truncated"]
