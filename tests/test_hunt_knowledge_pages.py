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
