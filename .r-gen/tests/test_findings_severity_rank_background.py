"""The first 2.11 start ranks existing findings after the API serves, not under the startup lock.

At 500k findings the one-time severity rank kept the API down for about a minute on the first 2.11
start (scale lane, 2026-10-15). It now runs as the API's background maintenance task; until it
records its marker the findings list orders by ``finding_severity_rank(severity)``, the value the
column holds once ranked. Unit fixtures (fake connections, no PostgreSQL); the real database
behaviour, including identical list answers, is in tests/test_findings_list_scale_postgres.py.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from finding_routes import list_query, list_schema  # noqa: E402
import list_contract  # noqa: E402


class FakeConn:
    def __init__(self, *, marker: bool = False, findings: bool = True, lock: bool = True):
        self.marker = marker
        self.findings = findings
        self.lock = lock
        self.statements: list[str] = []

    async def fetchval(self, query, *args):
        self.statements.append(query)
        if "app_schema_migrations" in query:
            return self.marker
        if "NOT EXISTS (SELECT 1 FROM findings)" in query:
            return not self.findings
        if "pg_try_advisory_lock" in query:
            return self.lock
        raise AssertionError(query)

    async def fetch(self, query, *args):
        self.statements.append(query)
        return []

    async def execute(self, query, *args):
        self.statements.append(query)
        if "INSERT INTO app_schema_migrations" in query:
            self.marker = True
        return "UPDATE 0"

    def transaction(self):
        @asynccontextmanager
        async def tx():
            yield
        return tx()


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


@pytest.fixture(autouse=True)
def _fresh_readiness():
    list_schema.reset_severity_rank_ready()
    yield
    list_schema.reset_severity_rank_ready()


def test_the_startup_step_never_ranks_existing_findings():
    conn = FakeConn(marker=False, findings=True)
    asyncio.run(list_schema.finish_findings_list_schema(conn))
    assert not [s for s in conn.statements if "UPDATE findings" in s or "SELECT id FROM findings" in s]
    assert conn.marker is False  # left to the background task, which records it when done


def test_a_database_without_findings_is_ranked_at_startup():
    conn = FakeConn(marker=False, findings=False)
    asyncio.run(list_schema.finish_findings_list_schema(conn))
    assert conn.marker is True


def test_a_ranked_database_costs_the_startup_one_marker_read():
    conn = FakeConn(marker=True)
    asyncio.run(list_schema.finish_findings_list_schema(conn))
    assert len(conn.statements) == 1


def test_the_background_rank_records_the_marker_and_a_busy_lock_is_skipped():
    conn = FakeConn(marker=False)
    asyncio.run(list_schema.repair_severity_rank_in_background(FakePool(conn), delay=3600))
    assert conn.marker is True  # a first rank does not wait out the repair delay
    busy = FakeConn(marker=False, lock=False)
    asyncio.run(list_schema.repair_severity_rank(FakePool(busy)))
    assert busy.marker is False and not [s for s in busy.statements if "UPDATE findings" in s]


def test_readiness_is_cached_once_true_and_rechecked_sparingly_while_false(monkeypatch):
    conn = FakeConn(marker=False)
    assert asyncio.run(list_schema.severity_rank_ready(conn)) is False
    assert asyncio.run(list_schema.severity_rank_ready(conn)) is False
    assert len(conn.statements) == 1  # within the re-check interval: no query
    conn.marker = True
    monkeypatch.setattr(list_schema, "_RANK_RECHECK_SECONDS", 0.0)
    assert asyncio.run(list_schema.severity_rank_ready(conn)) is True
    count = len(conn.statements)
    for _ in range(3):
        assert asyncio.run(list_schema.severity_rank_ready(conn)) is True
    assert len(conn.statements) == count  # steady state: no query per request


def test_an_unreadable_marker_reads_as_not_ready():
    class Broken(FakeConn):
        async def fetchval(self, query, *args):
            raise RuntimeError("relation does not exist")

    assert asyncio.run(list_schema.severity_rank_ready(Broken())) is False


def test_the_unranked_order_is_the_function_the_rank_is_computed_from():
    ranked = list_query.legacy_order(None, "desc")
    unranked = list_query.legacy_order(None, "desc", ranked=False)
    assert ranked[0] == ("f.severity_rank", "DESC")
    assert unranked[0] == ("finding_severity_rank(f.severity)", "DESC")
    assert ranked[1:] == unranked[1:]
    assert list_query.legacy_order("last_seen", "asc", ranked=False) == list_query.legacy_order("last_seen", "asc")
    assert list_query.FINDINGS_LIST_UNRANKED.sorts["severity"].sql == "finding_severity_rank(f.severity)"
    for name in ("last_seen", "first_seen", "cvss"):
        assert list_query.FINDINGS_LIST_UNRANKED.sorts[name] == list_query.FINDINGS_LIST.sorts[name]


def test_a_cursor_from_the_unranked_list_continues_in_the_ranked_one():
    list_contract.configure_cursor_key(b"u" * 32)
    try:
        page = list_contract.Page(limit=2, cursor=None, sort="-severity", fields=None, count="none", since=None)
        plan = list_query.FINDINGS_LIST_UNRANKED.plan(page, filters={"status": "active"})
        seen = datetime(2026, 10, 1, tzinfo=timezone.utc)
        rows = [{**{name: None for name in plan.fields}, "__list_sort": 5, "__list_sort_1": seen,
                 "__list_id": uuid.UUID(int=index + 1)} for index in range(3)]
        cursor = plan.envelope(rows)["next_cursor"]
        assert cursor
        resumed = list_query.FINDINGS_LIST.plan(
            list_contract.Page(limit=2, cursor=cursor, sort="-severity", fields=None, count="none", since=None),
            filters={"status": "active"})
        assert resumed.position[0] == 5 and resumed.sort_expr == "f.severity_rank"
    finally:
        list_contract.configure_cursor_key(None)
