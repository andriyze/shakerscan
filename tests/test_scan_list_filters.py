"""GET /scans filters, including the exact target filter."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from api.scan_list_filters import scan_list_filters

ROOT = Path(__file__).resolve().parents[1]


def test_filters_are_numbered_in_order_from_one():
    target = str(uuid.uuid4())
    sql, values = scan_list_filters(status="completed", target_id=target, target="honey",
                                    root_domain="example.com", created_within_days=7)
    assert sql == (" AND s.status = $1 AND s.target_id = $2 AND s.target_url ILIKE $3"
                   " AND t.root_domain = $4 AND s.created_at >= NOW() - INTERVAL '1 day' * $5")
    assert values == ["completed", uuid.UUID(target), "%honey%", "example.com", 7]


def test_no_filters_add_nothing_and_a_bad_target_id_is_refused():
    assert scan_list_filters() == ("", [])
    with pytest.raises(ValueError, match="target_id must be a UUID"):
        scan_list_filters(target_id="not-a-uuid")


def test_list_scans_uses_the_same_shared_filters_for_rows_and_count(monkeypatch):
    import asyncio
    from contextlib import asynccontextmanager
    from api import api as module
    calls = []
    class Conn:
        async def fetch(self, query, *values):
            calls.append((query, values))
            return []
        async def fetchval(self, query, *values):
            calls.append((query, values))
            return 7
    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Conn()
    monkeypatch.setattr(module, 'db_pool', Pool())
    target_id = str(uuid.uuid4())
    filters = dict(status='completed', target_id=target_id, target='needle',
                   root_domain='example.com', created_within_days=7)
    result = asyncio.run(module.list_scans(**filters, limit=10, offset=3))
    sql, values = scan_list_filters(**filters)
    assert result['total'] == 7 and result['scans'] == []
    assert len(calls) == 2
    assert all(sql in query and list(params[:len(values)]) == values for query, params in calls)
    assert calls[0][1][-2:] == (10, 3)
    assert calls[1][1] == tuple(values)


def test_exposure_links_open_the_whole_finding_history_they_count():
    source = (ROOT / "api" / "exposure" / "router.py").read_text(encoding="utf-8")
    assert source.count("&status=active&freshness=all\"") == 2
