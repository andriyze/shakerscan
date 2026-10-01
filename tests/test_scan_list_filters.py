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


def test_list_scans_uses_the_shared_filters():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    assert "status=status, target_id=target_id, target=target," in source
    assert "query += filter_sql\n        count_query += filter_sql" in source


def test_exposure_links_open_the_whole_finding_history_they_count():
    source = (ROOT / "api" / "exposure" / "router.py").read_text(encoding="utf-8")
    assert source.count("&status=active&freshness=all\"") == 2
