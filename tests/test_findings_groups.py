"""GET /findings?group_by=issue: request validation and how a page of groups is assembled.

Unit fixtures (a fake connection that answers canned rows, no PostgreSQL). The grouping itself, and
its equality with the Findings page's browser grouping, is checked on real PostgreSQL in
tests/test_findings_groups_postgres.py.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from finding_routes import list_groups, list_query  # noqa: E402
import list_contract  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _cursor_key():
    list_contract.configure_cursor_key(b"u" * 32)
    yield
    list_contract.configure_cursor_key(None)


def _project(row):
    return {"proof_state": "unverified", "is_verified": False, "is_suspected": False}


class FakeConn:
    """Answers the grouped read's queries: no undetermined rows, the given groups, their rows."""

    def __init__(self, groups, *, groups_total=None, findings_total=None):
        self.groups = groups
        self.groups_total = len(groups) if groups_total is None else groups_total
        self.findings_total = findings_total if findings_total is not None else sum(
            g["member_count"] for g in groups)
        self.queries: list[str] = []

    async def fetchval(self, query, *args):
        self.queries.append(query)
        return T0

    async def fetch(self, query, *args):
        self.queries.append(query)
        if "GROUP BY" in query:
            limit = int(query.rsplit("LIMIT", 1)[1])
            if not self.groups:
                return [{"lead_id": None, "groups_total": 0, "findings_total": 0}]
            return [{**g, "groups_total": self.groups_total, "findings_total": self.findings_total,
                     "__list_sort": g["lead_s0"], "__list_sort_1": g["lead_s1"], "__list_id": g["lead_id"]}
                    for g in self.groups[:limit]]
        if "_proof_undetermined" in query and "unnest" in query:  # lead rows
            return [{"id": i, "title": "Lead", "_proof_undetermined": False, "_proof_evidence": None,
                     "_proof_severity": "high", "_proof_verdict": None, "_proof_mode": None}
                    for i in args[0]]
        if "latest_retest_verdict" in query:  # member locations
            return [{"id": i, "url": f"https://app.test/{i}", "last_seen_at": T0,
                     "latest_retest_verdict": None} for i in reversed(args[0])]
        return []  # no undetermined rows


def _group(index, *, members=3, listed=None):
    ids = [uuid.UUID(int=index * 1000 + n) for n in range(listed or members)]
    return {
        "k_title": f"issue {index}", "k_severity": "high", "k_subject": "t-1", "k_proof": "unverified",
        "k_status": "active", "member_count": members, "last_seen_at": T0, "first_seen_at": T0,
        "member_ids": ids, "lead_id": ids[0], "lead_s0": 4, "lead_s1": T0 - timedelta(seconds=index),
    }


def _page(**kwargs):
    defaults = dict(limit=2, cursor=None, sort=None, fields=None, count="exact", since=None)
    defaults.update(kwargs)
    return list_contract.page_params(**defaults)


def _run(conn, page, **kwargs):
    return asyncio.run(list_groups.groups_page(
        conn, page, filters=list_query.FindingFilters(**kwargs), proof_states=None, project=_project))


def test_group_by_takes_issue_only():
    assert list_groups.parse_group_by(None) is None
    assert list_groups.parse_group_by(" Issue ") == "issue"
    for bad in ("", "title", "issue,subject"):
        with pytest.raises(HTTPException) as caught:
            list_groups.parse_group_by(bad)
        assert caught.value.status_code == 400 and caught.value.detail["error"] == "invalid_group_by"


def test_groups_sort_like_the_findings_list_under_their_own_cursor_scope():
    groups, findings = list_groups.FINDING_GROUPS_LIST, list_query.FINDINGS_LIST
    assert set(groups.sorts) == set(findings.sorts) and groups.default_sort == findings.default_sort
    for name, key in findings.sorts.items():
        assert [kind for _e, kind in groups.sorts[name].columns] == [kind for _e, kind in key.columns]
    assert groups.scope != findings.scope
    assert not set(groups.fields) & list_contract.LIST_HEAVY_FIELDS


def test_a_page_of_groups_carries_its_lead_members_and_counts():
    big = _group(1, members=80, listed=list_groups.GROUP_MEMBER_LIMIT)
    conn = FakeConn([big, _group(2), _group(3)], groups_total=3)
    body = _run(conn, _page())
    assert body["total"] == 3 and body["total_kind"] == "exact" and body["findings_total"] == 86
    assert body["has_more"] is True and body["next_cursor"]
    first, second = body["items"]
    assert first["count"] == 80 and first["member_ids_truncated"] is True
    assert len(first["member_ids"]) == list_groups.GROUP_MEMBER_LIMIT
    # Members come back in the group's order (lead first), whatever order the database read them.
    assert [m["id"] for m in first["members"]] == first["member_ids"]
    assert first["lead"]["id"] == first["member_ids"][0] and "_proof_undetermined" not in first["lead"]
    assert second["member_ids_truncated"] is False
    assert set(first) == set(list_groups.FINDING_GROUPS_LIST.fields)
    # The next page continues after the last lead, under the same filters only.
    following = _run(FakeConn([_group(3)]), _page(cursor=body["next_cursor"], count="none"))
    assert following["total_kind"] == "none" and "findings_total" not in following
    with pytest.raises(HTTPException) as caught:
        _run(FakeConn([]), _page(cursor=body["next_cursor"], count="none"), status="resolved")
    assert caught.value.detail["error"] == "cursor_mismatch"


def test_an_empty_match_set_is_an_empty_exact_page():
    body = _run(FakeConn([]), _page())
    assert body["items"] == [] and body["total"] == 0 and body["findings_total"] == 0
    assert body["has_more"] is False and body["next_cursor"] is None


def test_fields_are_refused_before_any_query():
    conn = FakeConn([])
    with pytest.raises(HTTPException) as caught:
        _run(conn, _page(fields="id,title"))
    assert caught.value.detail["error"] == "invalid_fields" and conn.queries == []


def test_since_is_refused_before_any_query():
    conn = FakeConn([])
    with pytest.raises(HTTPException) as caught:
        _run(conn, _page(since=T0))
    assert caught.value.status_code == 400 and caught.value.detail["error"] == "invalid_since"
    assert conn.queries == []


def test_without_a_proof_filter_too_many_unreadable_rows_are_keyed_not_refused(monkeypatch):
    monkeypatch.setattr(list_query, "UNDETERMINED_LIMIT", 0)

    class Unreadable(FakeConn):
        async def fetch(self, query, *args):
            if "AS latest_retest_mode" in query and "unnest" not in query:  # undetermined rows
                self.queries.append(query)
                return [{"id": uuid.uuid4(), "evidence": None, "severity": "high",
                         "last_verification_verdict": None, "latest_retest_mode": None}]
            return await super().fetch(query, *args)

    conn = Unreadable([_group(1)])
    body = _run(conn, _page())
    assert body["total"] == 1
    grouped = next(q for q in conn.queries if "GROUP BY" in q)
    assert f"'{list_groups.UNDETERMINED_PROOF_KEY}'" in grouped and "row_number()" in grouped
