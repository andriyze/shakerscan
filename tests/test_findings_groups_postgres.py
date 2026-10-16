"""GET /findings?group_by=issue on real PostgreSQL: the browser's groups, grouped in SQL.

Uses the disposable database of tests/test_findings_list_scale_postgres.py
(FINDINGS_LIST_TEST_DATABASE_URL on localhost/shakerscan_findings_list_test, schema from db/init.sql
plus the startup migrations) and its dataset, with rows added that repeat one issue: titles that
differ only in case and surrounding whitespace, findings with no target whose subject is their URL
host, groups larger than the member list, and triage blocks only Python can read.

The reference is the Findings page's own algorithm (``findingGroupKey``/``groupFindings`` in
ui/src/lib/findingGroups.ts), restated below in Python and applied to the whole matching set read
through the plain list/v1 walk. Walking the grouped pages must give exactly its groups, in its
order, with its counts, leads, member order and seen times, for every sort and several filters.
"""

from __future__ import annotations

from datetime import timedelta
import json
import random
import uuid

import pytest
from fastapi import HTTPException

from tests import test_findings_list_scale_postgres as scale

pytestmark = scale.pytestmark

from finding_routes import list_groups, list_query, list_schema  # noqa: E402
import finding_routes.router as findings_router  # noqa: E402
import list_contract  # noqa: E402

# ``new URL(url).host`` as the WHATWG URL parser (browser, Node) answers it; None: it throws.
BROWSER_HOSTS = {
    "https://App.Example.test:443/a?x=1": "app.example.test",
    "https://app.example.test/b": "app.example.test",
    "http://app.example.test:80/c": "app.example.test",
    "http://app.example.test:8080/d": "app.example.test:8080",
    "https://user:pw@APP.example.test/x": "app.example.test",
    "hf://Org/model": "Org",
    "not a url": None,
    "https://other.example.test": "other.example.test",
    "file:///etc/passwd": "",
    "mailto:a@b.test": "",
    "wss://Chat.example.test:443/s": "chat.example.test",
    "ftp://files.example.test:21/f": "files.example.test",
    "https://app.example.test:/e": "app.example.test",
}
# String.prototype.trim(): ECMAScript WhiteSpace and LineTerminator.
JS_WHITESPACE = "\t\n\x0b\x0c\r \xa0 " + "".join(chr(c) for c in range(0x2000, 0x200B)) + \
    "    　﻿"
TITLES = ["Reflected XSS", "  reflected xss ", "REFLECTED XSS \n", "Open redirect", "open redirect "]


@pytest.fixture(autouse=True)
def _cursor_key():
    list_contract.configure_cursor_key(b"g" * 32)
    list_schema.reset_severity_rank_ready()
    yield
    list_contract.configure_cursor_key(None)
    list_schema.reset_severity_rank_ready()


async def add_repeats(conn, *, rows: int = 420, big_group: int = 61) -> None:
    """Rows that group: few titles and subjects, URL-host subjects, one group past the member list."""
    rng = random.Random(4242)
    t0 = scale.T0
    device = await conn.fetchval("SELECT id FROM device_targets LIMIT 1")
    owners = [("target", scale.WEB[0]), ("target", scale.WEB[2]), ("ai", scale.AI), ("device", device),
              *[("url", url) for url in BROWSER_HOSTS], ("url", None), ("url", "")]
    evidence = [None, {"matcher": "x"}, {"proof_of_exploitation": True}, {"triage": {"suspected": True}},
                scale.UNDETERMINED]
    for index in range(rows + big_group):
        big = index >= rows
        kind, owner = ("target", scale.WEB[1]) if big else rng.choice(owners)
        url = owner if kind == "url" else f"https://app.alpha.test/r/{index}"
        await conn.execute(
            """INSERT INTO findings (id, target_id, ai_target_id, device_target_id, fingerprint, title, severity,
                                     cvss_score, tool, url, evidence, status, source, last_verification_verdict,
                                     first_seen_at, last_seen_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'nuclei', $9, $10::jsonb, $11, 'scan', $12, $13, $14)""",
            uuid.uuid4(), owner if kind == "target" else None, owner if kind == "ai" else None,
            owner if kind == "device" else None, f"repeat-{index}",
            "Exposed secret" if big else rng.choice(TITLES),
            "critical" if big else rng.choice(["high", "high", "medium", "Critical"]),
            rng.choice([None, 9.8, 5.0]), url,
            None if big else json.dumps(rng.choice(evidence)) if rng.random() < 0.9 else None,
            "active" if big else rng.choice(["active", "active", "resolved"]),
            None if big else rng.choice([None, "exploited", "likely_fixed"]),
            t0 - timedelta(seconds=rng.randrange(10_000)),
            None if index == 3 else t0 + timedelta(seconds=rng.randrange(1, 50_000)),
        )
    await conn.execute("ANALYZE findings")


def browser_key(row: dict) -> tuple:
    """findingGroupKey: title, severity, subject, proof_state, status (every row here is a finding)."""
    host = ""
    for raw in (row.get("url"), row.get("target_url")):
        if raw:
            parsed = BROWSER_HOSTS.get(raw, "unlisted") if not raw.startswith("https://app.alpha.test/") \
                else "app.alpha.test"
            assert parsed != "unlisted", raw
            if parsed is None:
                continue
            host = parsed
            break
    subject = row.get("target_id") or row.get("ai_target_id") or row.get("device_target_id") \
        or row.get("target_url") or host or ""
    return (str(row.get("title") or "").strip(JS_WHITESPACE).lower(), str(row.get("severity") or ""),
            str(subject), str(row.get("proof_state") or ""), str(row.get("status") or ""))


def browser_groups(rows: list[dict]) -> list[dict]:
    """groupFindings over the whole set: groups in first-member order, members in list order."""
    groups: dict[tuple, dict] = {}
    for row in rows:
        group = groups.setdefault(browser_key(row), {"lead": row, "members": []})
        group["members"].append(row)
    return list(groups.values())


async def full_list(pool, monkeypatch, *, sort, **filters) -> list[dict]:
    rows, cursor = [], None
    while True:
        params = {"sort": sort, "limit": 200, **filters}
        params.update({"cursor": cursor} if cursor else {"count": "none"})
        page, _ = await scale.route(pool, monkeypatch, **params)
        rows += page["items"]
        cursor = page["next_cursor"]
        if not cursor:
            return rows


async def group_walk(pool, monkeypatch, *, sort, limit, **filters) -> tuple[list[dict], dict]:
    groups, cursor, first = [], None, None
    while True:
        params = {"sort": sort, "limit": limit, "group_by": "issue", **filters}
        params.update({"cursor": cursor} if cursor else {"count": "exact"})
        page, _ = await scale.route(pool, monkeypatch, **params)
        first = first or page
        assert len(page["items"]) <= limit
        groups += page["items"]
        cursor = page["next_cursor"]
        assert page["has_more"] is bool(cursor)
        if not cursor:
            return groups, first


def _summary(group: dict) -> tuple:
    return (group["title_key"], group["severity"], group["subject"], group["proof_state"], group["status"])


FILTERS = [{}, {"status": "active"}, {"severity": "high,critical"}, {"target_id": str(scale.WEB[1])},
           {"proof_state": "suspected"}, {"search": "redirect"}, {"source_type": "dast", "status": "active"}]
SORTS = ["-severity", "severity", "-last_seen", "last_seen", "-first_seen", "first_seen", "-cvss", "cvss"]


def test_server_groups_equal_the_browser_grouping_of_every_match(monkeypatch):
    async def scenario(conn, pool):
        await add_repeats(conn)
        checked = 0
        for filters in FILTERS:
            for sort in SORTS:
                rows = await full_list(pool, monkeypatch, sort=sort, **filters)
                expected = browser_groups(rows)
                groups, first = await group_walk(pool, monkeypatch, sort=sort, limit=37, **filters)
                assert first["total_kind"] == "exact" and first["total"] == len(expected), (filters, sort)
                assert first["findings_total"] == len(rows)
                assert [g["lead"]["id"] for g in groups] == [e["lead"]["id"] for e in expected], (filters, sort)
                for group, reference in zip(groups, expected):
                    members = reference["members"]
                    assert _summary(group) == browser_key(reference["lead"]), (filters, sort)
                    assert group["lead"] == reference["lead"]
                    assert group["count"] == len(members)
                    assert group["member_ids"] == [m["id"] for m in members][: list_groups.GROUP_MEMBER_LIMIT]
                    assert group["member_ids_truncated"] is (len(members) > list_groups.GROUP_MEMBER_LIMIT)
                    assert [m["id"] for m in group["members"]] == group["member_ids"]
                    assert [m["url"] for m in group["members"]] == [m["url"] for m in members][:50]
                    assert [m["latest_retest_verdict"] for m in group["members"]] == \
                        [m["latest_retest_verdict"] for m in members][:50]
                    seen = [m["last_seen_at"] for m in members if m["last_seen_at"] is not None]
                    assert group["last_seen_at"] == (max(seen) if seen else None)
                    assert group["first_seen_at"] == min(m["first_seen_at"] for m in members)
                checked += len(groups)
        assert checked > 2_000
        # The dataset exercises what the key normalises and what the member list bounds.
        everything = browser_groups(await full_list(pool, monkeypatch, sort="-severity"))
        assert any(len(g["members"]) > list_groups.GROUP_MEMBER_LIMIT for g in everything)
        assert len({m["title"] for g in everything for m in g["members"]
                    if browser_key(m)[0] == "reflected xss"}) == 3
        assert {"app.example.test", "app.example.test:8080", "Org", "chat.example.test", ""} <= \
            {browser_key(g["lead"])[2] for g in everything}
        assert any(m["id"] for g in everything for m in g["members"]
                   if m["proof_state"] and m["url"] in BROWSER_HOSTS)

    scale.run(scenario)


def test_page_size_does_not_change_the_groups_and_rows_stay_summaries(monkeypatch):
    async def scenario(conn, pool):
        await add_repeats(conn)
        reference, _ = await group_walk(pool, monkeypatch, sort="-severity", limit=200)
        for limit in (1, 13, 50):
            groups, _ = await group_walk(pool, monkeypatch, sort="-severity", limit=limit)
            assert groups == reference
        lead_fields = set(reference[0]["lead"])
        assert lead_fields == set(list_query.FINDINGS_LIST.fields)
        assert not lead_fields & (list_contract.LIST_HEAVY_FIELDS | set(list_query.FINDING_DETAIL_COLUMNS))
        assert set(reference[0]) == set(list_groups.FINDING_GROUPS_LIST.fields)
        # Without count= (a later page) there is no total and no findings_total.
        page, _ = await scale.route(pool, monkeypatch, group_by="issue", sort="-severity", count="none", limit=5)
        assert page["total_kind"] == "none" and "total" not in page and "findings_total" not in page
        # The unranked order (an upgraded database still being ranked) gives the same groups.
        async with pool.acquire() as raw, list_query.without_jit(raw):
            page = list_contract.page_params(limit=200, cursor=None, sort="-severity", fields=None,
                                             count="exact", since=None)
            filters = list_query.FindingFilters()
            ranked = await list_groups.groups_page(raw, page, filters=filters, proof_states=None,
                                                   project=findings_router.finding_proof_fields)
            unranked = await list_groups.groups_page(raw, page, filters=filters, proof_states=None,
                                                     project=findings_router.finding_proof_fields, ranked=False)
        assert [g["lead"]["id"] for g in ranked["items"]] == [g["lead"]["id"] for g in unranked["items"]]
        assert ranked["next_cursor"] == unranked["next_cursor"]

    scale.run(scenario)


def test_the_grouped_read_refuses_what_it_does_not_serve(monkeypatch):
    async def scenario(conn, pool):
        await add_repeats(conn, rows=60, big_group=0)

        async def refused(**params):
            with pytest.raises(HTTPException) as caught:
                await scale.route(pool, monkeypatch, **params)
            assert caught.value.status_code == 400, params
            return caught.value.detail

        page, _ = await scale.route(pool, monkeypatch, group_by="issue", count="exact", limit=5)
        cursor = page["next_cursor"]
        assert cursor
        detail = await refused(group_by="issue", cursor=cursor, status="active")
        assert detail["error"] == "cursor_mismatch"
        assert (await refused(group_by="issue", cursor=cursor, sort="-last_seen"))["error"] == "cursor_mismatch"
        # A group cursor never continues the plain list, nor a plain cursor the groups.
        assert (await refused(cursor=cursor))["error"] == "cursor_mismatch"
        plain, _ = await scale.route(pool, monkeypatch, count="none", limit=5)
        assert (await refused(group_by="issue", cursor=plain["next_cursor"]))["error"] == "cursor_mismatch"
        assert (await refused(group_by="issue", fields="id,title"))["error"] == "invalid_fields"
        assert (await refused(group_by="title"))["error"] == "invalid_group_by"
        assert "offset" in await refused(group_by="issue", offset=10)
        assert "sort_by" in await refused(group_by="issue", sort_by="severity")
        # group_by alone (no other list/v1 parameter) is a list/v1 request.
        page, _ = await scale.route(pool, monkeypatch, group_by="issue")
        assert set(page) >= {"items", "next_cursor", "has_more", "total_kind", "generated_at"}
        # An empty match set is an empty page with an exact zero.
        empty, _ = await scale.route(pool, monkeypatch, group_by="issue", count="exact", search="no-such-title")
        assert empty["items"] == [] and empty["total"] == 0 and empty["findings_total"] == 0
        assert empty["has_more"] is False and empty["next_cursor"] is None

    scale.run(scenario)


def test_the_grouped_read_groups_the_match_set_in_one_aggregate(monkeypatch):
    async def scenario(conn, pool):
        await add_repeats(conn)
        _, queries = await scale.route(pool, monkeypatch, group_by="issue", count="exact", limit=20)
        grouped = [q for q, _ in queries if "GROUP BY" in q]
        assert len(grouped) == 1
        # Leads and member locations are read for the page's groups only, by id.
        by_id = [q for q, _ in queries if "unnest($1::uuid[])" in q]
        assert len(by_id) == 2
        assert all(len(args[0]) <= 20 * list_groups.GROUP_MEMBER_LIMIT for q, args in queries
                   if "unnest($1::uuid[])" in q)

    scale.run(scenario)
