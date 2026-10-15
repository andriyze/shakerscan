"""Server reads the UI uses instead of approximating in the browser (2.11), on real PostgreSQL.

Real PostgreSQL only: UI_ENDPOINTS_TEST_DATABASE_URL on localhost naming
``shakerscan_ui_endpoints_test``. The module resets that database's public schema, installs
db/init.sql plus the startup migrations and seeds ``.invalid``/private hosts only.

What it proves:

* the SQL cohort (``target_cohort_sql``) equals the Python cohort every target row shows, over
  metadata and host shapes that exercise truthiness, case, whitespace, the development/test
  mapping and the private/special-purpose address registries;
* ``/targets/grouped`` list/v1 filters by cohort, sorts by ASM coverage, keeps only inventoried
  domains and summarises coverage over every filtered target (not one page), equal to a Python
  oracle built from the per-target coverage the rows show;
* the dashboard's per-cohort recent scans and the timeline's cohort filter equal the global
  lists filtered by each row's Python cohort.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("UI_ENDPOINTS_TEST_DATABASE_URL")
REQUIRED = os.environ.get("UI_ENDPOINTS_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_ui_endpoints_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable ui-endpoints PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import list_contract as lc  # noqa: E402

HOSTS = [
    "https://app{n}.example.invalid", "http://localhost:{p}", "http://10.1.{n}.4", "http://[::1]:{p}",
    "https://[fe80::{n}]/x", "http://100.64.{n}.1", "http://intranet{n}", "http://host.docker.internal:{p}",
    "https://svc{n}.test", "http://192.0.0.9:{p}", "http://192.0.0.{n}", "https://user:pw@shop{n}.example.invalid:8443/p",
    "app{n}.example.invalid/path", "10.9.{n}.1:8080", "https://8.8.{n}.8", "https://[2001:db8::{n}]",
    "https://[::ffff:10.0.0.{n}]", "https://x{n}.internal", "https://x{n}.local.", "weird{n}",
]
METADATA = [
    None, {}, {"cohort": "Production "}, {"cohort": "development"}, {"cohort": "TEST"}, {"cohort": "bogus"},
    {"cohort": 0}, {"cohort": False}, {"cohort": ""}, {"cohort": None}, {"cohort": []}, {"cohort": {}},
    {"cohort": 1}, {"cohort": "internal"}, {"cohort": "unclassified"}, {"environment": "staging"},
    {"environment": " Development\t"}, {"environment": "other"}, {"environment": 0}, {"environment": "demo"},
    {"cohort": "", "environment": "calibration"}, {"cohort": "lab", "environment": "production"}, [1, 2], "text",
    {"cohort": " staging"}, {"environment": "test"},
]


async def _connect():
    return await asyncpg.connect(require_disposable_database(DSN, DATABASE))


def _run(fn):
    async def wrapper():
        conn = await _connect()
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(wrapper())


SEED_SQL = """
-- ASM inventories on a few targets, with completed and partial attempts.
INSERT INTO target_endpoints(target_id, method, path, fingerprint, test_status)
SELECT t.id, 'GET', '/e/' || e, 'fp-' || t.id || '-' || e,
       (ARRAY['untested','tested','stale','gone','tested'])[1 + (e + t.rn) % 5]
FROM (SELECT id, row_number() OVER (ORDER BY url, id) AS rn FROM targets) t, generate_series(1, 12) e
WHERE t.rn % 7 = 0 AND e <= 4 + t.rn % 9;
INSERT INTO asm_endpoint_attempts(endpoint_id, status, started_at, completed_at, scanner_telemetry_json)
SELECT te.id, (ARRAY['completed','partial','completed'])[1 + abs(hashtext(te.id::text)) % 3],
       NOW() - INTERVAL '1 day', NOW() - INTERVAL '23 hours',
       CASE WHEN abs(hashtext(te.id::text)) % 4 = 0 THEN '{}'::jsonb ELSE '{"per_endpoint_telemetry": true}'::jsonb END
FROM target_endpoints te WHERE abs(hashtext(te.id::text)) % 3 <> 0;
-- Completed scans: one or two per target, newest first by target order; URL-only and AI scans.
INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role, created_at, completed_at,
                  execution_context, coverage_json)
SELECT t.id, t.url, 'completed', 'standard', 'web_dast', 'standalone',
       TIMESTAMPTZ '2026-10-01' - (t.rn * 3 + k) * INTERVAL '1 minute',
       TIMESTAMPTZ '2026-10-01' - (t.rn * 3 + k) * INTERVAL '1 minute' + INTERVAL '2 minutes', '{}', '{}'
FROM (SELECT id, url, row_number() OVER (ORDER BY url, id) AS rn FROM targets) t, generate_series(0, 1) k;
INSERT INTO ai_targets(name, endpoint_url, metadata_json) VALUES
    ('ai prod', 'https://ai.example.invalid/chat', '{"environment": "production"}'),
    ('ai local', 'http://127.0.0.1:9000/chat', '{}');
INSERT INTO scans(target_id, ai_target_id, target_url, status, scan_type, run_kind, scan_role, created_at,
                  completed_at, execution_context, coverage_json)
SELECT NULL, CASE WHEN g % 3 = 0 THEN (SELECT id FROM ai_targets ORDER BY name LIMIT 1 OFFSET g % 2) END,
       (ARRAY['https://orphan.example.invalid', 'http://192.168.3.3', 'https://o2.example.invalid'])[1 + g % 3],
       'completed', 'standard', 'web_dast', 'standalone',
       TIMESTAMPTZ '2026-10-01' - g * INTERVAL '7 minutes' + INTERVAL '30 seconds',
       TIMESTAMPTZ '2026-10-01' - g * INTERVAL '7 minutes' + INTERVAL '1 minute', '{}', '{}'
FROM generate_series(1, 12) g;
"""


@pytest.fixture(scope="module", autouse=True)
def _database():
    async def setup():
        conn = await _connect()
        try:
            await conn.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            await conn.execute((ROOT / "db" / "init.sql").read_text())
            import retest_contract
            from targets.asset_migration import BoundConnectionPool
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            rows = []
            n = 0
            for index, host in enumerate(HOSTS):
                for meta_index, metadata in enumerate(METADATA):
                    if (index + meta_index) % 3:
                        continue
                    n += 1
                    url = host.format(n=n % 250, p=8000 + n)
                    root = f"g{n % 9}.example.invalid"
                    rows.append((url, f"t{n}", root, n <= 9, json.dumps(metadata)))  # one root per group
            await conn.executemany(
                "INSERT INTO targets(url, name, root_domain, is_root, metadata_json, asm_enabled) "
                "VALUES ($1, $2, $3, $4, $5::jsonb, true) ON CONFLICT DO NOTHING",
                rows,
            )
            await conn.execute(SEED_SQL)
            await conn.execute("ANALYZE")
        finally:
            await conn.close()

    lc.configure_cursor_key(b"u" * 32)
    asyncio.run(setup())
    yield
    lc.configure_cursor_key(None)


def _page(**kwargs) -> lc.Page:
    values = {"limit": 50, "cursor": None, "sort": None, "fields": None, "count": "none", "since": None}
    values.update(kwargs)
    return lc.Page(**values)


async def _python_cohorts(conn) -> dict[str, str]:
    """The oracle: the cohort the target row itself shows (``_public_target_row``)."""
    from targets import router as targets_router
    rows = await conn.fetch("SELECT id, url, name, root_domain, discovery_source, metadata_json FROM targets")
    return {str(row["id"]): targets_router._public_target_row(dict(row))["cohort"] for row in rows}


def test_sql_cohort_equals_the_python_cohort_of_every_row():
    import target_cohort_sql as tcs

    async def body(conn):
        filled = await tcs.fill_url_classes(conn)
        assert filled > 0
        assert await tcs.fill_url_classes(conn) == 0  # a second read classifies nothing new
        expected = await _python_cohorts(conn)
        params = lc.SqlParams()
        version = params.add(tcs.CLASSIFIER_VERSION)
        rows = await conn.fetch(
            f"SELECT t.id, {tcs.target_cohort_sql('t', version)} AS cohort FROM targets t", *params.values)
        got = {str(row["id"]): row["cohort"] for row in rows}
        assert got == expected
        # The fixture reaches every cohort, so the equality is not vacuous.
        assert set(expected.values()) >= {"production", "staging", "lab", "demo", "calibration", "internal",
                                           "unclassified"}
        # cohorts_for_targets (the labels on dashboard and timeline rows) is the same oracle.
        assert await tcs.cohorts_for_targets(conn, list(expected)) == expected
    _run(body)


def test_a_url_without_a_cached_class_is_classified_on_the_next_read():
    import target_cohort_sql as tcs

    async def body(conn):
        await tcs.fill_url_classes(conn)
        row = await conn.fetchrow(
            "INSERT INTO targets(url, name, root_domain, metadata_json) "
            "VALUES ('http://172.16.9.9', 'late', 'late.invalid', '{}') RETURNING id")
        try:
            # The target and the host asset row created with it.
            assert await tcs.fill_url_classes(conn) >= 1
            assert await tcs.fill_url_classes(conn) == 0
            params = lc.SqlParams()
            sql = tcs.cohort_filter_sql("t", ("internal",), params)
            ids = {r["id"] for r in await conn.fetch(f"SELECT t.id FROM targets t WHERE {sql}", *params.values)}
            assert row["id"] in ids
        finally:
            await conn.execute("DELETE FROM targets WHERE id = $1 OR asset_owner_id = $1 OR url LIKE '%172.16.9.9%'",
                               row["id"])
    _run(body)


def _grouped_kwargs():
    return {"filters": {"include_inactive": False, "search": None, "discovery_source": None, "grade": None,
                        "has_findings": None, "member_limit": 200}}


async def _walk(conn, page_kwargs, **kwargs):
    from targets import grouped_list
    from targets import router as targets_router
    items, cursor, first = [], None, None
    while True:
        body = await grouped_list.grouped_page(
            conn, _page(cursor=cursor, **page_kwargs), member_limit=200,
            member_columns=targets_router._GROUPED_TARGET_COLUMNS, public_row=targets_router._public_target_row,
            **_grouped_kwargs(), **kwargs,
        )
        first = first or body
        items.extend(body["items"])
        if not body["has_more"]:
            return items, first
        cursor = body["next_cursor"]


def test_grouped_cohort_filter_keeps_exactly_the_cohort_members():
    import target_cohort_sql as tcs

    async def body(conn):
        expected = await _python_cohorts(conn)
        active = {str(r["id"]) for r in await conn.fetch(
            "SELECT id FROM targets WHERE is_active AND COALESCE(discovery_source,'manual') NOT IN ('model-intake','host')")}
        for view in ("operational", "non_operational", "internal", "production"):
            cohorts = tcs.view_cohorts(view)
            items, _ = await _walk(conn, {"limit": 3}, cohorts=cohorts)
            got = {t["id"] for g in items for t in [g["root_target"], *g["subdomains"]] if t}
            want = {tid for tid in active if expected[tid] in cohorts}
            assert got == want, view
            assert all(t["cohort"] in cohorts for g in items for t in [g["root_target"], *g["subdomains"]] if t)
    _run(body)


async def _per_target_coverage(conn, ids):
    from targets import grouped_list
    return await grouped_list.asm_coverage_by_target(conn, ids)


def test_grouped_asm_summary_sort_and_inventory_filter_equal_the_per_target_values():
    import target_cohort_sql as tcs

    async def body(conn):
        expected = await _python_cohorts(conn)
        for view in (None, "operational", "internal"):
            cohorts = tcs.view_cohorts(view)
            ids = [r["id"] for r in await conn.fetch(
                "SELECT id FROM targets WHERE is_active AND COALESCE(discovery_source,'manual') NOT IN ('model-intake','host')")
                if not cohorts or expected[str(r["id"])] in cohorts]
            coverage = await _per_target_coverage(conn, ids)
            total = sum(c["total"] for c in coverage.values())
            tested = sum(c["tested"] for c in coverage.values())
            items, first = await _walk(conn, {"limit": 2, "sort": "asm_coverage", "count": "exact"},
                                       cohorts=cohorts, has_inventory=True, summary=True)
            summary = first["asm_summary"]
            assert summary["total"] == total and summary["tested"] == tested
            assert summary["untested"] == total - tested
            assert summary["targets_with_inventory"] == sum(1 for c in coverage.values() if c["total"] > 0)
            ranked = sorted(((c["total"] - c["tested"], tid) for tid, c in coverage.items() if c["total"] > 0),
                            key=lambda pair: (-pair[0], pair[1]))[:5]
            assert [(t["untested"], t["id"]) for t in summary["most_untested"]] == [(u, tid) for u, tid in ranked]
            # Only inventoried domains; least covered first; the group rollup is the sort key.
            assert items and all(g["asm_coverage"] and g["asm_coverage"]["total"] > 0 for g in items)
            ratios = [g["asm_coverage"]["tested"] / g["asm_coverage"]["total"] for g in items]
            assert ratios == sorted(ratios)
            assert first["total"] == len(items)
            # Most untested first.
            desc, _ = await _walk(conn, {"limit": 2, "sort": "-asm_untested"}, cohorts=cohorts, has_inventory=True)
            untested = [g["asm_coverage"]["untested"] for g in desc]
            assert untested == sorted(untested, reverse=True)
    _run(body)


def test_grouped_new_parameters_need_list_v1(monkeypatch):
    from fastapi import HTTPException
    from targets import router as targets_router

    async def body(conn):
        class Pool:
            def acquire(self):
                class Ctx:
                    async def __aenter__(self_inner):
                        return conn

                    async def __aexit__(self_inner, *exc):
                        return False
                return Ctx()
        monkeypatch.setattr(targets_router, "_pool", lambda: Pool())
        base = dict(include_inactive=False, search=None, discovery_source=None, grade=None, has_findings=None,
                    sort_by="root_domain", sort_order="asc", limit=None, cursor=None, sort=None, fields=None,
                    since=None, member_limit=20)
        with pytest.raises(HTTPException) as caught:
            await targets_router.list_targets_grouped(None, cohort="internal", count=None, **base)
        assert caught.value.status_code == 400
        page = await targets_router.list_targets_grouped(None, cohort="internal", count="exact", summary="asm", **base)
        assert "asm_summary" in page and page["total_kind"] == "exact"
    _run(body)


def test_dashboard_recent_scans_per_cohort_equal_the_global_walk_filtered_by_label():
    import target_cohort_sql as tcs
    from operations import dashboard_data

    async def body(conn):
        everything = await dashboard_data.recent_latest_scans(conn, limit=10_000)
        assert everything and all("target_cohort" in row for row in everything)
        targets = await _python_cohorts(conn)
        for row in everything:
            if row["target_id"]:
                assert row["target_cohort"] == targets[str(row["target_id"])]
        by_view = await dashboard_data.recent_scans_by_cohort(conn, limit=4)
        for view, rows in by_view.items():
            cohorts = tcs.view_cohorts(view)
            want = [row["id"] for row in everything if (row["target_cohort"] or "unclassified") in cohorts][:4]
            assert [row["id"] for row in rows] == want, view
        assert any(row["ai_target_id"] for row in everything)
        assert any(row["target_id"] is None and row["ai_target_id"] is None for row in everything)
    _run(body)


def test_timeline_cohort_filter_and_labels(monkeypatch):
    import target_cohort_sql as tcs
    from operations import router as operations

    async def body(conn):
        class Pool:
            def acquire(self):
                class Ctx:
                    async def __aenter__(self_inner):
                        return conn

                    async def __aexit__(self_inner, *exc):
                        return False
                return Ctx()
        monkeypatch.setattr(operations, "_pool", lambda: Pool())
        flags = dict(include_campaign_actions=True, include_scans=True, include_schedules=True,
                     include_evidence=True, include_refuters=True, include_exports=True, target_id=None)
        everything = await operations.mission_timeline(limit=200, cohort=None, **flags)
        events = everything["events"]
        assert events and all("target_cohort" in event for event in events)
        targets = await _python_cohorts(conn)
        for event in events:
            if event.get("target_id"):
                assert event["target_cohort"] == targets[event["target_id"]]
        for view in ("operational", "non_operational", "internal"):
            cohorts = tcs.view_cohorts(view)
            want = [e["event_id"] for e in events if e["target_cohort"] in (None, *cohorts)][:20]
            assert len(want) == 20, view
            # The scoped feed reads its own rows: its newest 20 are the global feed's newest 20 of
            # that cohort (the global top 200 holds every event newer than its last one).
            scoped = await operations.mission_timeline(limit=20, cohort=view, **flags)
            assert [e["event_id"] for e in scoped["events"]] == want, view
    _run(body)


WEB_RULE_URLS = [
    "https://ok.example.invalid", "HTTP://UPPER.example.invalid/x", "  https://padded.example.invalid  ",
    " https://nbsp.example.invalid﻿", "http:noslash.example.invalid", "http:/one.example.invalid",
    "http:\\\\back.example.invalid", "https://user:pw@auth.example.invalid:8443/p", "http://@empty-user.example.invalid",
    "https://[::1]:8443", "http://10.0.0.5", "http://", "https://", "http:///nohost", "http://?q", "http://#f",
    "https://in side.example.invalid", "https://tab\t.example.invalid", "ftp://ftp.example.invalid",
    "host.example.invalid", "10.0.0.9:8080", "https://" + "a" * 2040 + ".invalid", "https://" + "b" * 2030 + ".in",
    "javascript:alert(1)", "https://bad port.example.invalid:99999", "https://exa mple.invalid",
]


def _js_usable(urls: list[str]) -> list[bool]:
    """The UI's own rule, evaluated by Node on the same strings (targetChoices.ts isUsableWebTarget)."""
    import subprocess
    script = (
        "const urls = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
        "const ok = (value) => { if (typeof value !== 'string') return false; const target = value.trim();"
        " if (!target || target.length > 2048 || /\\s/.test(target)) return false;"
        " try { const url = new URL(target); return Boolean(url.hostname) && ['http:', 'https:'].includes(url.protocol) }"
        " catch { return false } };"
        "process.stdout.write(JSON.stringify(urls.map(ok)))"
    )
    out = subprocess.run(["node", "-e", script], input=json.dumps(urls), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_inventory_web_only_never_drops_a_row_the_ui_accepts_and_drops_what_it_cannot():
    from targets import asset_inventory as inv

    source = (ROOT / "ui" / "src" / "lib" / "targetChoices.ts").read_text()
    # The rule evaluated above is the UI's current one, character for character.
    assert "if (!target || target.length > MAX_SCAN_TARGET_CHARS || /\\s/.test(target)) return false" in source
    assert "return Boolean(url.hostname) && ['http:', 'https:'].includes(url.protocol)" in source

    async def body(conn):
        ids = []
        try:
            for index, url in enumerate(WEB_RULE_URLS):
                row = await conn.fetchrow(
                    "INSERT INTO targets(url, name, root_domain, is_active) VALUES ($1, $2, 'webrule.invalid', $3) "
                    "ON CONFLICT DO NOTHING RETURNING id", url, f"webrule {index}", index != 0)
                ids.append(row["id"] if row else None)
            rows = await conn.fetch(
                f"SELECT t.id, t.url FROM targets t WHERE t.id = ANY($1::uuid[]) AND {inv.WEB_ONLY}",
                [i for i in ids if i])
            server = {row["id"] for row in rows}
            ui = _js_usable(WEB_RULE_URLS)
            for index, (url, target_id) in enumerate(zip(WEB_RULE_URLS, ids)):
                if target_id is None:
                    continue
                accepted = ui[index] and index != 0  # row 0 is inactive: the UI drops it too
                if accepted:
                    assert target_id in server, url
            # It is a real filter: every row the UI rejects for scheme, whitespace or length is gone.
            for url in ("ftp://ftp.example.invalid", "host.example.invalid", "10.0.0.9:8080", "javascript:alert(1)",
                        "https://in side.example.invalid", "https://tab\t.example.invalid", "http://", "https://",
                        "https://" + "a" * 2040 + ".invalid", "https://ok.example.invalid"):
                index = WEB_RULE_URLS.index(url)
                if ids[index] is not None:
                    assert ids[index] not in server, url
        finally:
            await conn.execute("DELETE FROM targets WHERE root_domain = 'webrule.invalid' OR name LIKE 'webrule %'")
    _run(body)
