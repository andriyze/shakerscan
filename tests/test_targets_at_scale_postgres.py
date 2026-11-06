"""The Targets and Findings pages at 500 and 2,000 targets on real PostgreSQL.

Real PostgreSQL only: TARGETS_AT_SCALE_TEST_DATABASE_URL on localhost naming
``shakerscan_targets_at_scale_test``. The module resets that database's public schema, installs
db/init.sql plus the startup migrations, and seeds ``.invalid`` hosts only.

The fixture is shaped like a recon-heavy install: 40% of the targets are subdomains of one large
domain, the rest domains of three web apps each; ten findings and two completed Scans per web app.

``test_measure_pages`` prints the server time and response size of the requests the Targets and
Findings pages send for their first page, at 500 and at 2,000 targets (median of 5 runs). It
asserts nothing about time (machines differ); the bound tests below assert the work instead.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import statistics
import sys
import time

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("TARGETS_AT_SCALE_TEST_DATABASE_URL")
REQUIRED = os.environ.get("TARGETS_AT_SCALE_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_targets_at_scale_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable targets-at-scale PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import list_contract as lc  # noqa: E402

RUNS = 5


def seed_sql(start: int, count: int) -> str:
    """Web apps ``start``..``start+count-1``: 40% under big.invalid, the rest three per domain."""
    return f"""
INSERT INTO targets(url, name, root_domain, is_root, discovery_source, metadata_json, created_at)
SELECT CASE WHEN g % 5 < 2 THEN 'https://n' || g || '.big.invalid'
            WHEN g % 5 = 2 THEN 'https://d' || (g / 5) || '.invalid'
            ELSE 'https://s' || g || '.d' || (g / 5) || '.invalid' END,
       'seed ' || g,
       CASE WHEN g % 5 < 2 THEN 'big.invalid' ELSE 'd' || (g / 5) || '.invalid' END,
       g % 5 = 2, (ARRAY['manual','subfinder','import'])[1 + g % 3],
       jsonb_build_object('environment', (ARRAY['production','staging','lab'])[1 + g % 3]),
       TIMESTAMPTZ '2026-09-01' + g * INTERVAL '1 minute'
FROM generate_series({start}, {start + count - 1}) g;

CREATE TEMP TABLE seed_web AS
SELECT id, url FROM targets WHERE url ~ '^https://' AND name ~ '^seed ' AND NOT EXISTS (
    SELECT 1 FROM scans s WHERE s.target_id = targets.id);
INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role, score, grade, findings_count,
                  created_at, started_at, completed_at, execution_context, coverage_json)
SELECT w.id, w.url, 'completed', 'standard', 'web_dast', 'standalone', 70, 'B', 10,
       TIMESTAMPTZ '2026-10-01' - k * INTERVAL '1 day', TIMESTAMPTZ '2026-10-01' - k * INTERVAL '1 day',
       TIMESTAMPTZ '2026-10-01' - k * INTERVAL '1 day' + INTERVAL '5 minutes', '{{}}', '{{}}'
FROM seed_web w, generate_series(1, 2) k;
INSERT INTO findings(scan_id, target_id, fingerprint, title, severity, tool, url, evidence, status, source,
                     first_seen_at, last_seen_at)
SELECT s.id, w.id, 'seed-' || w.id || '-' || f, 'Seeded ' || (f % 7),
       (ARRAY['critical','high','medium','low','info'])[1 + f % 5], 'nuclei', w.url || '/p/' || f, '{{}}'::jsonb,
       CASE WHEN f % 5 = 0 THEN 'resolved' ELSE 'active' END, 'scan',
       TIMESTAMPTZ '2026-09-20' + f * INTERVAL '1 hour', TIMESTAMPTZ '2026-10-01'
FROM seed_web w
JOIN LATERAL (SELECT id FROM scans WHERE target_id = w.id ORDER BY created_at DESC LIMIT 1) s ON true,
     generate_series(1, 10) f;
UPDATE targets t SET total_scans = 2, last_scanned_at = TIMESTAMPTZ '2026-09-30', last_score = 70, last_grade = 'B',
       active_findings_count = 8
FROM seed_web w WHERE w.id = t.id;
DROP TABLE seed_web;
"""


async def _connect():
    return await asyncpg.connect(require_disposable_database(DSN, DATABASE))


@pytest.fixture(scope="module")
def database():
    async def setup():
        conn = await _connect()
        try:
            await conn.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
            await conn.execute((ROOT / "db" / "init.sql").read_text())
            import retest_contract
            from targets.asset_migration import BoundConnectionPool
            await retest_contract.run_schema_migrations(BoundConnectionPool(conn))
            from runtime.loop_scale_indexes import ensure_loop_scale_indexes
            await ensure_loop_scale_indexes(BoundConnectionPool(conn))
        finally:
            await conn.close()

    lc.configure_cursor_key(b"t" * 32)
    asyncio.run(setup())
    yield
    lc.configure_cursor_key(None)


async def _seed(conn, start: int, count: int) -> None:
    await conn.execute(seed_sql(start, count))
    await conn.execute("ANALYZE")


def _page(**kwargs) -> lc.Page:
    values = {"limit": 50, "cursor": None, "sort": None, "fields": None, "count": "none", "since": None}
    values.update(kwargs)
    return lc.page_params(**values)


class _Request:
    def __init__(self, **params):
        self.query_params = params


class _Pool:
    def __init__(self, pool):
        self.pool = pool

    def acquire(self):
        return self.pool.acquire()


FINDING_DEFAULTS = dict(
    severity=None, status=None, source_type=None, target_id=None, ai_target_id=None, device_target_id=None,
    scan_id=None, hunt_id=None, root_domain=None, verification_verdict=None, verification_mode=None,
    verified_only=False, proof_state=None, driven_by=None, research_campaign_id=None, search=None,
    seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None, resolved_within_days=None,
    sort_by=None, sort_order="desc", include_candidates=False, limit=100, offset=0, include_details=False,
)


async def _timed(call) -> tuple[float, int, object]:
    samples = []
    body = None
    for _ in range(RUNS):
        started = time.perf_counter()
        body = await call()
        encoded = json.dumps(body, default=str)
        samples.append((time.perf_counter() - started) * 1000)
    return statistics.median(samples), len(encoded), body


def targets_first_page_calls(conn):
    """The requests the Targets page sends for its first page (name order, no filter)."""
    from targets.asset_inventory import list_assets_v1

    def grouped_211():
        return list_assets_v1(conn, _page(limit=40, count="exact", sort="name"), group_by="domain",
                              include_facets=True, member_limit=200)

    def grouped():
        return list_assets_v1(conn, _page(limit=25, count="exact", sort="name"), group_by="domain",
                              include_facets=True, member_limit=20)

    def one_domain():
        return list_assets_v1(conn, _page(limit=50, count="exact", sort="name"), domain="big.invalid",
                              include_facets=True)
    return {"targets page as 2.11 asks (40 groups x 200 members, facets, exact count)": grouped_211,
            "targets page as 2.12 asks (25 groups x 20 members, facets, exact count)": grouped,
            "one domain's page (domain=big.invalid, 50 targets, facets, exact count)": one_domain}


def findings_first_page_calls(monkeypatch, pool):
    import finding_routes.router as findings_router

    monkeypatch.setattr(findings_router, "_pool", lambda: _Pool(pool))

    def grouped():
        query = {"group_by": "issue", "limit": 50, "sort": "-severity", "count": "exact"}
        arguments = dict(FINDING_DEFAULTS, limit=50, cursor=None, sort="-severity", fields=None, count="exact",
                         since=None, group_by="issue")
        return findings_router.list_findings(_Request(**query), **arguments)

    def flat():
        arguments = dict(FINDING_DEFAULTS, limit=50, offset=0, sort_by="severity")
        return findings_router.list_findings(_Request(limit=50, offset=0, sort_by="severity"), **arguments)
    return {"findings page (group_by=issue, 50 groups, exact count)": grouped,
            "findings page (flat, 50 rows)": flat}


async def _measure_liveness(conn) -> list[str]:
    """The liveness loop's steady state (every asset checked, nothing due) and a filtered page."""
    from targets import liveness
    from targets.asset_inventory import list_assets_v1

    await conn.execute("DELETE FROM target_liveness")
    for index, row in enumerate(await conn.fetch("SELECT id FROM targets WHERE asset_owner_id IS NULL")):
        status = liveness.LIVE if index % 4 else liveness.UNREACHABLE
        await liveness.store_result(conn, row["id"], {"status": status, "dns": "resolves", "reachable": index % 4 > 0,
                                                      "live": index % 4 > 0, "addresses": [], "ports": []}, "schedule")
    await conn.execute("ANALYZE target_liveness")

    async def idle_claim():
        return await liveness.claim_due(conn, liveness.TICK_BATCH)

    def unreachable_page():
        return list_assets_v1(conn, _page(limit=25, count="exact", sort="name"), group_by="domain",
                              include_facets=True, member_limit=20, liveness="unreachable")
    claim_ms, _, claimed = await _timed(idle_claim)
    page_ms, page_bytes, body = await _timed(unreachable_page)
    await conn.execute("DELETE FROM target_liveness")
    assert claimed == []
    return [f"liveness loop claim with nothing due: {claim_ms:.1f} ms median",
            f"targets page filtered to unreachable (25 groups x 20, facets, exact count): {page_ms:.0f} ms median, "
            f"{page_bytes:,} bytes, {_assets_on(body)} targets on the page"]


def _assets_on(body) -> int:
    items = body.get("items") or body.get("groups") or []
    return sum(len(item.get("targets") or []) for item in items)


def test_measure_pages(database, monkeypatch, capsys):
    async def run():
        conn = await _connect()
        pool = await asyncpg.create_pool(require_disposable_database(DSN, DATABASE), min_size=1, max_size=2)
        lines = []
        try:
            seeded = 0
            for size in (500, 2000):
                await _seed(conn, seeded, size - seeded)
                seeded = size
                web = await conn.fetchval("SELECT count(*) FROM targets WHERE url ~ '^https://'")
                assets = await conn.fetchval("SELECT count(*) FROM targets WHERE asset_owner_id IS NULL")
                findings = await conn.fetchval("SELECT count(*) FROM findings")
                lines.append(f"== {web} web apps, {assets} Targets-list rows, {findings} findings")
                calls = {**targets_first_page_calls(conn), **findings_first_page_calls(monkeypatch, pool)}
                for label, call in calls.items():
                    median, size_bytes, body = await _timed(call)
                    extra = f", {_assets_on(body)} targets on the page" if label.startswith("targets") else ""
                    lines.append(f"{label}: {median:.0f} ms median, {size_bytes:,} bytes{extra}")
                lines += await _measure_liveness(conn)
        finally:
            await pool.close()
            await conn.close()
        return lines

    lines = asyncio.run(run())
    with capsys.disabled():
        print("\n" + "\n".join(lines))


# --- Bounds, filters and liveness on the 2,000-target fixture ------------------------------------

def _run(fn):
    async def wrapper():
        conn = await _connect()
        try:
            if not await conn.fetchval("SELECT count(*) >= 2000 FROM targets WHERE url ~ '^https://'"):
                existing = await conn.fetchval("SELECT count(*) FROM targets WHERE url ~ '^https://'")
                await _seed(conn, existing, 2000 - existing)
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(wrapper())


async def _walk(conn, **arguments):
    from targets.asset_inventory import list_assets_v1

    ids, cursor, pages, first = [], None, 0, None
    while True:
        page = _page(limit=50, cursor=cursor, count="exact" if cursor is None else "none")
        body = await list_assets_v1(conn, page, **arguments)
        first = first or body
        pages += 1
        ids += [item["id"] for item in body["items"]]
        assert len(body["items"]) <= 50
        cursor = body["next_cursor"]
        if not cursor:
            return ids, first, pages


def test_domain_filter_pages_through_a_large_domain(database):
    async def go(conn):
        # Each web app sits under its host asset (host://...), the row the Targets list shows.
        expected = {row["id"] for row in await conn.fetch(
            "SELECT id FROM targets WHERE url LIKE '%.big.invalid' AND asset_owner_id IS NULL AND is_active")}
        ids, first, pages = await _walk(conn, domain="big.invalid")
        assert len(expected) == 800 and pages == 16
        assert len(ids) == len(set(ids)) and set(ids) == expected
        assert first["total"] == 800 and first["total_kind"] == "exact"
        # The filter is the group, not a suffix: d1.invalid is not d11.invalid's group.
        ids, first, _ = await _walk(conn, domain="d11.invalid")
        assert {row["url"] for row in await conn.fetch("SELECT url FROM targets WHERE id = ANY($1::uuid[])", ids)} == {
            "host://d11.invalid", "host://s58.d11.invalid", "host://s59.d11.invalid"}
        # A domain cursor is bound to its domain.
        from fastapi import HTTPException
        from targets.asset_inventory import list_assets_v1
        body = await list_assets_v1(conn, _page(limit=50), domain="big.invalid")
        with pytest.raises(HTTPException):
            await list_assets_v1(conn, _page(limit=50, cursor=body["next_cursor"]), domain="d11.invalid")
        with pytest.raises(HTTPException):
            await list_assets_v1(conn, _page(limit=50), domain="bad domain;")
    _run(go)


def test_grouped_first_page_is_bounded(database):
    from targets.asset_inventory import list_assets_v1

    async def go(conn):
        body = await list_assets_v1(conn, _page(limit=25, count="exact", sort="name"), group_by="domain",
                                    include_facets=True, member_limit=20)
        shown = sum(len(group["targets"]) for group in body["items"])
        assert len(body["items"]) == 25 and shown <= 25 * 20
        big = [group for group in body["items"] if group["root_domain"] == "big.invalid"]
        assert big and big[0]["member_count"] == 800 and big[0]["members_truncated"] and len(big[0]["targets"]) == 20
        assert body["target_total"] == await conn.fetchval(
            "SELECT count(*) FROM targets WHERE asset_owner_id IS NULL AND is_active")
    _run(go)


def test_liveness_filter_counts_and_walk_agree(database):
    from targets import liveness
    from targets.asset_inventory import list_assets_v1

    async def go(conn):
        await conn.execute("DELETE FROM target_liveness")
        assets = [row["id"] for row in await conn.fetch(
            "SELECT id FROM targets WHERE asset_owner_id IS NULL AND is_active ORDER BY url")]
        states = [liveness.LIVE, liveness.UNREACHABLE, liveness.NO_DNS, liveness.REACHABLE, liveness.DNS_ERROR]
        expected: dict[str, set] = {status: set() for status in liveness.STATUSES}
        for index, asset in enumerate(assets):
            if index % 7 == 6:
                expected[liveness.UNCHECKED].add(asset)
                continue
            status = states[index % len(states)]
            expected[status].add(asset)
            await liveness.store_result(conn, asset, {
                "status": status, "dns": "resolves", "reachable": status in ("live", "reachable"),
                "live": status == "live", "addresses": ["203.0.113.9"], "ports": [], "reason": None}, "schedule")
        body = await list_assets_v1(conn, _page(limit=1), include_facets=True)
        for status in liveness.STATUSES:
            assert body["facets"]["liveness"][status] == len(expected[status]), status
        for status in (liveness.LIVE, liveness.UNREACHABLE, liveness.NO_DNS, liveness.UNCHECKED):
            ids, first, _ = await _walk(conn, liveness=status)
            assert set(ids) == expected[status] and len(ids) == len(set(ids)), status
            assert first["total"] == len(expected[status])
            assert all(item["liveness"]["status"] == status for item in first["items"])
        # Combined with the domain filter and the grouped view.
        ids, first, _ = await _walk(conn, liveness=liveness.LIVE, domain="big.invalid")
        big = {row["id"] for row in await conn.fetch("SELECT id FROM targets WHERE url LIKE '%.big.invalid'")}
        assert set(ids) == expected[liveness.LIVE] & big
        grouped = await list_assets_v1(conn, _page(limit=200, count="exact"), group_by="domain",
                                       liveness=liveness.NO_DNS, member_limit=200)
        assert grouped["target_total"] == len(expected[liveness.NO_DNS])
        members = [target for group in grouped["items"] for target in group["targets"]]
        assert members and all(target["liveness"]["status"] == liveness.NO_DNS for target in members)
    _run(go)


def test_due_claims_the_trigger_and_the_tick(database):
    from targets import liveness

    async def go(conn):
        await conn.execute("DELETE FROM target_liveness")
        first = await liveness.claim_due(conn, 10)
        assert len(first) == 10 and all(trigger == "add" for _id, trigger in first)
        # Claimed rows are not claimed again while the claim lasts.
        second = await liveness.claim_due(conn, 10)
        assert not {asset for asset, _ in first} & {asset for asset, _ in second}
        await conn.execute("DELETE FROM target_liveness")
        # Every asset checked: nothing is due.
        for row in await conn.fetch("SELECT id FROM targets WHERE asset_owner_id IS NULL"):
            await liveness.store_result(conn, row["id"], {"status": "live", "dns": "resolves", "reachable": True,
                                                          "live": True, "addresses": [], "ports": []}, "schedule")
        assert await liveness.claim_due(conn, 10) == []
        # Submitting a Scan asks for a check of its target first...
        # (the check belongs to the web app's host asset).
        target = await conn.fetchrow("SELECT id, url, asset_owner_id FROM targets WHERE url = 'https://n0.big.invalid'")
        assert target["asset_owner_id"]
        await conn.execute("UPDATE target_liveness SET checked_at = now() - interval '1 hour' WHERE target_id=$1",
                           target["asset_owner_id"])
        await conn.execute("""INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role,
            execution_context, coverage_json) VALUES ($1, $2, 'queued', 'standard', 'web_dast', 'standalone', '{}', '{}')""",
                           target["id"], target["url"])
        assert await liveness.claim_due(conn, 10) == [(target["asset_owner_id"], "pre_scan")]
        # ...but not when the last check is recent, and never for a shard.
        other = await conn.fetchrow("SELECT id, url, asset_owner_id FROM targets WHERE url = 'https://n1.big.invalid'")
        await conn.execute("""INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role,
            execution_context, coverage_json) VALUES ($1, $2, 'queued', 'standard', 'web_dast', 'standalone', '{}', '{}'),
            ($1, $2, 'queued', 'standard', 'web_dast', 'shard', '{}', '{}')""", other["id"], other["url"])
        assert await conn.fetchval("SELECT requested_at FROM target_liveness WHERE target_id=$1",
                                   other["asset_owner_id"]) is None
        stale = await conn.fetchrow("SELECT id, url, asset_owner_id FROM targets WHERE url = 'https://n5.big.invalid'")
        await conn.execute("UPDATE target_liveness SET checked_at = now() - interval '1 hour' WHERE target_id=$1",
                           stale["asset_owner_id"])
        await conn.execute("""INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role,
            execution_context, coverage_json) VALUES ($1, $2, 'queued', 'standard', 'web_dast', 'shard', '{}', '{}')""",
                           stale["id"], stale["url"])
        assert await conn.fetchval("SELECT requested_at FROM target_liveness WHERE target_id=$1",
                                   stale["asset_owner_id"]) is None
        # A web app added to a checked asset makes the asset due again.
        host = await conn.fetchval("""INSERT INTO targets(url, name, discovery_source)
            VALUES ('host://fresh.big.invalid', 'fresh', 'host') RETURNING id""")
        await liveness.store_result(conn, host, {"status": "live", "dns": "resolves", "reachable": True,
                                                 "live": True, "addresses": [], "ports": []}, "add")
        await conn.execute("UPDATE target_liveness SET claimed_until=NULL")
        await conn.execute("""INSERT INTO targets(url, name, asset_owner_id, discovery_source, created_at)
            VALUES ('https://fresh.big.invalid:8443', 'fresh app', $1, 'manual', now() + interval '1 second')""", host)
        due = dict(await liveness.claim_due(conn, 10))
        assert host in due
        await conn.execute("DELETE FROM target_liveness")
    _run(go)


def test_tick_and_check_now_store_results(database):
    from targets import liveness
    import socket as socket_module

    async def go(conn):
        await conn.execute("DELETE FROM target_liveness")
        pool = await asyncpg.create_pool(require_disposable_database(DSN, DATABASE), min_size=1, max_size=4)
        looked_up = []

        async def no_record(host):
            looked_up.append(host)
            raise socket_module.gaierror(socket_module.EAI_NONAME, "no record")
        try:
            checked = await liveness.liveness_tick(pool, lookup=no_record, batch=12, concurrency=4)
            assert checked == 12 and len(looked_up) == 12
            rows = await conn.fetch("SELECT * FROM target_liveness WHERE checked_at IS NOT NULL")
            assert len(rows) == 12
            assert all(row["status"] == "no_dns" and row["dns"] == "no_record" and row["trigger"] == "add"
                       and row["claimed_until"] is None and row["reason"].endswith("has no address record")
                       for row in rows)
            # Check now on a web app answers for its asset; a fresh result is not repeated.
            target = rows[0]["target_id"]
            result = await liveness.check_now(pool, target)
            assert result["checked"] is False and result["liveness"]["status"] == "no_dns"
            assert await liveness.check_now(pool, "00000000-0000-0000-0000-000000000000") is None
            # Archived targets are never claimed.
            await conn.execute("UPDATE targets SET is_active=false WHERE id=$1", rows[1]["target_id"])
            await conn.execute("UPDATE target_liveness SET next_check_at = now() - interval '1 day'")
            due = {asset for asset, _ in await liveness.claim_due(conn, 5000)}
            assert rows[1]["target_id"] not in due and rows[0]["target_id"] in due
            await conn.execute("UPDATE targets SET is_active=true WHERE id=$1", rows[1]["target_id"])
            await conn.execute("DELETE FROM target_liveness")
        finally:
            await pool.close()
    _run(go)
