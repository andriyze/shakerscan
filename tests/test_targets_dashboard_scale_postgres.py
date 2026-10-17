"""Targets, inventory, dashboard, graph, ASM coverage, campaign and refuter reads at scale.

Real PostgreSQL only: TARGETS_SCALE_TEST_DATABASE_URL on localhost naming
``shakerscan_targets_scale_test``. The module resets that database's public schema, installs
db/init.sql plus the startup migrations, and seeds a synthetic fixture (``.invalid`` hosts only).

What it proves:

* equality: every reworked read returns what the 2.10 query returned on the same fixture (the
  2.10 queries are kept in tests/targets_scale_reference.py as the oracle);
* the trigger-maintained counts stay exact through inserts, bucket and non-bucket updates,
  deletes, cascades, upserts and TRUNCATE, with and without compaction;
* list/v1 walks return every row once, in order, also with rows inserted mid-walk, and a cursor
  is bound to its filters;
* bounds: no single query of a list/v1 page, the dashboard, ASM coverage or campaign impact
  returns more rows than its page or bucket bound, on a fixture far larger than those bounds, so
  a regression to an unbounded read fails here.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database
from tests import targets_scale_reference as ref

DSN = os.environ.get("TARGETS_SCALE_TEST_DATABASE_URL")
REQUIRED = os.environ.get("TARGETS_SCALE_POSTGRES_REQUIRED") == "1"
DATABASE = "shakerscan_targets_scale_test"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable targets-scale PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import HTTPException  # noqa: E402

import list_contract as lc  # noqa: E402

DOMAINS = 300          # 4 web targets each (root + 3 subdomains)
BIG_MEMBERS = 120      # one domain with this many subdomains
FINDINGS = 12_000
GRAPH_NODES = 900


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


SEED_SQL = f"""
INSERT INTO ai_targets(name, endpoint_url) VALUES ('seed ai', 'https://ai.seed.invalid/chat');
INSERT INTO targets(url, name, root_domain, is_root, discovery_source, metadata_json, created_at, asm_enabled)
SELECT CASE WHEN s = 0 THEN 'https://d' || lpad(d::text, 4, '0') || '.invalid'
            ELSE 'https://s' || s || '.d' || lpad(d::text, 4, '0') || '.invalid' END,
       'seed ' || d || '/' || s, 'd' || lpad(d::text, 4, '0') || '.invalid', s = 0,
       (ARRAY['manual','subfinder','import'])[1 + d % 3],
       jsonb_build_object('environment', (ARRAY['production','staging','lab'])[1 + d % 3]),
       TIMESTAMPTZ '2026-09-01' + (d * 4 + s) * INTERVAL '1 minute', d % 5 = 0
FROM generate_series(1, {DOMAINS}) d, generate_series(0, 3) s;
INSERT INTO targets(url, name, root_domain, is_root, discovery_source, created_at)
SELECT CASE WHEN s = 0 THEN 'https://big.invalid' ELSE 'https://n' || s || '.big.invalid' END,
       'big ' || s, 'big.invalid', s = 0, 'subfinder', TIMESTAMPTZ '2026-08-01' + s * INTERVAL '1 second'
FROM generate_series(0, {BIG_MEMBERS}) s;
-- a target with no root domain groups as "unknown"; two inactive subdomains
INSERT INTO targets(url, name, root_domain, is_root) VALUES ('https://loose.invalid', 'loose', NULL, false);
UPDATE targets SET is_active = false WHERE url IN ('https://s1.d0007.invalid', 'https://s2.d0011.invalid');

CREATE TEMP TABLE wt AS
SELECT id, url, row_number() OVER (ORDER BY url) AS rn FROM targets WHERE discovery_source <> 'host';

-- completed scans: 3 per target for the first 900 targets, distinct timestamps
INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role, score, grade, findings_count,
                  created_at, started_at, completed_at, execution_context, coverage_json)
SELECT wt.id, wt.url, 'completed', 'standard', 'web_dast', 'standalone',
       CASE WHEN g % 17 = 0 THEN NULL ELSE (g * 37) % 101 END, 'B',
       CASE WHEN g % 211 = 0 THEN 90 ELSE g % 9 END,
       TIMESTAMPTZ '2026-10-01' - g * INTERVAL '1 minute', TIMESTAMPTZ '2026-10-01' - g * INTERVAL '1 minute',
       TIMESTAMPTZ '2026-10-01' - g * INTERVAL '1 minute' + INTERVAL '5 minutes', '{{}}', '{{}}'
FROM generate_series(1, 2700) g JOIN wt ON wt.rn = ((g - 1) % 900) + 1;
-- other statuses, shards, device and AI kinds, model intake, URL-only and AI-target scans
INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role, error_message, created_at,
                  completed_at, score, execution_context, coverage_json)
SELECT wt.id, wt.url, (ARRAY['failed','running','queued','pending','failed','completed'])[1 + g % 6], 'standard',
       (ARRAY['web_dast','web_dast','ai_api','device_posture','web_dast','model_intake'])[1 + g % 5],
       CASE WHEN g % 7 = 0 THEN 'shard' WHEN g % 11 = 0 THEN 'device_web_origin' ELSE 'standalone' END,
       'seeded failure ' || g, NOW() - g * INTERVAL '97 minutes', NOW() - g * INTERVAL '96 minutes',
       (g * 13) % 101, '{{}}', '{{}}'
FROM generate_series(1, 400) g JOIN wt ON wt.rn = ((g * 7) % 1000) + 1;
INSERT INTO scans(target_id, ai_target_id, target_url, status, scan_type, run_kind, scan_role, created_at, completed_at,
                  score, execution_context, coverage_json)
SELECT NULL, CASE WHEN g % 2 = 0 THEN (SELECT id FROM ai_targets LIMIT 1) END,
       'https://orphan' || (g % 5) || '.invalid', 'completed', 'standard', 'web_dast', 'standalone',
       TIMESTAMPTZ '2026-10-02' - g * INTERVAL '7 seconds', TIMESTAMPTZ '2026-10-02' - g * INTERVAL '7 seconds',
       g % 100, '{{}}', '{{}}'
FROM generate_series(1, 60) g;
INSERT INTO scans(target_id, target_url, status, scan_type, run_kind, scan_role, created_at, completed_at, score, result,
                  execution_context, coverage_json)
SELECT wt.id, wt.url, 'completed', 'model_intake', 'model_intake', 'standalone',
       TIMESTAMPTZ '2026-09-20' + g * INTERVAL '1 hour', TIMESTAMPTZ '2026-09-20' + g * INTERVAL '1 hour', g,
       jsonb_build_object('model_intake', jsonb_build_object('summary', jsonb_build_object(
           'signature_verification_status', CASE WHEN g % 3 = 0 THEN 'verified' ELSE 'unsigned' END,
           'signature_verified', CASE WHEN g % 3 = 0 THEN 'true' ELSE 'false' END))), '{{}}', '{{}}'
FROM generate_series(1, 30) g JOIN wt ON wt.rn = g;

CREATE TEMP TABLE ws AS
SELECT id, target_id, row_number() OVER (PARTITION BY target_id ORDER BY created_at) AS k
FROM scans WHERE status = 'completed' AND run_kind = 'web_dast' AND scan_role = 'standalone' AND target_id IS NOT NULL;

INSERT INTO findings(scan_id, target_id, ai_target_id, fingerprint, title, severity, tool, url, evidence, status, source,
                     first_seen_at, last_seen_at, last_verification_verdict)
SELECT ws.id, wt.id, CASE WHEN f % 41 = 0 THEN (SELECT id FROM ai_targets LIMIT 1) END, 'seed-' || f,
       'Seeded ' || (f % 50), (ARRAY['critical','high','medium','low','info','high','unknown'])[1 + f % 7],
       CASE WHEN f % 101 = 0 THEN 'model_intake' WHEN f % 43 = 0 THEN 'autonomous_workflow' WHEN f % 47 = 0 THEN 'bola'
            WHEN f % 53 = 0 THEN NULL ELSE 'nuclei' END,
       wt.url || '/p/' || f,
       CASE WHEN f % 59 = 0 THEN '{{"matched_markers": true, "parser_promoted": true}}'::jsonb ELSE '{{}}'::jsonb END,
       CASE WHEN f % 9 = 0 THEN 'resolved' WHEN f % 31 = 0 THEN 'false_positive' WHEN f % 613 = 0 THEN NULL ELSE 'active' END,
       CASE WHEN f % 13 = 0 THEN 'ai_gate' WHEN f % 17 = 0 THEN 'model_intake' WHEN f % 19 = 0 THEN 'device'
            WHEN f % 23 = 0 THEN 'asm' WHEN f % 29 = 0 THEN NULL WHEN f % 37 = 0 THEN 'manual' ELSE 'scan' END,
       TIMESTAMPTZ '2026-10-01' - f * INTERVAL '1 second', TIMESTAMPTZ '2026-10-01' - (f % 4000) * INTERVAL '1 second'
            - f * INTERVAL '1 millisecond',
       CASE WHEN f % 43 = 0 OR f % 47 = 0 THEN 'exploited' END
FROM generate_series(1, {FINDINGS}) f
JOIN wt ON wt.rn = ((f - 1) % 900) + 1
JOIN ws ON ws.target_id = wt.id AND ws.k = ((f - 1) / 900) % 3 + 1;
-- a finding with no target
INSERT INTO findings(fingerprint, title, severity, status, source) VALUES ('seed-untargeted', 'Untargeted', 'high', 'active', 'scan');

-- ASM inventory: 20 targets x 30 endpoints, latest-attempt telemetry in every shape
INSERT INTO target_endpoints(target_id, method, path, fingerprint, test_status, last_attempt_status, last_tested_at,
                             last_verdict, attempt_count)
SELECT wt.id, 'GET', '/e/' || (e % 12), 'fp-' || e,
       (ARRAY['untested','tested','stale','gone','in_progress','tested'])[1 + e % 6],
       (ARRAY[NULL,'completed','partial','auth_missing','auth_failed','partial_timeout'])[1 + e % 6],
       CASE WHEN e % 3 = 0 THEN TIMESTAMPTZ '2026-09-30' END, CASE WHEN e % 7 = 0 THEN 'verified' END, e % 4
FROM generate_series(1, 20) t JOIN wt ON wt.rn = t * 20, generate_series(1, 30) e;
UPDATE targets SET asm_enabled = true WHERE id IN (SELECT target_id FROM target_endpoints);
INSERT INTO asm_endpoint_attempts(endpoint_id, status, started_at, completed_at, scanner_telemetry_json)
SELECT te.id,
       (ARRAY['completed','partial','auth_missing','rate_limited','error','completed','timeout',' Completed '])
           [1 + (abs(hashtext(te.id::text || a)) % 8)],
       TIMESTAMPTZ '2026-09-30' - (a * 60 + abs(hashtext(te.id::text)) % 50) * INTERVAL '1 minute',
       CASE WHEN a = 1 OR abs(hashtext(te.id::text)) % 5 <> 0
            THEN TIMESTAMPTZ '2026-09-30' - (a * 60 - 5) * INTERVAL '1 minute' END,
       CASE abs(hashtext(te.id::text || 't' || a)) % 6
         WHEN 0 THEN '{{"per_endpoint_telemetry": true, "endpoint_attempt": {{"schema_version": "active_endpoint_attempt_v1"}}}}'::jsonb
         WHEN 1 THEN '{{"per_endpoint_telemetry": " TRUE ", "endpoint_attempt": {{"schema_version": "active_endpoint_attempt_v1"}}}}'::jsonb
         WHEN 2 THEN '{{"per_endpoint_telemetry": true}}'::jsonb
         WHEN 3 THEN '{{"per_endpoint_telemetry": 1, "endpoint_attempt": {{"schema_version": "active_endpoint_attempt_v1"}}}}'::jsonb
         WHEN 4 THEN '{{"per_endpoint_telemetry": true, "endpoint_attempt": {{"schema_version": "other"}}}}'::jsonb
         ELSE '{{}}'::jsonb END
FROM target_endpoints te, generate_series(1, 2) a
WHERE abs(hashtext(te.id::text)) % 7 <> 0;

-- application graph on one target
INSERT INTO application_graph_nodes(target_id, node_type, node_key, label, attributes)
SELECT wt.id, (ARRAY['route','object','principal'])[1 + n % 3], 'k:' || lpad(n::text, 5, '0'), 'node ' || n,
       jsonb_build_object('n', n)
FROM wt, generate_series(1, {GRAPH_NODES}) n WHERE wt.rn = 5;
INSERT INTO application_graph_edges(target_id, src_key, dst_key, edge_type)
SELECT wt.id, 'k:' || (n % {GRAPH_NODES}), 'k:' || ((n * 7) % {GRAPH_NODES}),
       (ARRAY['produces','consumed_by','auth_boundary'])[1 + n % 3]
FROM wt, generate_series(1, 1200) n WHERE wt.rn = 5
ON CONFLICT DO NOTHING;

-- campaigns linking findings by canonical, upper-case and invalid ids
INSERT INTO campaigns(objective, campaign_type, target_id, target_scope, risk_tier, planner, status, deployment_impact,
                      metadata_json, created_at, updated_at)
SELECT 'seed campaign ' || c, 'focused_family', wt.id, '{{}}', 'read_only', '{{}}',
       (ARRAY['planned','active','completed'])[1 + c % 3], '{{}}', '{{}}',
       TIMESTAMPTZ '2026-10-01' - c * INTERVAL '1 minute', NOW()
FROM generate_series(1, 20) c JOIN wt ON wt.rn = c;
INSERT INTO campaign_actions(mission_campaign_id, target_id, command, action_name, status, dry_run, risk_tier, finding_ids,
                             hypothesis_ids, evidence_object_ids, tool_receipt_ids, blocked_by, result_json, created_at, updated_at)
SELECT c.id, c.target_id, 'scan.submit', 'scan.submit', 'planned', false, 'read_only',
       (SELECT COALESCE(jsonb_agg(CASE WHEN x % 11 = 0 THEN 'not-a-uuid' WHEN x % 13 = 0 THEN upper(f.id::text)
                                       ELSE f.id::text END), '[]'::jsonb)
          FROM (SELECT f.id, row_number() OVER (ORDER BY f.id) AS x FROM findings f WHERE f.target_id = c.target_id) f
         WHERE x <= 4 * a),
       '[]', '[]', '[]', '[]', '{{}}', NOW() - a * INTERVAL '1 minute', NOW()
FROM campaigns c, generate_series(1, 6) a;

-- schedules (more than one page) and investigation candidates
INSERT INTO schedules(target_id, frequency, scan_type, is_active, next_run_at, created_at, updated_at)
SELECT wt.id, 'daily', 'standard', s % 5 <> 0, NOW() + s * INTERVAL '1 minute',
       TIMESTAMPTZ '2026-10-01' - s * INTERVAL '1 minute', NOW()
FROM generate_series(1, 70) s JOIN wt ON wt.rn = s * 3;
INSERT INTO investigation_candidates(plane, family, canonical_locus, title, claim, claimed_severity, evidence_refs,
                                     verification_context, source_kind, fingerprint, status, first_seen_at, last_seen_at,
                                     created_at, updated_at, target_id)
SELECT 'web', 'xss', jsonb_build_object('path', '/c/' || c), 'cand ' || c, 'claim', 'high', '[]', '{{}}', 'hunt',
       'cand-' || c, (ARRAY['new','verified','refuted','inconclusive','blocked','expired'])[1 + c % 6],
       NOW(), NOW(), NOW(), NOW(), wt.id
FROM generate_series(1, 400) c JOIN wt ON wt.rn = ((c - 1) % 900) + 1;

-- standing authorizations: one on a host asset, one on a web member
INSERT INTO scope_receipts(id, target_id, verdict, allowed_hosts, normalized_scope)
SELECT 'scale-scope-' || n, t.id, 'allowed', jsonb_build_array(target_asset_locator(t.url)),
       jsonb_build_object('host', target_asset_locator(t.url))
FROM (SELECT id, url, row_number() OVER (ORDER BY url) AS n FROM targets
      WHERE url IN ('host://d0003.invalid', 'https://s2.d0004.invalid')) t;
INSERT INTO approval_receipts(scope_receipt_id, approved_by, status, risk_tier, action_name)
SELECT id, 'scale-test', 'active', 'active', 'target.authorization' FROM scope_receipts WHERE id LIKE 'scale-scope-%';

-- target badges as scan completion leaves them
UPDATE targets t SET total_scans = 3, last_scanned_at = TIMESTAMPTZ '2026-10-01' - wt.rn * INTERVAL '1 minute',
       last_score = CASE WHEN wt.rn % 9 = 0 THEN NULL ELSE (wt.rn * 7) % 101 END,
       last_grade = (ARRAY['A','B','C','D','F'])[1 + wt.rn % 5],
       active_findings_count = (SELECT count(*) FROM findings f WHERE f.target_id = t.id AND f.status = 'active')
FROM wt WHERE wt.id = t.id AND wt.rn <= 900;
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
            await conn.execute(SEED_SQL)
            # What the API's background builder adds once it serves.
            from runtime.loop_scale_indexes import ensure_loop_scale_indexes
            await ensure_loop_scale_indexes(BoundConnectionPool(conn))
            await conn.execute("ANALYZE")
        finally:
            await conn.close()

    lc.configure_cursor_key(b"s" * 32)
    asyncio.run(setup())
    yield
    lc.configure_cursor_key(None)


def _page(**kwargs) -> lc.Page:
    values = {"limit": 50, "cursor": None, "sort": None, "fields": None, "count": "none", "since": None}
    values.update(kwargs)
    return lc.page_params(**values)


class Spy:
    """A connection that records how many rows each read returned."""

    def __init__(self, conn):
        self.conn, self.rows = conn, []

    async def fetch(self, sql, *args):
        rows = await self.conn.fetch(sql, *args)
        self.rows.append((len(rows), sql))
        return rows

    async def fetchrow(self, sql, *args):
        self.rows.append((1, sql))
        return await self.conn.fetchrow(sql, *args)

    async def fetchval(self, sql, *args):
        self.rows.append((1, sql))
        return await self.conn.fetchval(sql, *args)

    async def execute(self, *args):
        return await self.conn.execute(*args)

    async def executemany(self, sql, rows, *args):
        self.written = list(rows)
        return await self.conn.executemany(sql, self.written, *args)

    def transaction(self):
        return self.conn.transaction()

    def is_in_transaction(self):
        return self.conn.is_in_transaction()

    @property
    def most(self) -> int:
        return max((count for count, _ in self.rows), default=0)


# --- Trigger-maintained counts -----------------------------------------------------------------

FINDING_TRUTH = """SELECT COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid) AS target_id,
       COALESCE(status, '') AS status, COALESCE(severity, '') AS severity, COALESCE(source, '') AS source,
       COALESCE(tool = 'model_intake', false) AS model_intake_tool, ai_target_id IS NOT NULL AS ai_target, count(*) AS n
FROM findings GROUP BY 1, 2, 3, 4, 5, 6"""
SCAN_TRUTH = """SELECT COALESCE(status, '') AS status, COALESCE(run_kind, '') AS run_kind,
       COALESCE(scan_role = 'shard', false) AS shard, count(*) AS n FROM scans GROUP BY 1, 2, 3"""


async def _assert_summary_exact(conn):
    from targets.scale_summary import FINDING_COUNTS_SQL, SCAN_TOTALS_SQL
    summary = {tuple(r.values()) for r in await conn.fetch(f"SELECT * FROM {FINDING_COUNTS_SQL} s")}
    truth = {tuple(r.values()) for r in await conn.fetch(FINDING_TRUTH)}
    assert summary == truth
    scans = {tuple(r.values()) for r in await conn.fetch(f"SELECT * FROM {SCAN_TOTALS_SQL} s")}
    assert scans == {tuple(r.values()) for r in await conn.fetch(SCAN_TRUTH)}


def test_summary_counts_stay_exact_through_every_kind_of_write():
    from targets.scale_summary import compact

    async def check(conn):
        await _assert_summary_exact(conn)
        async with conn.transaction():
            target = await conn.fetchval("SELECT id FROM targets WHERE url = 'https://s3.d0100.invalid'")
            await conn.execute("""INSERT INTO findings(target_id, fingerprint, title, severity, status, source, tool)
                SELECT $1, 'bulk-' || g, 'bulk', (ARRAY['critical','low'])[1 + g % 2], 'active',
                       CASE WHEN g % 3 = 0 THEN NULL ELSE 'scan' END, 'model_intake'
                FROM generate_series(1, 250) g""", target)
            # bucket changes, and a non-bucket change the update trigger must ignore
            await conn.execute("UPDATE findings SET status = 'resolved' WHERE fingerprint LIKE 'bulk-%' AND severity = 'low'")
            await conn.execute("UPDATE findings SET severity = 'high', source = 'ai_gate' WHERE fingerprint = 'bulk-2'")
            await conn.execute("UPDATE findings SET status = NULL WHERE fingerprint = 'bulk-4'")
            await conn.execute("UPDATE findings SET last_seen_at = NOW() WHERE fingerprint LIKE 'seed-1%'")
            await conn.execute("UPDATE findings SET ai_target_id = (SELECT id FROM ai_targets LIMIT 1) WHERE fingerprint = 'bulk-6'")
            # upsert: one conflict updates, one row inserts
            await conn.execute("""INSERT INTO findings(target_id, fingerprint, title, severity, status)
                VALUES ($1, 'bulk-8', 'x', 'medium', 'false_positive'), ($1, 'bulk-new', 'x', 'info', 'active')
                ON CONFLICT (target_id, fingerprint) WHERE target_id IS NOT NULL
                DO UPDATE SET severity = EXCLUDED.severity, status = EXCLUDED.status""", target)
            await conn.execute("DELETE FROM findings WHERE fingerprint IN ('bulk-10', 'bulk-11')")
            await _assert_summary_exact(conn)
            assert await compact(conn) > 0
            await _assert_summary_exact(conn)
            # a cascade from deleting the target, scans moving status
            await conn.execute("DELETE FROM targets WHERE id = $1", target)
            await conn.execute("UPDATE scans SET status = 'failed' WHERE status = 'running'")
            await conn.execute("UPDATE scans SET scan_role = 'shard' WHERE id = (SELECT id FROM scans ORDER BY id LIMIT 1)")
            await conn.execute("UPDATE scans SET progress = 50 WHERE status = 'completed'")
            await _assert_summary_exact(conn)
            await compact(conn)
            await _assert_summary_exact(conn)
            raise _Rollback
    with pytest.raises(_Rollback):
        _run(check)
    _run(_assert_summary_exact)


def test_truncate_resets_the_summary():
    async def check(conn):
        async with conn.transaction():
            await conn.execute("TRUNCATE findings CASCADE")
            await _assert_summary_exact(conn)
            assert await conn.fetchval("SELECT count(*) FROM finding_summary_counts") == 0
            raise _Rollback
    with pytest.raises(_Rollback):
        _run(check)
    _run(_assert_summary_exact)


def test_the_led_compactor_folds_deltas_without_the_dashboard():
    import loop_leader
    from targets import scale_summary

    async def check(conn):
        pool = await asyncpg.create_pool(require_disposable_database(DSN, DATABASE), min_size=1, max_size=3)
        try:
            target = await conn.fetchval("SELECT id FROM targets WHERE url = 'https://s3.d0101.invalid'")
            # Many single-row writes leave one delta row each (the terminal-first install).
            for i in range(300):
                await conn.execute("INSERT INTO findings(target_id, fingerprint, title, severity, status) "
                                   "VALUES ($1, $2, 'x', 'low', 'active')", target, f"led-{i}")
            assert await conn.fetchval("SELECT count(*) FROM finding_summary_deltas") >= 300
            ran = await loop_leader.run_tick(pool, "summary_compactor",
                                             lambda: scale_summary.compact_tick(pool), timeout=60)
            assert ran
            assert await conn.fetchval("SELECT count(*) FROM finding_summary_deltas") == 0
            await _assert_summary_exact(conn)
            # A large fold also refreshes the counts' statistics.
            await conn.execute("UPDATE findings SET status = 'resolved' WHERE fingerprint LIKE 'led-%'")
            await conn.execute("DELETE FROM findings WHERE fingerprint LIKE 'led-%'")
            original = scale_summary.ANALYZE_AFTER_FOLDED_ROWS
            scale_summary.ANALYZE_AFTER_FOLDED_ROWS = 100
            try:
                before = await conn.fetchval(
                    "SELECT analyze_count FROM pg_stat_user_tables WHERE relname = 'finding_summary_counts'")
                assert await scale_summary.compact_tick(pool) >= 300
                after = await conn.fetchval(
                    "SELECT analyze_count FROM pg_stat_user_tables WHERE relname = 'finding_summary_counts'")
            finally:
                scale_summary.ANALYZE_AFTER_FOLDED_ROWS = original
            assert after >= before  # stats views are updated asynchronously; the ANALYZE did run
            await _assert_summary_exact(conn)
        finally:
            await loop_leader.leadership_for(pool).close()
            await pool.close()
            await conn.execute("DELETE FROM findings WHERE fingerprint LIKE 'led-%'")
    _run(check)


def test_the_api_runs_the_compactor_as_a_led_loop():
    import app_lifecycle
    assert "summary_compactor" in app_lifecycle.LIFESPAN_TASK_NAMES
    source = (ROOT / "api" / "targets" / "scale_summary.py").read_text()
    assert 'run_led_loop(pool, "summary_compactor"' in source


def test_a_busy_compactor_is_skipped_not_waited_for():
    async def check(conn):
        other = await _connect()
        try:
            async with other.transaction():
                await other.execute("SELECT pg_advisory_xact_lock(2110, 1)")
                async with conn.transaction():
                    assert await conn.fetchval("SELECT summary_compact()") == -1
        finally:
            await other.close()
    _run(check)


class _Rollback(Exception):
    pass


# --- Dashboard ---------------------------------------------------------------------------------

def test_dashboard_numbers_equal_the_full_table_queries():
    from operations import dashboard_data as dd

    async def check(conn):
        counts = await dd.load_dashboard_counts(conn)
        metrics = await dd.dashboard_metrics(conn, counts)
        assert metrics == dict(await conn.fetchrow("SELECT * FROM dashboard_metrics"))
        assert metrics["total_scans"] > 2000 and metrics["active_findings"] > 5000

        old_scans = [dict(r) for r in await conn.fetch(ref.DASHBOARD_RECENT_SCANS)]
        recent = await dd.recent_latest_scans(conn, limit=10)
        # 2.11 labels each row with its subject's cohort; the rows are the 2.10 ones.
        assert all("target_cohort" in row for row in recent)
        assert [{k: v for k, v in row.items() if k != "target_cohort"} for row in recent] == old_scans
        old_findings = [dict(r) for r in await conn.fetch(ref.DASHBOARD_RECENT_FINDINGS)]
        assert await dd.recent_blocker_findings(conn, limit=10) == old_findings

        dast = await conn.fetchrow(ref.DASHBOARD_DAST_FINDINGS)
        assert (counts.dast_active(blockers=True), counts.dast_active(blockers=False)) == (
            dast["blockers"], dast["active_findings"])
        dast_scans = await conn.fetchrow(ref.DASHBOARD_DAST_SCANS)
        assert (counts.dast_active_scans(), counts.recent_failed_dast_scans) == (
            dast_scans["active_scans"], dast_scans["recent_failed"])
        assert counts.ai_gate_active() == await conn.fetchval(ref.DASHBOARD_AI_GATE)
        assert counts.model_intake_active() == await conn.fetchval(ref.DASHBOARD_MODEL_INTAKE)
        deployment = await conn.fetchrow(ref.DASHBOARD_DEPLOYMENT)
        assert (counts.active_any_source("critical"), counts.active_any_source("high")) == (
            deployment["critical"], deployment["high"])
        blockers = await conn.fetchrow(ref.DASHBOARD_BLOCKERS)
        assert (counts.active_findings("critical"), counts.active_findings("high")) == (
            blockers["critical"], blockers["high"])
        assert counts.recent_failed_dast_scans > 0 and counts.dast_active_scans() > 0
    _run(check)


def test_dashboard_reads_are_bounded_by_buckets_not_rows(monkeypatch):
    from operations import router as operations

    monkeypatch.setattr(operations, "_worker_freshness_snapshot", lambda *a, **k: {"available": False})
    monkeypatch.setattr(operations, "_load_refuter_work_summary", _refuter_summary)
    from arsenal_routes import router as arsenal
    monkeypatch.setattr(arsenal, "_load_benchmark_scorecard_artifacts", lambda **_kwargs: [])
    _compose_routers()

    async def check(conn):
        # The host-class cache (target_cohort_sql.py) is filled once per URL, on first read; the
        # bound is about every later computation.
        import target_cohort_sql
        await target_cohort_sql.fill_url_classes(conn)
        spy = Spy(conn)

        class Pool:
            def acquire(self):
                return _Acquired(spy)

        monkeypatch.setattr(operations, "_pool", lambda: Pool())
        body = await operations._compute_dashboard()
        assert body["metrics"]["active_findings"] > 5000
        assert {"recent-failed-scans", "refuter-review-backlog", "deploy-gate-blockers"} <= {
            item["id"] for item in body["action_center"]}
        assert [item["id"] for item in body["product_status"]] == [
            "dast", "asm", "ai_gate", "model_intake", "deployment", "workers"]
        assert "unavailable" not in " ".join(item["summary"] for item in body["product_status"][:5])
        # The fixture has 12k findings and 3k scans; every read returns at most the count buckets
        # (distinct status/severity/source/flag combinations) or a page-sized list.
        buckets = await conn.fetchval("""SELECT count(*) FROM (SELECT DISTINCT COALESCE(status, ''), severity,
            COALESCE(source, ''), COALESCE(tool = 'model_intake', false), ai_target_id IS NOT NULL FROM findings) b""")
        assert buckets < FINDINGS / 20
        assert spy.most <= max(210, buckets), sorted(spy.rows, key=lambda item: -item[0])[:3]
    _run(check)


def _compose_routers():
    """Wire the routers' injected collaborators the way the API process does."""
    import importlib
    module = importlib.import_module("api")
    if hasattr(module, "__path__"):  # the package layout: the composition root is api.api
        importlib.import_module("api.api")


async def _refuter_summary(conn, **kwargs):
    from arsenal_routes import router as arsenal
    return await arsenal._load_refuter_work_summary(conn, **kwargs)


class _Acquired:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def test_dashboard_cache_is_single_flight(monkeypatch):
    from operations import dashboard_data as dd

    calls = []

    async def compute():
        calls.append(1)
        await asyncio.sleep(0.05)
        return {"n": len(calls)}

    async def check():
        cache = dd.SingleFlightCache(ttl=lambda: 15.0)
        results = await asyncio.gather(*(cache.get(compute) for _ in range(10)))
        assert results == [{"n": 1}] * 10 and len(calls) == 1
        assert await cache.get(compute) == {"n": 1} and len(calls) == 1
        expired = dd.SingleFlightCache(ttl=lambda: 0.0)
        await expired.get(compute)
        await expired.get(compute)
        assert len(calls) == 3
    asyncio.run(check())


# --- Grouped targets ---------------------------------------------------------------------------

def _grouped_kwargs(**overrides):
    values = dict(include_inactive=False, search=None, discovery_source=None, grade=None, has_findings=None,
                  sort_by="root_domain", sort_order="asc", limit=None, cursor=None, sort=None, fields=None,
                  count=None, since=None, member_limit=20)
    values.update(overrides)
    return values


class _Response:
    def __init__(self):
        self.headers = {}


def _with_pool(monkeypatch, module, attr="_pool"):
    async def install(conn):
        class Pool:
            def acquire(self):
                return _Acquired(conn)
        monkeypatch.setattr(module, attr, lambda: Pool())
    return install


def test_grouped_legacy_enrichment_equals_the_per_target_queries(monkeypatch):
    from targets import router as targets_router, grouped_list

    async def check(conn):
        await _with_pool(monkeypatch, targets_router)(conn)
        response = _Response()
        legacy = await targets_router.list_targets_grouped(response, **_grouped_kwargs())
        assert response.headers["Deprecation"] == "true"
        ids = [t["id"] for d in legacy["domains"] for t in ([d["root_target"]] if d["root_target"] else []) + d["subdomains"]]
        uuids = [uuid.UUID(i) for i in ids]
        old_investigator = {str(r["target_id"]): (r["investigator_verified_count"], r["investigator_suspected_count"])
                            for r in await conn.fetch(ref.GROUPED_INVESTIGATOR, uuids)}
        new_investigator = await grouped_list.investigator_counts(conn, uuids)
        assert {k: (v["investigator_verified_count"], v["investigator_suspected_count"])
                for k, v in new_investigator.items()} == old_investigator
        assert any(v[0] for v in old_investigator.values()) and any(v[1] for v in old_investigator.values())
        old_asm = {str(r["target_id"]): dict(r) for r in await conn.fetch(ref.GROUPED_ASM, uuids)}
        new_asm = {str(r["target_id"]): dict(r) for r in await conn.fetch(grouped_list.ASM_COVERAGE_SQL, uuids)}
        assert new_asm == old_asm and len(old_asm) == 20
    _run(check)


def _comparable_group(group: dict) -> dict:
    members = ([group["root_target"]] if group["root_target"] else []) + group["subdomains"]
    return {
        "root_domain": group["root_domain"],
        "root": group["root_target"]["id"] if group["root_target"] else None,
        "subdomains": [m["id"] for m in group["subdomains"]],
        "values": (group["subdomain_count"], group["total_count"], group["total_findings"], group["best_score"],
                   group["latest_scan"], group["earliest_created"]),
        "asm": group["asm_coverage"],
        "members": {m["id"]: (m.get("asm_coverage"), m["investigator_verified_count"],
                              m["investigator_suspected_count"], m["authorized_for_active_testing"]) for m in members},
    }


async def _walk(fetch, first_page: lc.Page, mutate=None):
    items, cursor, pages = [], None, 0
    while True:
        page = lc.Page(limit=first_page.limit, cursor=cursor, sort=first_page.sort, count=first_page.count)
        body = await fetch(page)
        assert len(body["items"]) <= first_page.limit
        items.extend(body["items"])
        pages += 1
        if mutate and pages == 2:
            await mutate()
        if not body["has_more"]:
            assert body["next_cursor"] is None
            return items, pages
        cursor = body["next_cursor"]


@pytest.mark.parametrize("sort_by,sort_order", [
    ("root_domain", "asc"), ("active_findings_count", "desc"), ("last_score", "asc"), ("last_score", "desc"),
    ("last_scanned_at", "desc"), ("created_at", "asc"),
])
def test_grouped_v1_pages_hold_exactly_the_legacy_groups(monkeypatch, sort_by, sort_order):
    from targets import router as targets_router, grouped_list

    async def check(conn):
        await _with_pool(monkeypatch, targets_router)(conn)
        legacy = await targets_router.list_targets_grouped(
            _Response(), **_grouped_kwargs(sort_by=sort_by, sort_order=sort_order))
        sort = ("-" if sort_order == "desc" else "") + sort_by

        async def fetch(page):
            return await grouped_list.grouped_page(
                conn, page, filters={"sort": sort}, member_limit=200,
                member_columns=_member_columns(targets_router), public_row=targets_router._public_target_row)

        items, pages = await _walk(fetch, _page(limit=37, sort=sort))
        assert pages > 5
        assert [_comparable_group(g) for g in sorted(items, key=lambda g: g["root_domain"])] == [
            _comparable_group(g) for g in sorted(legacy["domains"], key=lambda g: g["root_domain"])]
        # Same order on the sort key (ties may break differently: the keyset breaks them by domain).
        key = {"root_domain": lambda g: g["root_domain"].lower(), "active_findings_count": lambda g: g["total_findings"],
               "last_score": lambda g: g["best_score"], "last_scanned_at": lambda g: g["latest_scan"] or "",
               "created_at": lambda g: g["earliest_created"] or ""}[sort_by]
        assert [key(g) for g in items] == [key(g) for g in legacy["domains"]]
        assert any(g["root_domain"] == "unknown" for g in items)
    _run(check)


def _member_columns(targets_router) -> str:
    return f"{targets_router._GROUPED_TARGET_COLUMNS}, {targets_router._authorized_for_active_testing_sql()}"


def test_grouped_v1_caps_members_and_reads_only_the_page(monkeypatch):
    from targets import router as targets_router, grouped_list

    async def check(conn):
        spy = Spy(conn)
        body = await grouped_list.grouped_page(
            spy, _page(limit=10, count="exact"), filters={}, member_limit=5,
            member_columns=_member_columns(targets_router), public_row=targets_router._public_target_row)
        assert body["total_kind"] == "exact" and body["total"] == DOMAINS + 2
        big = next(g for g in body["items"] if g["root_domain"] == "big.invalid")
        assert big["subdomain_count"] == BIG_MEMBERS and len(big["subdomains"]) == 5 and big["subdomains_truncated"]
        assert all(len(g["subdomains"]) <= 5 for g in body["items"])
        # 1,300 targets: no read returns more than a page of groups or of members.
        assert spy.most <= 10 * 6 + 1, sorted(spy.rows, key=lambda item: -item[0])[:2]
    _run(check)


def test_grouped_v1_cursor_is_stable_under_inserts_and_bound_to_filters(monkeypatch):
    from targets import router as targets_router, grouped_list

    async def check(conn):
        async def fetch(page):
            return await grouped_list.grouped_page(
                conn, page, filters={"search": None}, member_limit=3,
                member_columns=_member_columns(targets_router), public_row=targets_router._public_target_row)

        before = {r["k"] for r in await conn.fetch(
            "SELECT DISTINCT COALESCE(NULLIF(root_domain, ''), 'unknown') AS k FROM targets "
            "WHERE is_active AND COALESCE(discovery_source, 'manual') NOT IN ('model-intake','host')")}

        async def insert():
            await conn.execute("INSERT INTO targets(url, root_domain, is_root) VALUES "
                               "('https://aaa-early.invalid', 'aaa-early.invalid', true), "
                               "('https://zzz-late.invalid', 'zzz-late.invalid', true)")
        try:
            items, _ = await _walk(fetch, _page(limit=40), mutate=insert)
            domains = [g["root_domain"] for g in items]
            assert len(domains) == len(set(domains))
            assert before <= set(domains) and "zzz-late.invalid" in domains and "aaa-early.invalid" not in domains
            first = await fetch(_page(limit=40))
            with pytest.raises(HTTPException) as caught:
                await grouped_list.grouped_page(
                    conn, _page(limit=40, cursor=first["next_cursor"]), filters={"search": "d00"}, member_limit=3,
                    member_columns=_member_columns(targets_router), public_row=targets_router._public_target_row)
            assert caught.value.detail["error"] == "cursor_mismatch"
        finally:
            await conn.execute("DELETE FROM targets WHERE url IN ('https://aaa-early.invalid', 'https://zzz-late.invalid')")
    _run(check)


# --- Inventory ---------------------------------------------------------------------------------

def _old_inventory(monkeypatch, ai):
    """Patch the module back to the 2.10 correlated fragments (the oracle)."""
    old = ref.old_inventory_fragments(ai)
    monkeypatch.setitem(ai.SORTS, "risk", (old["risk"], "max", "DESC"))
    monkeypatch.setitem(ai.FILTERS, "findings", {"any": old["any"], "critical_high": old["critical_high"],
                                                 "none": f"NOT {old['any']}"})
    old_any = (f"({ref.old_authorized_sql(ai, 't')} OR (SELECT count(*) FROM targets member WHERE member.asset_owner_id=t.id "
               f"AND member.is_active AND {ref.old_authorized_sql(ai, 'member')}) > 0)")
    monkeypatch.setitem(ai.FILTERS, "authorization", {"authorized": old_any, "unauthorized": f"NOT {old_any}"})
    monkeypatch.setattr(ai, "DETAIL_COLUMNS", ai.DETAIL_COLUMNS
                        .replace(ai.authorized_sql("t"), ref.old_authorized_sql(ai, "t"))
                        .replace(ai.authorized_sql("member"), ref.old_authorized_sql(ai, "member")))


@pytest.mark.parametrize("options", [
    {"sort": "risk"}, {"sort": "name"}, {"sort": "recent"}, {"findings": "any"}, {"findings": "critical_high"},
    {"findings": "none", "sort": "risk"}, {"authorization": "authorized"}, {"authorization": "unauthorized", "sort": "risk"},
    {"group_by": "domain", "sort": "risk"}, {"group_by": "domain", "findings": "critical_high"},
    {"include_services": True, "sort": "risk"},
])
def test_inventory_summary_reads_equal_the_correlated_queries(monkeypatch, options):
    from targets import asset_inventory as ai

    async def check(conn):
        new = await ai.list_assets(conn, limit=500, include_facets=True, **options)
        with pytest.MonkeyPatch.context() as patch:
            _old_inventory(patch, ai)
            old = await ai.list_assets(conn, limit=500, include_facets=True, **options)
        assert new == old
        assert new["total"] > 0
    _run(check)


def test_inventory_facets_equal_the_correlated_facets():
    from targets import asset_inventory as ai

    async def check(conn):
        facets = {}
        for search in ("", "d00", "big"):
            query = ai._scope_query(search=search, connected_only=False, include_inactive=False, include_services=False)
            facets[search] = await ai.inventory_facets(conn, ai._Query(query.where, query.parameters))
            assert facets[search] == await ref.old_inventory_facets(conn, ai, query.where, query.parameters)
        assert facets[""]["authorization"]["authorized"] == 2 and facets[""]["findings"]["critical_high"] > 0
    _run(check)


@pytest.mark.parametrize("sort", ["name", "-risk", "-recent", "created"])
def test_inventory_v1_walk_returns_the_legacy_assets_in_sort_order(sort):
    from targets import asset_inventory as ai

    async def check(conn):
        legacy_sort = sort.lstrip("-")
        legacy = await ai.list_assets(conn, limit=500, sort=legacy_sort)
        legacy_all = legacy["targets"]
        offset = 500
        while offset < legacy["total"]:
            legacy_all += (await ai.list_assets(conn, limit=500, offset=offset, sort=legacy_sort))["targets"]
            offset += 500

        async def fetch(page):
            return await ai.list_assets_v1(conn, page)

        items, _ = await _walk(fetch, _page(limit=113, sort=sort))
        assert sorted(a["id"] for a in items) == sorted(a["id"] for a in legacy_all)
        assert len(items) == len({a["id"] for a in items})
        by_id = {a["id"]: a for a in legacy_all}
        assert all(by_id[a["id"]] == a for a in items)
        # In the sort's order, keyset tiebreak included.
        expr, _kind = ai._SORT_KEYS[legacy_sort]
        direction = "DESC" if sort.startswith("-") else "ASC"
        scope = ai._scope_query(search="", connected_only=False, include_inactive=False, include_services=False)
        expected = [r["id"] for r in await conn.fetch(
            f"SELECT t.id FROM {ai.SUMMARY_FROM} WHERE {scope.where} ORDER BY {expr} {direction}, t.id {direction}",
            *scope.parameters)]
        assert [uuid.UUID(str(a["id"])) for a in items] == expected
    _run(check)


def test_inventory_v1_domain_groups_hold_the_legacy_groups_with_capped_members():
    from targets import asset_inventory as ai

    async def check(conn):
        legacy = await ai.list_assets(conn, group_by="domain", limit=1000)
        legacy_groups = {g["root_domain"]: [a["id"] for a in g["targets"]] for g in legacy["groups"]}

        async def fetch(page):
            return await ai.list_assets_v1(conn, page, group_by="domain", member_limit=200)

        items, _ = await _walk(fetch, _page(limit=29))
        assert [g["root_domain"] for g in items] == [g["root_domain"] for g in legacy["groups"]]
        assert {g["root_domain"]: [a["id"] for a in g["targets"]] for g in items} == legacy_groups
        # The group cache fills in locator order, so concurrent fills lock rows in one order.
        await conn.execute("DELETE FROM target_inventory_groups")
        filler = Spy(conn)
        await ai.list_assets_v1(filler, _page(limit=5), group_by="domain")
        assert len(filler.written) > 100 and filler.written == sorted(filler.written)
        spy = Spy(conn)
        capped = await ai.list_assets_v1(spy, _page(limit=10, sort="-risk", count="exact"), group_by="domain",
                                         member_limit=4, include_facets=True)
        assert capped["total"] == len(legacy_groups)
        # The target total counts every filtered asset, not the facets' search scope.
        assert (capped["target_total"], capped["target_total_kind"]) == (legacy["total"], "exact")
        narrowed = await ai.list_assets_v1(conn, _page(limit=10, count="exact"), group_by="domain",
                                           findings="none", include_facets=True)
        expected = (await ai.list_assets(conn, group_by="domain", findings="none", limit=1))["total"]
        assert narrowed["target_total"] == expected < narrowed["facets"]["total"]
        assert "target_total" not in (await ai.list_assets_v1(conn, _page(limit=10), group_by="domain"))
        assert all(len(g["targets"]) <= 4 for g in capped["items"])
        assert sum(g["members_truncated"] for g in capped["items"]) >= 0
        assert spy.most <= 10 * 4 + 1, sorted(spy.rows, key=lambda item: -item[0])[:2]
    _run(check)


def test_inventory_v1_flat_page_reads_are_bounded():
    from targets import asset_inventory as ai

    async def check(conn):
        spy = Spy(conn)
        body = await ai.list_assets_v1(spy, _page(limit=25, sort="-risk", count="estimate"), include_facets=True)
        assert len(body["items"]) == 25 and body["has_more"] and body["total_kind"] == "estimate"
        assert spy.most <= 26
        with pytest.raises(HTTPException) as caught:
            await ai.list_assets_v1(conn, _page(limit=25, cursor=body["next_cursor"], sort="-risk"), findings="any")
        assert caught.value.detail["error"] == "cursor_mismatch"
    _run(check)


# --- Graph, ASM coverage, campaigns, refuter, schedules ----------------------------------------

def test_graph_v1_walk_returns_every_node_and_edge_once_by_id(monkeypatch):
    from targets import router as targets_router

    async def check(conn):
        await _with_pool(monkeypatch, targets_router)(conn)
        target = str(await conn.fetchval("SELECT target_id FROM application_graph_nodes LIMIT 1"))
        response = _Response()
        legacy = await targets_router.get_application_graph(
            target, response, None, None, "nodes", None, None, None, None, None, None)
        assert response.headers["Deprecation"] == "true"

        async def fetch_kind(kind, page, inserted=None):
            body = await targets_router.get_application_graph(
                target, _Response(), None, None, kind, page.limit, page.cursor, page.sort, None,
                page.count or "none", None)
            assert body["summary"] == legacy["summary"] or inserted
            return body

        late = []

        async def insert():
            late.append(await conn.fetchval(
                "INSERT INTO application_graph_nodes(id, target_id, node_type, node_key) "
                "VALUES ('ffffffff-ffff-4fff-bfff-ffffffffffff', $1, 'route', $2) RETURNING id",
                uuid.UUID(target), "k:" + "x" * 5000))  # a key far past any cursor bound
        try:
            nodes, _ = await _walk(lambda page: fetch_kind("nodes", page, inserted=True), _page(limit=150), mutate=insert)
            ids = [uuid.UUID(n["id"]) for n in nodes]
            assert ids == sorted(ids) and len(ids) == len(set(ids))
            assert {n["id"] for n in legacy["nodes"]} | {str(late[0])} == {n["id"] for n in nodes}
            assert isinstance(nodes[0]["attributes"], dict)
            # The keyset is on the uuid id: an index range scan, whatever a node key holds.
            plan = await conn.fetchval(
                "EXPLAIN (FORMAT JSON) SELECT n.id FROM application_graph_nodes n WHERE n.target_id = $1 "
                "AND (n.id, n.id) > ($2, $2) ORDER BY n.id, n.id LIMIT 51", uuid.UUID(target), ids[10])
            assert "idx_app_graph_nodes_target_id_walk" in str(plan) and '"Sort"' not in str(plan)
        finally:
            await conn.execute("DELETE FROM application_graph_nodes WHERE id = 'ffffffff-ffff-4fff-bfff-ffffffffffff'")
        edges, _ = await _walk(lambda page: fetch_kind("edges", page), _page(limit=200))
        assert sorted(e["id"] for e in edges) == sorted(e["id"] for e in legacy["edges"])
        spy = Spy(conn)
        await _with_pool(monkeypatch, targets_router)(spy)
        body = await targets_router.get_application_graph(
            target, _Response(), None, None, "nodes", 50, None, None, None, "exact", None)
        assert body["total"] == GRAPH_NODES and spy.most <= 51
    _run(check)


def test_asm_coverage_counts_equal_the_per_attempt_rows():
    import asm_inventory

    async def check(conn):
        targets = [r["target_id"] for r in await conn.fetch("SELECT DISTINCT target_id FROM target_endpoints")]
        assert len(targets) == 20
        for target in targets:
            rows = await conn.fetch(ref.ASM_LATEST_ATTEMPTS, target)
            testable = await conn.fetchval(
                "SELECT count(*) FROM target_endpoints WHERE target_id = $1 AND test_status <> 'gone'", target)
            old = asm_inventory.attempt_coverage_from_rows(list(rows), total=testable, basis="latest_attempt_per_endpoint")
            spy = Spy(conn)
            new = await asm_inventory.coverage_summary(spy, str(target))
            assert new["attempt_coverage"] == old
            assert spy.most == 1
        assert old["completed"] >= 0
    _run(check)


def test_asm_coverage_normalization_matches_the_python_rules():
    import asm_inventory
    shapes = [
        ("completed", {"per_endpoint_telemetry": True, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}}),
        (" Completed ", {"per_endpoint_telemetry": " TRUE ", "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}}),
        ("completed", {"per_endpoint_telemetry": 1, "endpoint_attempt": {"schema_version": "active_endpoint_attempt_v1"}}),
        ("completed", {"per_endpoint_telemetry": True}),
        ("completed", {"per_endpoint_telemetry": True, "endpoint_attempt": "active_endpoint_attempt_v1"}),
        ("completed", "not an object"), ("TIMEOUT", {}), ("auth_failed", {}), ("rate_limited", None),
    ]

    async def check(conn):
        async with conn.transaction():
            target = await conn.fetchval("INSERT INTO targets(url) VALUES ('https://norm.invalid') RETURNING id")
            for i, (status, telemetry) in enumerate(shapes):
                endpoint = await conn.fetchval(
                    "INSERT INTO target_endpoints(target_id, path, fingerprint) VALUES ($1, $2, $2) RETURNING id",
                    target, f"/n{i}")
                await conn.execute(
                    "INSERT INTO asm_endpoint_attempts(endpoint_id, status, scanner_telemetry_json) VALUES ($1, $2, $3::jsonb)",
                    endpoint, status, json.dumps(telemetry if telemetry is not None else {}))
            expected = asm_inventory.attempt_coverage_from_rows(
                [{"status": s, "scanner_telemetry_json": t} for s, t in shapes], total=len(shapes), basis="b")
            counts = await conn.fetchrow(asm_inventory.LATEST_ATTEMPT_COUNTS_SQL, target,
                                         asm_inventory.ENDPOINT_ATTEMPT_SCHEMA_V1)
            assert asm_inventory.attempt_coverage_from_counts(counts, total=len(shapes), basis="b") == expected
            assert expected["completed"] == 2 and expected["partial"] == 5
            raise _Rollback
    with pytest.raises(_Rollback):
        _run(check)


def test_campaign_impact_equals_the_text_join_and_compares_as_uuid():
    from arsenal_routes import router as arsenal

    async def check(conn):
        ids = [r["id"] for r in await conn.fetch("SELECT id FROM campaigns ORDER BY created_at DESC")]
        old = await ref.old_campaign_impact(conn, ids, arsenal._campaign_deployment_impact)
        spy = Spy(conn)
        new = await arsenal._campaign_live_finding_impact(spy, ids)
        assert new == old
        assert any(v["partial"] for v in new.values()) and all(v["linked_finding_count"] for v in new.values())
        assert spy.most <= len(ids) * 25
        plan = await conn.fetchval("EXPLAIN (FORMAT JSON) " + spy.rows[0][1], ids)
        assert "findings_pkey" in str(plan) and "f.id)::text" not in str(plan)
    _run(check)


def test_refuter_summary_equals_the_full_sort_and_bounds_the_scan_window(monkeypatch):
    from arsenal_routes import router as arsenal

    monkeypatch.setattr(arsenal, "_load_benchmark_scorecard_artifacts", lambda **_kwargs: [])
    _compose_routers()

    async def check(conn):
        for window in (50, 400, 3000):
            old = await conn.fetch(ref.REFUTER_FINDINGS, window)
            new = await arsenal._refuter_window_findings(conn, window)
            assert [r["id"] for r in new] == [r["id"] for r in old]
        old_scans = await conn.fetch(ref.REFUTER_SCANS, arsenal.REFUTER_FINDING_DELTA_MIN_BASELINE + 4)
        old_signals = arsenal._finding_delta_refuter_signals(arsenal._finding_delta_target_stats(old_scans), limit=20)
        expected = arsenal._refuter_work_summary([], [], limit=20, integrity_signals=old_signals)["integrity_signals"]
        assert len(old_signals) > 3
        # With windows covering every target the bounded read is the 2.10 read.
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(arsenal, "REFUTER_FINDING_DELTA_TARGET_WINDOW", 100_000)
            patch.setattr(arsenal, "REFUTER_FINDING_DELTA_SCAN_WINDOW", 1_000_000)
            summary = await arsenal._load_refuter_work_summary(conn, limit=20, finding_window=200)
        assert summary["integrity_signals"] == expected
        # With the default windows only the most recently scanned targets are read, one row each.
        spy = Spy(conn)
        bounded = await arsenal._load_refuter_work_summary(spy, limit=20, finding_window=200)
        assert spy.most <= max(200, arsenal.REFUTER_FINDING_DELTA_TARGET_WINDOW)
        recent = {r["target_id"] for r in await conn.fetch(
            "SELECT target_id FROM scans WHERE status = 'completed' AND run_kind = 'web_dast' AND target_id IS NOT NULL "
            "AND scan_role IS DISTINCT FROM 'shard' GROUP BY target_id ORDER BY max(created_at) DESC LIMIT $1",
            arsenal.REFUTER_FINDING_DELTA_TARGET_WINDOW)}
        kept = [s for s in expected if uuid.UUID(s["target_id"]) in recent]
        assert bounded["integrity_signals"] == kept
    _run(check)


def test_schedules_total_counts_every_match(monkeypatch):
    from schedules import router as schedules

    async def check(conn):
        await _with_pool(monkeypatch, schedules)(conn)
        page = await schedules.list_schedules(target_id=None, is_active=None, limit=50, offset=0)
        assert len(page["schedules"]) == 50 and page["total"] == 70
        active = await schedules.list_schedules(target_id=None, is_active=True, limit=10, offset=60)
        assert active["total"] == await conn.fetchval("SELECT count(*) FROM schedules WHERE is_active")
    _run(check)


# --- Startup -----------------------------------------------------------------------------------

def test_read_path_indexes_are_built_by_the_background_builder():
    from runtime.loop_scale_indexes import LOOP_SCALE_INDEXES, ensure_loop_scale_indexes
    from targets.asset_migration import BoundConnectionPool

    async def check(conn):
        names = [name for name, *_ in LOOP_SCALE_INDEXES]
        assert len(names) == len(set(names))
        for wanted in ("idx_scans_status_created", "idx_scans_target_created", "idx_targets_url_trgm",
                       "idx_app_graph_nodes_target_id_walk", "idx_asm_endpoint_attempts_latest"):
            assert wanted in names
        # One waiting-scan walk index (the loops' idx_scans_waiting_created_walk), not two.
        assert sum("WHERE status IN ('pending','queued')" in d.replace(", ", ",") for *_, d in LOOP_SCALE_INDEXES) == 1
        valid = {r["relname"] for r in await conn.fetch(
            "SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE i.indisvalid")}
        assert set(names) <= valid
        assert await ensure_loop_scale_indexes(BoundConnectionPool(conn)) == []
        # A failed concurrent build leaves an INVALID index under the name; the builder drops it
        # and builds the declared definition.
        await conn.execute("DROP INDEX idx_scans_status_created")
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute("CREATE UNIQUE INDEX CONCURRENTLY idx_scans_status_created ON scans (status)")
        assert await ensure_loop_scale_indexes(BoundConnectionPool(conn)) == ["idx_scans_status_created"]
        definition = await conn.fetchval("SELECT pg_get_indexdef('idx_scans_status_created'::regclass)")
        assert "UNIQUE" not in definition and "created_at DESC" in definition
    _run(check)


def test_redundant_scans_indexes_are_dropped_once_their_covering_index_is_valid():
    """idx_scans_target_id and idx_scans_unified_target (scans(target_id)) and idx_scans_status
    (scans(status)) are served by the declared (target_id, created_at DESC) and (status,
    created_at DESC) indexes. The builder drops them concurrently, only after the covering index is
    valid, and leaves an index under one of those names with another definition alone. The scans
    lookups they served (by target, by status, the targets delete cascade) plan on the covering
    indexes."""
    from runtime.loop_scale_indexes import REDUNDANT_INDEXES, ensure_loop_scale_indexes
    from targets.asset_migration import BoundConnectionPool

    async def present(conn):
        return {r["relname"] for r in await conn.fetch(
            "SELECT relname FROM pg_class WHERE relname = ANY($1::text[])",
            [name for name, *_rest in REDUNDANT_INDEXES])}

    async def check(conn):
        # The fixture ran the builder already: a fresh install converges to no redundant index.
        assert await present(conn) == set()
        # A database as every earlier release left it (init.sql and the asset conversion made them).
        for name, table, column, _covering in REDUNDANT_INDEXES:
            await conn.execute(f"CREATE INDEX {name} ON {table} ({column})")
        await conn.execute("DROP INDEX idx_scans_status_created")
        pool = BoundConnectionPool(conn)
        # A covering index that cannot be built yet keeps the index it would replace.
        await conn.execute("CREATE INDEX idx_scans_status_created ON scans (status, created_at DESC)")
        await conn.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'idx_scans_status_created'::regclass")
        assert await ensure_loop_scale_indexes(pool, retry_delays=()) == ["idx_scans_status_created"]
        assert await present(conn) == set()
        # Another definition under a redundant name is not the old schema's index: kept.
        await conn.execute("CREATE INDEX idx_scans_status ON scans (status) WHERE status = 'running'")
        assert await ensure_loop_scale_indexes(pool, retry_delays=()) == []
        assert await present(conn) == {"idx_scans_status"}
        await conn.execute("DROP INDEX idx_scans_status")

        target = await conn.fetchval("SELECT target_id FROM scans WHERE target_id IS NOT NULL LIMIT 1")
        used = []
        for query, args in (
            ("SELECT id FROM scans WHERE target_id = $1", (target,)),
            ("SELECT count(*) FROM scans WHERE target_id = $1", (target,)),
            ("SELECT id FROM scans WHERE status = 'running'", ()),
            ("SELECT count(*) FROM scans WHERE status IN ('pending', 'queued', 'running')", ()),
        ):
            async with conn.transaction():
                await conn.execute("SET LOCAL enable_seqscan = off")
                plan = json.loads(await conn.fetchval(f"EXPLAIN (FORMAT JSON) {query}", *args))[0]["Plan"]
            names = set()
            stack = [plan]
            while stack:
                node = stack.pop()
                names.add(node.get("Index Name"))
                stack.extend(node.get("Plans", []))
            used.append(names)
            assert names & {"idx_scans_target_created", "idx_scans_status_created", "idx_scans_active_target"}, (query, names)
        # The delete cascade from targets finds a target's scans through the covering index too.
        async with conn.transaction():
            await conn.execute("SET LOCAL enable_seqscan = off")
            plan = json.loads(await conn.fetchval(
                "EXPLAIN (FORMAT JSON) SELECT 1 FROM ONLY scans x WHERE $1 OPERATOR(pg_catalog.=) target_id FOR KEY SHARE OF x",
                target))[0]["Plan"]
        assert "idx_scans_target_created" in json.dumps(plan)
    _run(check)


def test_index_health_reports_a_build_that_gave_up_and_one_in_progress():
    from runtime import loop_scale_indexes
    from targets.asset_migration import BoundConnectionPool

    async def check(conn):
        pool = BoundConnectionPool(conn)
        assert await loop_scale_indexes.ensure_loop_scale_indexes(pool, retry_delays=()) == []
        health = await loop_scale_indexes.index_health(conn)
        assert health["status"] == "ok" and health["missing"] == [] and health["invalid"] == []
        assert health["last_run"]["state"] == "done" and health["redundant_present"] == []

        # A build that keeps failing (here: a definition the server refuses) is "failed".
        original = loop_scale_indexes.LOOP_SCALE_INDEXES
        broken = ("idx_targets_broken_health", "targets", "targets (no_such_column)")
        loop_scale_indexes.LOOP_SCALE_INDEXES = (*original, broken)
        try:
            await loop_scale_indexes.ensure_loop_scale_indexes(pool, retry_delays=(0.0,))
            health = await loop_scale_indexes.index_health(conn)
            assert health["status"] == "failed", health
            assert health["missing"] == ["idx_targets_broken_health"]
            assert health["last_run"]["state"] == "failed"
            assert health["last_run"]["failed"] == [
                {"index": "idx_targets_broken_health", "error": "UndefinedColumnError"}]

            # While another process holds the build lock, the same gap reads "building".
            holder = await _connect()
            try:
                assert await holder.fetchval("SELECT pg_try_advisory_lock($1::int, $2::int)",
                                             loop_scale_indexes._LOCK_NAMESPACE, loop_scale_indexes._LOCK_KEY)
                assert (await loop_scale_indexes.index_health(conn))["status"] == "building"
            finally:
                await holder.close()
        finally:
            loop_scale_indexes.LOOP_SCALE_INDEXES = original
        assert (await loop_scale_indexes.index_health(conn))["status"] == "ok"
    _run(check)


def test_concurrent_builds_never_wait_under_the_startup_lock_with_a_waiter_present():
    """CREATE/DROP INDEX CONCURRENTLY under the startup lock (8675309) deadlocks with a process
    waiting for that lock (its waiting statement holds a snapshot the build waits for). The
    builder runs after serving and never takes it: with a waiter queued behind another holder,
    the build finishes once that holder lets go, and it never held the lock itself."""
    from runtime.loop_scale_indexes import ensure_loop_scale_indexes
    from targets.asset_migration import BoundConnectionPool

    async def check(conn):
        holder, waiter, builder = await _connect(), await _connect(), await _connect()
        try:
            await conn.execute("DROP INDEX IF EXISTS idx_scans_target_created")
            await holder.execute("SELECT pg_advisory_lock(8675309)")
            waiting = asyncio.ensure_future(waiter.execute("SELECT pg_advisory_lock(8675309)"))
            await asyncio.sleep(0.3)
            assert not waiting.done()
            build = asyncio.ensure_future(ensure_loop_scale_indexes(BoundConnectionPool(builder)))
            await asyncio.sleep(1.0)
            held_by_builder = await conn.fetchval(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 8675309 AND granted "
                "AND pid = $1", builder.get_server_pid())
            assert held_by_builder == 0
            await holder.execute("SELECT pg_advisory_unlock(8675309)")
            await asyncio.wait_for(waiting, 30)
            assert await asyncio.wait_for(build, 60) == ["idx_scans_target_created"]
            await waiter.execute("SELECT pg_advisory_unlock(8675309)")
        finally:
            for other in (holder, waiter, builder):
                await other.close()
    _run(check)


async def _deadlocks(conn) -> int:
    await conn.execute("SELECT pg_stat_clear_snapshot()")
    return await conn.fetchval("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")


def test_a_restart_during_builds_on_every_loop_index_table_completes_without_deadlock():
    """The background builder is mid-CREATE INDEX CONCURRENTLY on every table it builds on (the
    tables come from LOOP_SCALE_INDEXES, so a table added there is covered), each build stalled on
    an open snapshot while holding its table lock; a process restarts and runs the startup
    migrations, and another queues on the startup lock (8675309). Every startup statement on an
    up-to-date database must be a catalog check that takes no lock a build holds: the startup
    completes while the builds still wait, and nothing deadlocks. This is the one restart-during-builds
    test: findings, scans, targets and every other builder table are derived, not listed."""
    from retest_contract import run_schema_migrations
    from runtime.loop_scale_indexes import LOOP_SCALE_INDEXES

    async def check(conn):
        dsn = require_disposable_database(DSN, DATABASE)
        tables = {table for _name, table, _definition in LOOP_SCALE_INDEXES}
        present = {table for table in tables if await conn.fetchval("SELECT to_regclass($1)", table)}
        assert {"findings", "scans", "targets", "hunt_permission_requests"} <= present
        picks: dict[str, tuple[str, str]] = {}
        for name, table, definition in LOOP_SCALE_INDEXES:
            if table in present and table not in picks and "gin_trgm_ops" not in definition:
                picks[table] = (name, definition)
        assert set(picks) == present, "one build on every builder table present"
        for name, _definition in picks.values():
            await conn.execute(f"DROP INDEX IF EXISTS {name}")
        before = await _deadlocks(conn)
        holder = await asyncpg.connect(dsn)
        waiter = await asyncpg.connect(dsn)
        startup_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        builders = []
        try:
            await holder.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            await holder.fetchval("SELECT 1")  # an open snapshot stalls every concurrent build
            for name, definition in picks.values():
                session = await asyncpg.connect(dsn)
                builders.append((session, asyncio.ensure_future(
                    session.execute(f"CREATE INDEX CONCURRENTLY {name} ON {definition}"))))
            await asyncio.sleep(1.0)
            assert not any(task.done() for _session, task in builders)
            startup = asyncio.ensure_future(run_schema_migrations(startup_pool))
            await asyncio.sleep(0.2)
            queued = asyncio.ensure_future(waiter.execute("SELECT pg_advisory_lock(8675309)"))
            await asyncio.wait_for(startup, 60)  # blocked behind a build, it would never finish
            assert not any(task.done() for _session, task in builders)
            await asyncio.wait_for(queued, 30)
            await waiter.execute("SELECT pg_advisory_unlock(8675309)")
            await holder.execute("ROLLBACK")
            for _session, task in builders:
                await asyncio.wait_for(task, 120)
        finally:
            for session, _task in builders:
                await session.close()
            await holder.close()
            await waiter.close()
            await startup_pool.close()
        await asyncio.sleep(1.5)  # backends flush their statistics when they go idle
        assert await _deadlocks(conn) == before
        for name, _definition in picks.values():
            assert await conn.fetchval(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)", name) is True, name
    _run(check)
