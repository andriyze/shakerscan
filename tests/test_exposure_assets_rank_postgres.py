"""GET /exposure/assets ranked in SQL, on real PostgreSQL: the same answers as before, bounded work.

Only EXPOSURE_ASSETS_TEST_DATABASE_URL on localhost/shakerscan_exposure_assets_test is permitted. Its
public schema is RESET, db/init.sql is loaded and the engine's startup migrations run, so these tests
use the real schema, triggers and indexes.

* The limit/offset response equals the previous implementation's (tests/exposure_assets_reference.py,
  which ranked every asset in Python) for a matrix of kinds, cohorts, root domains and pages over a
  fixture that exercises every reason, priority, cohort rule, scan state and proof count.
* list/v1 walks the same order with a cursor, carries the same summary, and refuses a cursor from
  other filters.
* The stored per-asset facts follow edits (trigger), survive a racing edit, and the startup install
  is a catalog-only no-op on a database that has them.
* EXPLAIN shows the ranking never reads the findings table beyond its small partial indexes.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import random
import sys
from urllib.parse import urlsplit, urlunsplit
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("EXPOSURE_ASSETS_TEST_DATABASE_URL")
REQUIRED = os.environ.get("EXPOSURE_ASSETS_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable exposure-assets PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import HTTPException  # noqa: E402

from exposure import asset_rank  # noqa: E402
import exposure.router as exposure_router  # noqa: E402
import list_contract  # noqa: E402
from runtime import loop_scale_indexes  # noqa: E402
from tests.exposure_assets_reference import reference_exposure_assets  # noqa: E402

NOW = datetime.now(timezone.utc)


def _ago(days: float) -> datetime:
    # Whole days plus half a day: no fixture timestamp sits on the 7- or 30-day boundary.
    return NOW - timedelta(days=days + 0.5)


TARGET_URLS = [
    "https://app.alpha.test", "https://api.alpha.test/v2", "https://shop.beta.example", "https://beta.example",
    "http://10.0.0.5:8080", "http://intranet", "https://printer.local", "https://8.8.8.8",
    "https://svc.internal/path", "https://gamma.example.org/login", "ftp://weird", "not a url",
    "https://[2001:db8::1]/", "https://host.docker.internal", "https://xn--bcher-kva.example",
]
METADATA = [
    {}, {"owner": "team-a"}, {"asset_owner": "  "}, {"owner": 5}, {"cohort": "lab"}, {"cohort": "development"},
    {"cohort": "nonsense"}, {"cohort": ""}, {"environment": "Production "}, {"environment": "staging"},
    {"environment": "test"}, {"environment": "qa"}, {"cohort": "demo", "owner": "x", "risk_tier": "high"},
    {"data_classification": "pii", "environment": "calibration"}, ["not", "an", "object"], {"cohort": True},
]
COMPLETION = [
    None, {"complete": True}, {"limited": True}, {"budget_exhausted": 1}, {"limited": 0}, {"limited": ""},
    {"limited": []}, {"limited": {"x": 1}}, {"limited": "no"}, {"budget_exhausted": 0.0, "complete": False},
    {"skipped_modules": ["zap"], "capped_lists": {"urls": 3}, "coverage_status": "partial"},
    "string-completion", [1, 2],
]
SCAN_STATUSES = ["completed", "completed", "failed", "running", "queued", "cancelled"]
SEVERITIES = ["critical", "high", "medium", "low", "info", "Critical", ""]
EVIDENCE = [
    None, {}, {"matcher": "x"}, {"proof_of_exploitation": True}, {"triage": {"suspected": True}},
    {"proof_state": "candidate"}, {"triage": '{"needs_verification": true}'},
]
UNDETERMINED = {"triage": '{"suspected": true, "score": NaN}'}
VERDICTS = [None, None, None, "exploited", "inconclusive", "likely_fixed", "false_positive", "not_vulnerable"]
ANALYST = [None, None, "needs_review", "retest_needed", "confirmed"]


def _unique_url(index: int) -> str:
    """The base URLs once, then each again on its own port (targets are unique per host and port)."""
    base = TARGET_URLS[index % len(TARGET_URLS)]
    if index < len(TARGET_URLS):
        return base
    parts = urlsplit(base)
    if not parts.hostname or parts.scheme not in ("http", "https"):
        return f"https://plain-{index}.example"
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return urlunsplit((parts.scheme, f"{host}:{8000 + index}", parts.path, "", ""))


async def seed(conn, *, targets: int = 70, ai_targets: int = 8, findings: int = 2500) -> dict:
    rng = random.Random(20261015)
    web_ids: list[uuid.UUID] = []
    for index in range(targets):
        model = index % 13 == 0
        url = f"hf://org/model-{index}" if model else _unique_url(index)
        root = rng.choice(["alpha.test", "beta.example", None, "internal"])
        total_scans = rng.choice([0, 0, 1, 3])
        last_scanned = rng.choice([None, _ago(2), _ago(45), _ago(10)])
        created = rng.choice([_ago(1), _ago(3), _ago(20), _ago(400)])
        target_id = await conn.fetchval(
            """INSERT INTO targets (url, name, root_domain, discovery_source, metadata_json, created_at, total_scans,
                                    last_scanned_at, last_grade, last_score, is_active)
               VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11) RETURNING id""",
            url, f"target {index}", root, "model-intake" if model else rng.choice(["manual", "asm", None]),
            json.dumps(METADATA[index % len(METADATA)]), created, total_scans, last_scanned,
            rng.choice([None, "A", "C"]), rng.choice([None, 71]), index % 17 != 5)
        web_ids.append(target_id)
        for scan_index in range(rng.choice([0, 1, 2, 3])):
            completion = rng.choice(COMPLETION)
            result = {"coverage_status": rng.choice(["complete", "partial", None])}
            if completion is not None:
                result["scan_completion_status"] = completion
            await conn.execute(
                """INSERT INTO scans (target_id, target_url, status, scan_type, created_at, completed_at, result, scan_role)
                   VALUES ($1, $2, $3, 'standard', $4, $5, $6::jsonb, $7)""",
                target_id, url, rng.choice(SCAN_STATUSES), _ago(60 - scan_index * 20 + rng.random()),
                rng.choice([None, _ago(40 - scan_index * 15)]), json.dumps(result),
                rng.choice(["primary", "primary", "shard"]))
    ai_ids: list[uuid.UUID] = []
    ai_metadata = [
        {}, {"environment": "production"}, {"tools": ["send_email", "wire_transfer", "a", "b"], "oauth_scopes": ["admin", "write"]},
        {"tool_inventory": ["x"] * 6, "per_tool_scopes": ["delete"] * 5, "delegated_identity": ["svc"],
         "memory_stores": ["m"], "data_classification": "restricted", "risk_tier": "critical"},
        {"owner": "ai-team", "cohort": "staging"}, {"environment": " PRODUCTION"},
    ]
    for index in range(ai_targets):
        ai_id = await conn.fetchval(
            """INSERT INTO ai_targets (name, endpoint_url, target_type, production_mode, metadata_json, created_at,
                                       last_scanned_at, is_active)
               VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8) RETURNING id""",
            rng.choice([f"bot {index}", ""]), ["https://chat.alpha.test/v1", "http://localhost:11434/api",
                                           "https://bot.beta.example/chat"][index % 3] + f"/{index}",
            rng.choice(["api_chat", "agent_trace", "widget"]), rng.choice([True, False, None]),
            json.dumps(ai_metadata[index % len(ai_metadata)]), rng.choice([_ago(2), _ago(30)]),
            rng.choice([None, _ago(5), _ago(50)]), index != 3)
        ai_ids.append(ai_id)
        for scan_index in range(rng.choice([0, 1, 2])):
            await conn.execute(
                """INSERT INTO scans (ai_target_id, target_url, status, scan_type, created_at, completed_at, result)
                   VALUES ($1, 'https://chat', $2, 'ai_gate', $3, $4, $5::jsonb)""",
                ai_id, rng.choice(SCAN_STATUSES), _ago(20 - scan_index * 5), rng.choice([None, _ago(3)]),
                json.dumps({"scan_completion_status": rng.choice(COMPLETION)}))
    for index in range(findings):
        owner = rng.random()
        target_id = rng.choice(web_ids) if owner < 0.8 else (rng.choice(web_ids) if owner < 0.85 else None)
        ai_id = rng.choice(ai_ids) if owner >= 0.8 else None
        evidence = UNDETERMINED if index % 211 == 0 else rng.choice(EVIDENCE)
        finding_id = await conn.fetchval(
            """INSERT INTO findings (target_id, ai_target_id, fingerprint, title, severity, tool, url, evidence, status,
                                     source, last_verification_verdict, analyst_verdict, first_seen_at, last_seen_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'https://x.test/p', $7::jsonb, $8, 'scan', $9, $10, $11, $11)
               RETURNING id""",
            target_id, ai_id, f"fp-{index}", f"finding {index}", rng.choice(SEVERITIES),
            rng.choice(["nuclei", "bola", "autonomous_workflow"]), None if evidence is None else json.dumps(evidence),
            rng.choice(["active", "active", "active", "resolved", "false_positive"]), rng.choice(VERDICTS),
            rng.choice(ANALYST), _ago(rng.randint(0, 90)))
        if rng.random() < 0.1:
            verdict, mode = rng.choice([("exploited", "deterministic"), ("exploited", "ai_driven"),
                                        ("likely_fixed", "deterministic")])
            await conn.execute(
                "INSERT INTO finding_verifications (finding_id, verdict, verification_mode, finding_type, target_url)"
                " VALUES ($1, $2, $3, 'xss', 'https://app.alpha.test')", finding_id, verdict, mode)
    # Assets that need no action: scanned recently and completely, nothing critical or high.
    for index in range(3):
        clean = await conn.fetchval(
            """INSERT INTO targets (url, name, root_domain, discovery_source, metadata_json, created_at, total_scans,
                                    last_scanned_at) VALUES ($1, 'clean', 'alpha.test', 'manual', '{}', $2, 2, $2)
               RETURNING id""", f"https://clean-{index}.alpha.test", _ago(90))
        await conn.execute(
            """INSERT INTO scans (target_id, target_url, status, scan_type, created_at, completed_at, result)
               VALUES ($1, 'https://clean', 'completed', 'standard', $2, $2, '{"scan_completion_status": {"complete": true}}')""",
            clean, _ago(index + 1))
        await conn.execute(
            """INSERT INTO findings (target_id, fingerprint, title, severity, status, source)
               VALUES ($1, $2, 'low one', 'low', 'active', 'scan')""", clean, f"clean-{index}")
    for index in range(40):
        await conn.execute(
            """INSERT INTO investigation_candidates (plane, family, title, claim, fingerprint, status, target_id)
               VALUES ('web', 'xss', 't', 'c', $1, $2, $3)""",
            f"cand-{index}", rng.choice(["new", "verifying", "verified", "refuted", "blocked", "inconclusive"]),
            rng.choice(web_ids[:20]))
    await conn.execute("ANALYZE")
    return {"web": web_ids, "ai": ai_ids}


# --- harness ----------------------------------------------------------------------------------

_SCHEMA_READY = False


def run(scenario, *, data=True, **seed_options):
    dsn = require_disposable_database(DSN or "", "shakerscan_exposure_assets_test")

    async def go():
        global _SCHEMA_READY
        conn = await asyncpg.connect(dsn)
        try:
            if not _SCHEMA_READY:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
                await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
                from retest_contract import run_schema_migrations
                pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
                try:
                    await run_schema_migrations(pool)
                    assert await loop_scale_indexes.ensure_loop_scale_indexes(pool)
                finally:
                    await pool.close()
                _SCHEMA_READY = True
            await conn.execute("TRUNCATE findings, finding_verifications, scans, targets, ai_targets,"
                               " investigation_candidates CASCADE")
            ids = await seed(conn, **seed_options) if data else {}
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
            try:
                return await scenario(conn, pool, ids)
            finally:
                await pool.close()
        finally:
            await conn.close()

    return asyncio.run(go())


class _Recording:
    """Pool and connection that note every query the route runs."""

    def __init__(self, pool):
        self.pool = pool
        self.queries: list[tuple[str, tuple]] = []

    @asynccontextmanager
    async def acquire(self):
        async with self.pool.acquire() as conn:
            yield _RecordingConn(conn, self.queries)


class _RecordingConn:
    def __init__(self, conn, queries):
        self._conn = conn
        self._queries = queries

    async def fetch(self, query, *args):
        self._queries.append((query, args))
        return await self._conn.fetch(query, *args)

    async def fetchval(self, query, *args):
        self._queries.append((query, args))
        return await self._conn.fetchval(query, *args)

    async def execute(self, query, *args):
        self._queries.append((query, args))
        return await self._conn.execute(query, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


async def assets(pool, monkeypatch, **params):
    recording = _Recording(pool)
    monkeypatch.setattr(exposure_router, "_pool", lambda: recording)
    return await exposure_router.exposure_assets(**params), recording.queries


def _comparable(body: dict) -> dict:
    """``scan_age_days`` follows the request's clock; everything else must match exactly."""
    copy = json.loads(json.dumps(body, default=str))
    return copy


LEGACY_CASES = [
    {},
    {"limit": 7},
    {"limit": 9, "offset": 5},
    {"offset": 500},
    {"kind": "web"}, {"kind": "model"}, {"kind": "ai"}, {"kind": "other"},
    {"cohort": "all"}, {"cohort": "operational"}, {"cohort": "non_operational"}, {"cohort": "lab"},
    {"cohort": "internal"}, {"cohort": "unclassified"}, {"cohort": "production"},
    {"root_domain": "alpha.test"}, {"root_domain": "beta.example", "kind": "ai"},
    {"root_domain": "nowhere.test"},
    {"cohort": "operational", "kind": "web", "limit": 4, "offset": 2},
]


def test_the_legacy_response_equals_the_previous_implementation(monkeypatch):
    async def scenario(conn, pool, ids):
        reasons_seen: set[str] = set()
        priorities: set = set()
        cohorts: set[str] = set()
        for case in LEGACY_CASES:
            params = {"root_domain": None, "kind": None, "cohort": None, "limit": 1000, "offset": 0, **case}
            expected = await reference_exposure_assets(pool, **params)
            actual, _ = await assets(pool, monkeypatch, **params)
            assert _comparable(actual) == _comparable(expected), case
            # The page is the previous ranking, row for row.
            assert [a["id"] for a in actual["assets"]] == [a["id"] for a in expected["assets"]], case
            for asset in actual["assets"]:
                reasons_seen.update(asset["action_reasons"])
                priorities.add(asset["action_priority"])
                cohorts.add(asset["cohort"])
        # The fixture exercises every branch the ranking has.
        assert reasons_seen >= {"never_scanned", "stale_scan", "failed_scan", "incomplete_scan", "critical_findings",
                                "high_findings", "public_high_risk", "production_ai_risk", "high_blast_radius"}
        assert priorities == {None, "P1", "P2", "P3"}
        assert cohorts >= {"internal", "unclassified", "lab", "production", "staging", "demo", "calibration"}
        full = await reference_exposure_assets(pool)
        metrics = full["metrics"]
        assert metrics["active_verified"] > 0 and metrics["investigator_suspected_assets"] > 0
        assert metrics["incomplete_scans"] > 0 and metrics["high_blast_ai_surfaces"] > 0
        assert full["new_count"] > 0 and metrics["fresh_scans"] > 0

    run(scenario)


def test_list_v1_walks_the_same_ranking_with_a_cursor(monkeypatch):
    async def scenario(conn, pool, ids):
        for case in ({}, {"cohort": "operational"}, {"kind": "web", "root_domain": "alpha.test"}):
            params = {"root_domain": None, "kind": None, "cohort": None, "limit": 1000, "offset": 0, **case}
            legacy = await reference_exposure_assets(pool, **params)
            walked, cursor, pages = [], None, 0
            while True:
                body, _ = await assets(pool, monkeypatch, **{**case, "limit": 6, "cursor": cursor,
                                                           "count": None if cursor else "exact"})
                pages += 1
                assert set(body) >= {"items", "next_cursor", "has_more", "total_kind", "generated_at", "summary"}
                assert body["summary"]["metrics"] == legacy["metrics"], case
                assert body["summary"]["cohort_counts"] == legacy["cohort_counts"]
                assert body["summary"]["new_count"] == legacy["new_count"]
                if cursor is None:
                    assert (body["total"], body["total_kind"]) == (legacy["total"], "exact")
                walked.extend(body["items"])
                cursor = body["next_cursor"]
                if not cursor:
                    assert not body["has_more"]
                    break
            assert pages > 1 or legacy["total"] <= 6
            expected = {item["id"]: item for item in legacy["assets"]}
            assert [item["id"] for item in walked] == [item["id"] for item in legacy["assets"]], case
            for item in walked:
                # Every legacy field, the same value; fields the asset kind lacks are null.
                legacy_item = _comparable(expected[item["id"]])
                item = _comparable(item)
                assert {key: item[key] for key in legacy_item} == legacy_item
                assert all(item[key] is None for key in set(item) - set(legacy_item))
        # Other sorts walk every asset once.
        for sort in ("-risk", "risk", "first_seen", "-first_seen", "priority"):
            seen, cursor = [], None
            while True:
                body, _ = await assets(pool, monkeypatch, limit=11, sort=sort, cursor=cursor, count="none",
                                       fields="id,risk_score,first_seen_at")
                assert all(set(item) == {"id", "risk_score", "first_seen_at"} for item in body["items"])
                seen.extend(item["id"] for item in body["items"])
                cursor = body["next_cursor"]
                if not cursor:
                    break
            assert len(seen) == len(set(seen)) == (await reference_exposure_assets(pool))["total"], sort
            if sort.lstrip("-") == "risk":
                body, _ = await assets(pool, monkeypatch, limit=200, sort=sort, count="none")
                scores = [item["risk_score"] for item in body["items"]]
                assert scores == sorted(scores, reverse=sort.startswith("-"))
        # A cursor is bound to its filters and sort.
        body, _ = await assets(pool, monkeypatch, limit=3, count="none")
        with pytest.raises(HTTPException) as refused:
            await assets(pool, monkeypatch, limit=3, cursor=body["next_cursor"], cohort="lab")
        assert refused.value.status_code == 400 and refused.value.detail["error"] == "cursor_mismatch"
        with pytest.raises(HTTPException) as too_big:
            await assets(pool, monkeypatch, limit=201, count="none")
        assert too_big.value.status_code == 422
        with pytest.raises(HTTPException) as legacy_sort:
            await assets(pool, monkeypatch, sort="-risk")
        assert legacy_sort.value.status_code == 400
        with pytest.raises(HTTPException) as since:
            await assets(pool, monkeypatch, since=NOW)
        assert since.value.status_code == 400

    run(scenario)


def test_facts_follow_edits_and_survive_a_racing_edit(monkeypatch):
    async def scenario(conn, pool, ids):
        body, _ = await assets(pool, monkeypatch, limit=2000)
        target = next(a for a in body["assets"] if a["kind"] == "web" and a["cohort"] == "unclassified")
        fresh = await conn.fetchval("SELECT count(*) FROM exposure_target_facts WHERE state = $1",
                                    asset_rank.FRESH_STATE)
        assert fresh == await conn.fetchval("SELECT count(*) FROM targets WHERE is_active")
        # A steady-state read recomputes nothing.
        _, queries = await assets(pool, monkeypatch, limit=5)
        assert not any(q.lstrip().startswith(("UPDATE exposure", "INSERT INTO exposure")) for q, _ in queries)
        # An edit marks the row stale in its own transaction; the next read recomputes it.
        await conn.execute("""UPDATE targets SET metadata_json = metadata_json || '{"cohort": "lab"}'::jsonb
                              WHERE id = $1""", uuid.UUID(target["id"]))
        assert (await conn.fetchval("SELECT state FROM exposure_target_facts WHERE target_id = $1",
                                    uuid.UUID(target["id"]))).startswith("stale:")
        body, _ = await assets(pool, monkeypatch, limit=2000)
        assert next(a for a in body["assets"] if a["id"] == target["id"])["cohort"] == "lab"
        # An unrelated column does not invalidate.
        await conn.execute("UPDATE targets SET last_grade = 'F' WHERE id = $1", uuid.UUID(target["id"]))
        assert await conn.fetchval("SELECT state FROM exposure_target_facts WHERE target_id = $1",
                                   uuid.UUID(target["id"])) == asset_rank.FRESH_STATE
        # A reader that read the old inputs never overwrites an edit that committed meanwhile.
        await conn.execute("UPDATE targets SET metadata_json = '{}'::jsonb WHERE id = $1", uuid.UUID(target["id"]))
        stale = await conn.fetchval("SELECT state FROM exposure_target_facts WHERE target_id = $1",
                                    uuid.UUID(target["id"]))

        class RacingConn:
            def __init__(self, inner):
                self.inner = inner

            async def fetch(self, query, *args):
                rows = await self.inner.fetch(query, *args)
                if query.lstrip().startswith("SELECT t.id, t.url"):
                    async with pool.acquire() as other:
                        await other.execute("""UPDATE targets SET metadata_json = '{"cohort": "demo"}'::jsonb
                                               WHERE id = $1""", uuid.UUID(target["id"]))
                return rows

            def __getattr__(self, name):
                return getattr(self.inner, name)

        async with pool.acquire() as inner:
            written = await asset_rank.refresh_facts(RacingConn(inner), include_ai=False, attempts=1)
        assert written == 0
        state = await conn.fetchval("SELECT state FROM exposure_target_facts WHERE target_id = $1",
                                    uuid.UUID(target["id"]))
        assert state.startswith("stale:") and state != stale
        body, _ = await assets(pool, monkeypatch, limit=2000)
        assert next(a for a in body["assets"] if a["id"] == target["id"])["cohort"] == "demo"
        # AI facts follow their own inputs.
        ai = next(a for a in body["assets"] if a["kind"] == "ai")
        await conn.execute("""UPDATE ai_targets SET metadata_json = '{"cohort": "calibration"}'::jsonb
                              WHERE id = $1""", uuid.UUID(ai["id"]))
        body, _ = await assets(pool, monkeypatch, limit=2000)
        assert next(a for a in body["assets"] if a["id"] == ai["id"])["cohort"] == "calibration"
        expected = await reference_exposure_assets(pool)
        assert _comparable(body) == _comparable(expected)
        # A deleted target takes its facts with it.
        await conn.execute("DELETE FROM targets WHERE id = $1", uuid.UUID(target["id"]))
        assert not await conn.fetchval("SELECT count(*) FROM exposure_target_facts WHERE target_id = $1",
                                       uuid.UUID(target["id"]))

    run(scenario)


def test_the_startup_install_is_a_catalog_only_no_op(monkeypatch):
    async def scenario(conn, pool, ids):
        statements: list[str] = []

        class Watch:
            async def fetchval(self, query, *args):
                statements.append(query)
                return await conn.fetchval(query, *args)

            async def fetch(self, query, *args):
                statements.append(query)
                return await conn.fetch(query, *args)

            async def execute(self, query, *args):
                statements.append(query)
                return await conn.execute(query, *args)

        await asset_rank.install_exposure_facts(Watch())
        assert statements and all(q.lstrip().upper().startswith("SELECT") for q in statements), statements
        # On a database without them, it creates exactly what a fresh install has.
        await conn.execute("DROP TABLE exposure_target_facts, exposure_ai_target_facts CASCADE")
        await conn.execute("DROP FUNCTION exposure_target_facts_stale_v1() CASCADE")
        await conn.execute("DROP FUNCTION exposure_ai_target_facts_stale_v1() CASCADE")
        await asset_rank.install_exposure_facts(conn)
        triggers = await conn.fetchval(
            "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'exposure_%_facts_stale_v1'")
        assert triggers == 2
        statements.clear()
        await asset_rank.install_exposure_facts(Watch())
        assert all(q.lstrip().upper().startswith("SELECT") for q in statements)

    run(scenario, data=False)


def _nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from _nodes(child)


def test_the_ranking_reads_findings_only_through_small_indexes(monkeypatch):
    async def scenario(conn, pool, ids):
        await conn.execute("""
            INSERT INTO findings (target_id, fingerprint, title, severity, status, evidence, last_seen_at, first_seen_at)
            SELECT $1, 'bulk-' || i, 'bulk ' || i, (ARRAY['critical','high','medium','low','info'])[1 + i % 5],
                   CASE WHEN i % 4 = 0 THEN 'resolved' ELSE 'active' END, '{"matcher": "x"}'::jsonb, now(), now()
            FROM generate_series(1, 30000) AS i""", ids["web"][0])
        await conn.execute("VACUUM ANALYZE findings")
        expected = await reference_exposure_assets(pool, limit=50)
        body, queries = await assets(pool, monkeypatch, limit=50)
        assert _comparable(body) == _comparable(expected)
        ranking, args = next((q, a) for q, a in queries if q.lstrip().startswith("WITH") and "ranked" in q)
        async with conn.transaction():
            await conn.execute("SET LOCAL jit = off")
            plan = json.loads(await conn.fetchval(f"EXPLAIN (ANALYZE, FORMAT JSON) {ranking}", *args))[0]["Plan"]
        reads = [node for node in _nodes(plan) if node.get("Relation Name") == "findings"]
        assert reads and not any("Seq Scan" in node["Node Type"] for node in reads), [n["Node Type"] for n in reads]
        # The 30,000 bulk rows are counted from the summary, never read.
        assert max(node["Actual Rows"] * node.get("Actual Loops", 1) for node in reads) < 3000

    run(scenario)


def test_list_contract_keyset_select_matches_select_list():
    spec = asset_rank.ASSETS_LIST
    plan = spec.plan(list_contract.Page(limit=5, sort="-priority"))
    assert plan.keyset_select in plan.select_list
    assert plan.keyset_select.count(" AS ") == 4



def test_a_cold_inventory_is_refreshed_in_bounded_batches_without_omitting_assets(monkeypatch):
    monkeypatch.setattr(asset_rank, "FACTS_BATCH", 7)

    async def scenario(conn, pool, ids):
        sizes = []

        class MeasuredConn:
            def __init__(self, inner):
                self.inner = inner

            async def fetch(self, query, *args):
                rows = await self.inner.fetch(query, *args)
                if query.lstrip().startswith("SELECT t.id, t.url"):
                    sizes.append(len(rows))
                return rows

            def __getattr__(self, name):
                return getattr(self.inner, name)

        # Asset creation also creates canonical host rows; count the current inventory.
        expected = await conn.fetchval("SELECT count(*) FROM targets WHERE is_active")
        written = await asset_rank.refresh_facts(MeasuredConn(conn), include_ai=False)
        assert written == expected
        assert len(sizes) > 1 and max(sizes) <= 7
        assert await conn.fetchval("SELECT count(*) FROM exposure_target_facts WHERE state=$1",
                                   asset_rank.FRESH_STATE) == expected
        body, _ = await assets(pool, monkeypatch, limit=2000)
        reference = await reference_exposure_assets(pool)
        assert _comparable(body) == _comparable(reference)
        assert await asset_rank.refresh_facts(conn, include_ai=False) == 0

    run(scenario, targets=17, ai_targets=0, findings=0)
