"""Bounded findings and exposure lists on real PostgreSQL: same answers as before, bounded work.

Only FINDINGS_LIST_TEST_DATABASE_URL on localhost/shakerscan_findings_list_test is permitted. Its
public schema is RESET, db/init.sql is loaded and the engine's startup migrations run, so these
tests use the real schema, triggers and indexes.

* The limit/offset shape of GET /findings answers exactly what the previous implementation (its
  SQL is kept below as the reference: COUNT(*) OVER(), a LATERAL per row, CASE severity order,
  proof projected per row) answered, for a matrix of filters, sorts and pages.
* The list contract (cursor/sort/fields/count) walks every row once in a stable order, also while
  rows are inserted, and refuses a cursor from other filters.
* GET /exposure/assets and /exposure/changes count what the previous implementation counted.
* EXPLAIN ANALYZE shows the page query reading at most a page of rows from an index (no Sort), and
  the verified filter reading the partial index: a regression to unbounded work fails here.
* The upgrade migration backfills severity_rank in batches without touching updated_at, rebuilds
  an interrupted index and ends with the definitions a fresh install has.
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
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("FINDINGS_LIST_TEST_DATABASE_URL")
REQUIRED = os.environ.get("FINDINGS_LIST_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable findings-list PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import HTTPException  # noqa: E402

import exposure.router as exposure_router  # noqa: E402
from exposure.proof_rollup import active_finding_proof_counts  # noqa: E402
import finding_routes.router as findings_router  # noqa: E402
from finding_routes import list_query, list_schema  # noqa: E402
import list_contract  # noqa: E402
from runtime import loop_scale_indexes  # noqa: E402

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
DETAIL = set(findings_router._FINDING_DETAIL_ONLY_FIELDS)


def _ids(seed: int, count: int) -> list[uuid.UUID]:
    rng = random.Random(seed)
    return [uuid.UUID(int=rng.getrandbits(128), version=4) for _ in range(count)]


WEB = _ids(1, 4)          # three web targets and one model artifact
AI = _ids(2, 1)[0]
SCANS = _ids(3, 3)

# --- the previous implementation, kept as the reference ---------------------------------------

OLD_SELECT = """
    SELECT f.*,
           COALESCE(t.url, ait.endpoint_url, dt.primary_locator) as target_url,
           COALESCE(t.name, ait.name, dt.name) as target_name,
           t.root_domain,
           ait.endpoint_url as ai_target_url,
           ait.name as ai_target_name,
           latest_retest.status AS latest_retest_status,
           latest_retest.result_status AS latest_retest_result_status,
           COALESCE(latest_retest.verdict, f.last_verification_verdict) AS latest_retest_verdict,
           COALESCE(latest_retest.confidence, f.last_verification_confidence) AS latest_retest_confidence,
           COALESCE(latest_retest.completed_at, f.last_verified_at) AS latest_retest_completed_at,
           CASE WHEN latest_retest.verdict IS NOT NULL THEN latest_retest.verification_mode END AS latest_retest_mode,
           COUNT(*) OVER() AS total_count
    FROM findings f
    LEFT JOIN targets t ON f.target_id = t.id
    LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
    LEFT JOIN device_targets dt ON f.device_target_id = dt.id
    LEFT JOIN LATERAL (
        SELECT status, result_status, verdict, confidence, completed_at, verification_mode
        FROM finding_verifications WHERE finding_id=f.id ORDER BY created_at DESC, id DESC LIMIT 1
    ) latest_retest ON TRUE
    WHERE 1=1"""

OLD_SOURCE_TYPES = {
    "ai": " AND (f.source IN ('ai_gate', 'ai_session', 'autonomous') OR f.ai_target_id IS NOT NULL)",
    "manual": " AND f.source = 'manual'",
    "dast": (" AND COALESCE(f.source, 'scan') NOT IN "
             "('ai_gate', 'ai_session', 'autonomous', 'deep_hunt', 'model_intake', 'asm', 'manual', 'device')"
             " AND f.ai_target_id IS NULL"
             " AND COALESCE(f.tool, '') NOT IN ('model_intake', 'autonomous_workflow')"
             " AND COALESCE(f.evidence->'research'->>'driven_by', '') <> 'autonomous_research'"),
}


def _old_host_in_domain(column: str, param: str) -> str:
    host = f"substring(LOWER({column}) from '^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)')"
    return f"({host} = LOWER({param}) OR right({host}, length({param}) + 1) = '.' || LOWER({param}))"


def old_query(**filters) -> tuple[str, list]:
    """The previous route's SQL for the filters it is compared on (without the proof filter)."""
    query, params = OLD_SELECT, []

    def add(value):
        params.append(value)
        return f"${len(params)}"

    if filters.get("severity"):
        query += f" AND f.severity = ANY({add(filters['severity'].split(','))}::text[])"
    if filters.get("status"):
        query += f" AND f.status = {add(filters['status'])}"
    query += OLD_SOURCE_TYPES.get(filters.get("source_type"), "")
    for name in ("target_id", "ai_target_id", "scan_id"):
        if filters.get(name):
            query += f" AND f.{name} = {add(uuid.UUID(filters[name]))}"
    if filters.get("root_domain"):
        p = add(filters["root_domain"])
        query += (f" AND (t.root_domain = {p} OR {_old_host_in_domain('ait.endpoint_url', p)}"
                  f" OR {_old_host_in_domain('dt.primary_locator', p)})")
    if filters.get("verification_verdict"):
        query += f" AND f.last_verification_verdict = {add(filters['verification_verdict'])}"
    if filters.get("search"):
        p = add(f"%{filters['search']}%")
        query += (f" AND (f.title ILIKE {p} OR f.url ILIKE {p} OR t.url ILIKE {p} OR t.name ILIKE {p}"
                  f" OR ait.endpoint_url ILIKE {p} OR ait.name ILIKE {p} OR dt.name ILIKE {p}"
                  f" OR dt.primary_locator ILIKE {p})")
    if filters.get("seen_within_days"):
        query += f" AND f.last_seen_at >= NOW() - INTERVAL '1 day' * {add(filters['seen_within_days'])}"
    return query, params


def old_order(sort_by, sort_order) -> str:
    direction = "DESC" if sort_order == "desc" else "ASC"
    if sort_by == "first_seen":
        return f"f.first_seen_at {direction} NULLS LAST"
    if sort_by == "last_seen":
        return f"f.last_seen_at {direction} NULLS LAST"
    if sort_by == "cvss":
        return f"f.cvss_score {direction} NULLS LAST"
    severity_direction = "ASC" if sort_order == "desc" else "DESC"
    return ("CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3"
            f" WHEN 'low' THEN 4 ELSE 5 END {severity_direction}, f.last_seen_at DESC NULLS LAST")


async def old_list(conn, *, proof_state=None, sort_by=None, sort_order="desc", limit=100, offset=0,
                   **filters) -> tuple[list[dict], int]:
    """The previous response's rows and total (proof projected per row, as it did)."""
    query, params = old_query(**filters)
    rows = await conn.fetch(f"{query} ORDER BY {old_order(sort_by, sort_order)}", *params)
    items = []
    for row in rows:
        item = dict(row)
        item.pop("total_count")
        item.pop("severity_rank")
        item.update(findings_router.finding_proof_fields(dict(item)))
        if proof_state and item["proof_state"] not in proof_state.split(","):
            continue
        for key in DETAIL:
            item.pop(key, None)
        items.append(item)
    return items[offset:offset + limit], len(items)


# --- the dataset ------------------------------------------------------------------------------

EVIDENCE = [
    None, {}, {"matcher": "x"}, {"proof_of_exploitation": True}, {"triage": {"suspected": True}},
    {"proof_state": "candidate"}, {"triage": '{"needs_verification": true}'},
    {"research": {"driven_by": "autonomous_research"}}, {"executed": "yes"},
]
UNDETERMINED = {"triage": '{"suspected": true, "score": NaN}'}
SEVERITIES = ["critical", "high", "medium", "low", "info", "Critical", "weird"]


async def seed(conn, *, rows: int = 640, undetermined: int = 4) -> None:
    rng = random.Random(20261014)
    await conn.execute("""
        INSERT INTO targets (id, url, name, root_domain, discovery_source, metadata_json, created_at, total_scans,
                             last_scanned_at)
        VALUES ($1, 'https://app.alpha.test', 'alpha app', 'alpha.test', 'manual', '{"owner": "a"}', $5, 2, $5),
               ($2, 'https://api.alpha.test', 'alpha api', 'alpha.test', 'manual', '{"cohort": "lab"}', $5, 0, NULL),
               ($3, 'https://shop.beta.test', 'beta shop', 'beta.test', 'manual', '{}', $5, 1, $5),
               ($4, 'hf://org/model', 'model', 'huggingface.co', 'model-intake', '{}', $5, 0, NULL)""",
        *WEB, T0)
    await conn.execute(
        "INSERT INTO ai_targets (id, name, endpoint_url, created_at) VALUES ($1, 'alpha bot', "
        "'https://chat.alpha.test/v1', $2)", AI, T0)
    device = await conn.fetchval(
        "INSERT INTO device_targets (name, primary_locator) VALUES ('lab-router', 'router.alpha.test') RETURNING id")
    for scan_id, target in zip(SCANS, WEB):
        await conn.execute(
            "INSERT INTO scans (id, target_id, target_url, status, scan_type, created_at, completed_at, result)"
            " VALUES ($1, $2, 'https://x.test', 'completed', 'standard', $3, $3, $4::jsonb)",
            scan_id, target, T0, json.dumps({"scan_completion_status": {"complete": True}}))
    seen = rng.sample(range(rows * 3), rows)
    first = rng.sample(range(rows * 3), rows)
    for index in range(rows):
        owner = rng.choice(["t0", "t0", "t1", "t2", "t3", "ai", "device"])
        target_id = WEB[int(owner[1])] if owner.startswith("t") else None
        evidence = UNDETERMINED if index < undetermined else rng.choice(EVIDENCE)
        finding_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO findings (id, scan_id, target_id, ai_target_id, device_target_id, fingerprint, title,
                                     severity, cvss_score, tool, url, evidence, status, source,
                                     last_verification_verdict, analyst_verdict, first_seen_at, last_seen_at,
                                     description, request, response)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14, $15, $16, $17, $18,
                       'body', 'GET /', 'HTTP/1.1 200')""",
            finding_id, SCANS[int(owner[1])] if owner in ("t0", "t1", "t2") else None,
            target_id, AI if owner == "ai" else None, device if owner == "device" else None,
            f"fp-{index}", f"finding {index} {rng.choice(['sqli', 'xss', 'cors'])}", rng.choice(SEVERITIES),
            rng.choice([None, 9.8, 7.5, 5.0, 3.1]), rng.choice(["nuclei", "bola", "autonomous_workflow"]),
            f"https://app.alpha.test/p/{index}", None if evidence is None else json.dumps(evidence),
            rng.choice(["active", "active", "active", "resolved", "false_positive"]),
            rng.choice(["scan", "scan", "manual", "ai_gate", "asm"]),
            rng.choice([None, None, "exploited", "inconclusive", "likely_fixed", "EXPLOITED"]),
            rng.choice([None, None, "needs_review"]),
            T0 - timedelta(seconds=first[index]),
            # A NULL sighting sorts last (as before); one, so that no two rows tie.
            None if index == 10 else T0 + timedelta(seconds=seen[index]),
        )
        if rng.random() < 0.2:
            verdict, mode = rng.choice([("exploited", "deterministic"), ("exploited", "ai_driven"),
                                        ("likely_fixed", "deterministic")])
            await conn.execute(
                "INSERT INTO finding_verifications (finding_id, verdict, verification_mode, finding_type, target_url)"
                " VALUES ($1, $2, $3, 'xss', 'https://app.alpha.test')", finding_id, verdict, mode)
    await conn.execute("ANALYZE")


# --- harness ----------------------------------------------------------------------------------

_SCHEMA_READY = False


def run(scenario, *, data=True, **seed_options):
    dsn = require_disposable_database(DSN or "", "shakerscan_findings_list_test")

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
                    # The list indexes come from the API's background builder, after startup.
                    assert await loop_scale_indexes.ensure_loop_scale_indexes(pool)
                finally:
                    await pool.close()
                _SCHEMA_READY = True
            await conn.execute("TRUNCATE findings, finding_verifications, scans, targets, ai_targets,"
                               " investigation_candidates CASCADE")
            if data:
                await seed(conn, **seed_options)
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
            try:
                return await scenario(conn, pool)
            finally:
                await pool.close()
        finally:
            await conn.close()

    return asyncio.run(go())


class _Request:
    def __init__(self, **params):
        self.query_params = params


LEGACY_DEFAULTS = dict(
    severity=None, status=None, source_type=None, target_id=None, ai_target_id=None, device_target_id=None,
    scan_id=None, hunt_id=None, root_domain=None, verification_verdict=None, verification_mode=None,
    verified_only=False, proof_state=None, driven_by=None, research_campaign_id=None, search=None,
    seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None, resolved_within_days=None,
    sort_by=None, sort_order="desc", include_candidates=False, limit=100, offset=0, include_details=False,
)


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

    def __getattr__(self, name):
        return getattr(self._conn, name)


async def route(pool, monkeypatch, **params):
    """GET /findings in process, with only ``params`` on the query string."""
    recording = _Recording(pool)
    monkeypatch.setattr(findings_router, "_pool", lambda: recording)
    arguments = dict(LEGACY_DEFAULTS)
    arguments.update(params)
    query_string = {key: value for key, value in params.items() if value not in (None, False)}
    result = await findings_router.list_findings(_Request(**query_string), **arguments)
    return result, recording.queries


@pytest.fixture(autouse=True)
def _cursor_key():
    list_contract.configure_cursor_key(b"f" * 32)
    list_schema.reset_severity_rank_ready()
    yield
    list_contract.configure_cursor_key(None)
    list_schema.reset_severity_rank_ready()


def _comparable(items):
    return [{key: value for key, value in item.items()} for item in items]


# --- parity with the previous implementation ---------------------------------------------------

CASES = [
    {},
    {"status": "active"},
    {"severity": "critical,high"},
    {"severity": "info", "status": "resolved"},
    {"source_type": "ai"},
    {"source_type": "dast", "status": "active"},
    {"source_type": "manual"},
    {"target_id": str(WEB[0])},
    {"ai_target_id": str(AI)},
    {"scan_id": str(SCANS[1])},
    {"root_domain": "alpha.test"},
    {"root_domain": "beta.test", "status": "active"},
    {"search": "sqli"},
    {"search": "lab-router"},
    {"search": "alpha bot"},
    {"verification_verdict": "exploited"},
    {"seen_within_days": 3650},
]
SORTS = [(None, "desc"), (None, "asc"), ("last_seen", "desc"), ("last_seen", "asc"),
         ("first_seen", "desc"), ("first_seen", "asc")]


def test_the_legacy_shape_answers_exactly_what_the_previous_implementation_did(monkeypatch):
    async def scenario(conn, pool):
        checked = 0
        for filters in CASES:
            for sort_by, sort_order in SORTS:
                for limit, offset in ((100, 0), (37, 74), (500, 0), (20, 10_000)):
                    result, _ = await route(pool, monkeypatch, sort_by=sort_by, sort_order=sort_order,
                                            limit=limit, offset=offset, **filters)
                    expected, total = await old_list(conn, sort_by=sort_by, sort_order=sort_order,
                                                     limit=limit, offset=offset, **filters)
                    assert result["total"] == total, (filters, sort_by, sort_order, limit, offset)
                    assert _comparable(result["findings"]) == _comparable(expected), (filters, sort_by, offset)
                    checked += len(expected)
        assert checked > 20_000
        # include_details=true still returns the bodies (deprecated shape, same as before).
        detailed, _ = await route(pool, monkeypatch, include_details=True, limit=5)
        assert {"evidence", "request", "response", "description"} <= set(detailed["findings"][0])
        summary, _ = await route(pool, monkeypatch, limit=5)
        assert not DETAIL & set(summary["findings"][0]) and "severity_rank" not in summary["findings"][0]

    run(scenario)


def test_cvss_order_and_proof_filters_match_the_previous_implementation(monkeypatch):
    async def scenario(conn, pool):
        for sort_order in ("desc", "asc"):
            result, _ = await route(pool, monkeypatch, sort_by="cvss", sort_order=sort_order, limit=500)
            rest, _ = await route(pool, monkeypatch, sort_by="cvss", sort_order=sort_order, limit=500, offset=500)
            expected, total = await old_list(conn, sort_by="cvss", sort_order=sort_order, limit=1000)
            items = result["findings"] + rest["findings"]
            # Equal CVSS scores had no defined order before; the score sequence and the set did.
            assert [item["cvss_score"] for item in items] == [item["cvss_score"] for item in expected]
            assert {item["id"] for item in items} == {item["id"] for item in expected} and result["total"] == total
        # Proof filters, first with rows only Python can decide (the streamed path), then without.
        for phase in ("undetermined", "decided"):
            for proof_state in ("verified", "suspected", "unverified", "verified,suspected"):
                for filters in ({}, {"status": "active"}, {"root_domain": "alpha.test"}):
                    for limit, offset in ((50, 0), (25, 40)):
                        result, queries = await route(pool, monkeypatch, proof_state=proof_state, limit=limit,
                                                      offset=offset, **filters)
                        expected, total = await old_list(conn, proof_state=proof_state, limit=limit,
                                                         offset=offset, **filters)
                        assert result["total"] == total and total > 0, (phase, proof_state, filters)
                        assert _comparable(result["findings"]) == _comparable(expected), (phase, proof_state)
            await conn.execute("DELETE FROM findings WHERE evidence -> 'triage' = $1::jsonb",
                               json.dumps(UNDETERMINED["triage"]))

    run(scenario)


# --- the list contract -------------------------------------------------------------------------

V1_SORTS = {
    "severity": ("(CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3"
                 " WHEN 'low' THEN 2 ELSE 1 END)", "COALESCE(f.last_seen_at, 'epoch'::timestamptz)"),
    "last_seen": ("COALESCE(f.last_seen_at, 'epoch'::timestamptz)",),
    "first_seen": ("COALESCE(f.first_seen_at, 'epoch'::timestamptz)",),
    "cvss": ("COALESCE(f.cvss_score, -1)",),
}


async def walk(pool, monkeypatch, *, limit, between=None, **params) -> list[dict]:
    items, cursor, pages = [], None, 0
    while True:
        page, _ = await route(pool, monkeypatch, limit=limit, **({"cursor": cursor} if cursor else {}), **params)
        assert set(page) >= {"items", "next_cursor", "has_more", "total_kind", "generated_at"}
        assert len(page["items"]) <= limit
        items += page["items"]
        pages += 1
        if between:
            await between(pages)
        if not page["has_more"]:
            assert page["next_cursor"] is None
            return items
        cursor = page["next_cursor"]


def test_cursor_walks_return_every_row_once_in_the_declared_order(monkeypatch):
    async def scenario(conn, pool):
        for filters in ({}, {"status": "active"}, {"root_domain": "alpha.test"}, {"search": "xss"},
                        {"severity": "critical,high"}):
            query, params = old_query(**filters)
            body = query.split("FROM findings f", 1)[1]
            for name, keys in V1_SORTS.items():
                for descending in (True, False):
                    direction = "DESC" if descending else "ASC"
                    order = ", ".join(f"{key} {direction}" for key in (*keys, "f.id"))
                    expected = [row["id"] for row in await conn.fetch(
                        f"SELECT f.id FROM findings f {body} ORDER BY {order}", *params)]
                    sort = ("-" if descending else "") + name
                    items = await walk(pool, monkeypatch, limit=37, sort=sort, count="exact", **filters)
                    assert [item["id"] for item in items] == expected, (filters, sort)
        # Summary rows only; the proof answers like the detail view.
        items = await walk(pool, monkeypatch, limit=200, sort="-severity")
        assert not ({"evidence", "request", "response", "description", "severity_rank"} & set(items[0]))
        by_id = {row["id"]: dict(row) for row in await conn.fetch(OLD_SELECT)}
        for item in items:
            proof = findings_router.finding_proof_fields(by_id[item["id"]])
            assert (item["proof_state"], item["is_verified"], item["is_suspected"]) == (
                proof["proof_state"], proof["is_verified"], proof["is_suspected"])

    run(scenario)


def test_a_cursor_walk_stays_exact_while_rows_arrive(monkeypatch):
    async def scenario(conn, pool):
        before = {row["id"] for row in await conn.fetch("SELECT id FROM findings")}

        async def insert(page):
            # New sightings at both ends of the order arrive between pages.
            for severity, offset in (("critical", 10_000), ("info", -10_000)):
                await conn.execute(
                    "INSERT INTO findings (target_id, fingerprint, title, severity, status, last_seen_at)"
                    " VALUES ($1, $2, 'arrived', $3, 'active', $4)",
                    WEB[0], f"late-{page}-{severity}", severity, T0 + timedelta(seconds=offset))

        items = await walk(pool, monkeypatch, limit=25, sort="-severity", between=insert)
        ids = [item["id"] for item in items]
        assert len(ids) == len(set(ids))
        assert before <= set(ids)

    run(scenario)


def test_the_list_contract_refuses_what_it_does_not_declare(monkeypatch):
    async def scenario(conn, pool):
        first, _ = await route(pool, monkeypatch, limit=10, status="active", sort="-last_seen")
        with pytest.raises(HTTPException) as mismatch:
            await route(pool, monkeypatch, limit=10, status="resolved", sort="-last_seen",
                        cursor=first["next_cursor"])
        assert mismatch.value.status_code == 400 and mismatch.value.detail["error"] == "cursor_mismatch"
        for params, status in (({"fields": "id,evidence"}, 400), ({"sort": "-title"}, 400),
                               ({"count": "exact", "offset": 10}, 400), ({"sort": "-cvss", "include_details": True}, 400),
                               ({"count": "none", "limit": 300}, 422)):
            with pytest.raises(HTTPException) as refused:
                await route(pool, monkeypatch, **params)
            assert refused.value.status_code == status, params
        narrow, _ = await route(pool, monkeypatch, fields="id,title,proof_state", count="exact", limit=5)
        assert all(set(item) == {"id", "title", "proof_state"} for item in narrow["items"])
        assert narrow["total_kind"] == "exact" and narrow["total"] == await conn.fetchval("SELECT count(*) FROM findings")
        estimate, _ = await route(pool, monkeypatch, count="estimate", status="active")
        assert estimate["total_kind"] == "estimate" and isinstance(estimate["total"], int)
        # A proof filter with an undetermined row: Python decides it, the page is still exact.
        suspected = await walk(pool, monkeypatch, limit=7, proof_state="suspected", sort="-severity")
        expected, total = await old_list(conn, proof_state="suspected", limit=10_000)
        assert {item["id"] for item in suspected} == {item["id"] for item in expected}
        counted, _ = await route(pool, monkeypatch, proof_state="suspected", count="exact")
        assert counted["total"] == total
        # Too many undetermined rows under one filter: a 422 the caller acts on, not a retryable 503.
        monkeypatch.setattr(list_query, "UNDETERMINED_LIMIT", 1)
        for params in ({"proof_state": "suspected"}, {"proof_state": "suspected", "count": "exact"}):
            with pytest.raises(HTTPException) as broad:
                await route(pool, monkeypatch, **params)
            assert broad.value.status_code == 422
            assert broad.value.detail["error"] == "proof_filter_too_broad", params

    run(scenario)


# --- exposure ---------------------------------------------------------------------------------

def test_exposure_counts_match_the_previous_rollup(monkeypatch):
    async def scenario(conn, pool):
        recording = _Recording(pool)
        monkeypatch.setattr(exposure_router, "_pool", lambda: recording)
        result = await exposure_router.exposure_assets(root_domain=None, kind=None, cohort=None, limit=1000, offset=0)
        # The previous rollup: every active finding row, proof projected in Python.
        rows = await conn.fetch(
            """SELECT f.*, CASE WHEN latest_retest.verdict IS NOT NULL THEN latest_retest.verification_mode END
                   AS latest_retest_mode
               FROM findings f LEFT JOIN LATERAL (
                   SELECT verdict, verification_mode FROM finding_verifications
                   WHERE finding_id=f.id ORDER BY created_at DESC, id DESC LIMIT 1) latest_retest ON TRUE
               WHERE f.status='active'""")
        proof = active_finding_proof_counts(rows)
        totals = {}
        for column, kind in (("target_id", "target"), ("ai_target_id", "ai")):
            for row in await conn.fetch(
                f"""SELECT {column} AS asset, count(*) AS total,
                           count(*) FILTER (WHERE severity = 'critical') AS critical,
                           count(*) FILTER (WHERE severity = 'high') AS high
                    FROM findings WHERE status = 'active' AND {column} IS NOT NULL GROUP BY {column}"""):
                totals[(kind, str(row["asset"]))] = (row["total"], row["critical"], row["high"])
        assets = {asset["id"]: asset for asset in result["assets"]}
        assert set(assets) >= {str(WEB[0]), str(WEB[1]), str(WEB[2]), str(WEB[3]), str(AI)}
        verified_seen = 0
        for asset_id, asset in assets.items():
            kind = "ai" if asset["kind"] == "ai" else "target"
            expected = proof.get((kind, asset_id), {})
            assert asset["active_verified"] == expected.get("verified", 0), asset_id
            assert asset["active_needs_verification"] == (
                expected.get("needs_verification", 0) + asset.get("investigator_suspected_count", 0)), asset_id
            if kind == "target":
                assert asset["investigator_verified_count"] == expected.get("investigator_verified", 0)
            assert (asset["active_total"], asset["active_critical"], asset["active_high"]) == totals.get(
                (kind, asset_id), (0, 0, 0)), asset_id
            verified_seen += asset["active_verified"]
        assert verified_seen > 5
        # Summary columns only: no finding row, evidence or full metadata reaches the API.
        for query, _ in recording.queries:
            assert "f.*" not in query
        kinds = await exposure_router.exposure_assets(root_domain=None, kind="model", cohort=None, limit=10, offset=0)
        assert [asset["id"] for asset in kinds["assets"]] == [str(WEB[3])]

    run(scenario)


def test_exposure_changes_count_every_row_and_return_the_newest_examples(monkeypatch):
    async def scenario(conn, pool):
        monkeypatch.setattr(exposure_router, "_pool", lambda: pool)
        await conn.execute("UPDATE findings SET first_seen_at = NOW() - (random() * INTERVAL '6 days')")
        await conn.execute("UPDATE findings SET resolved_at = NOW() - INTERVAL '1 day' WHERE status = 'resolved'")
        for root_domain in (None, "alpha.test"):
            changes = await exposure_router.exposure_changes(since=None, root_domain=root_domain, days=7, examples=3)
            categories = {item["key"]: item for item in changes["categories"]}
            scope = ("" if root_domain is None else
                     " AND (t.root_domain = $1 OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1) || '%')")
            args = [] if root_domain is None else [root_domain]
            for key, where, order in (
                ("new_critical", "f.status = 'active' AND f.severity = 'critical' AND f.first_seen_at > NOW() - INTERVAL '7 days'", "f.first_seen_at"),
                ("new_high", "f.status = 'active' AND f.severity = 'high' AND f.first_seen_at > NOW() - INTERVAL '7 days'", "f.first_seen_at"),
                ("resolved", "f.status = 'resolved' AND f.resolved_at > NOW() - INTERVAL '7 days'", "f.resolved_at"),
            ):
                rows = await conn.fetch(
                    f"SELECT f.title FROM findings f LEFT JOIN targets t ON f.target_id = t.id"
                    f" LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id WHERE {where}{scope}"
                    f" ORDER BY {order} DESC", *args)
                assert categories[key]["count"] == len(rows) and len(rows) > 3, (key, root_domain)
                assert [example["label"] for example in categories[key]["examples"]] == [row["title"] for row in rows[:3]]

    run(scenario)


# --- bounded work --------------------------------------------------------------------------------

def _nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from _nodes(child)


async def _explain(conn, query, args):
    async with conn.transaction():
        await conn.execute("SET LOCAL jit = off")
        raw = await conn.fetchval(f"EXPLAIN (ANALYZE, FORMAT JSON) {query}", *args)
    return json.loads(raw)[0]["Plan"]


def test_a_page_reads_a_page_of_rows_from_an_index(monkeypatch):
    async def scenario(conn, pool):
        await conn.execute("""
            INSERT INTO findings (target_id, fingerprint, title, severity, status, evidence, last_seen_at, first_seen_at)
            SELECT $1, 'bulk-' || i, 'bulk ' || i, (ARRAY['critical','high','medium','low','info'])[1 + i % 5],
                   CASE WHEN i % 4 = 0 THEN 'resolved' ELSE 'active' END, '{"matcher": "x"}'::jsonb,
                   $2::timestamptz - (i || ' seconds')::interval, $2::timestamptz - (i || ' minutes')::interval
            FROM generate_series(1, 30000) AS i""", WEB[0], T0)
        await conn.execute("VACUUM ANALYZE findings")
        cases = [
            ({"limit": 50}, "legacy default"),
            ({"limit": 50, "sort_by": "last_seen"}, "legacy last seen"),
            ({"limit": 50, "status": "active"}, "legacy active"),
            ({"limit": 50, "sort": "-severity"}, "v1 severity"),
            ({"limit": 50, "sort": "-first_seen", "status": "active"}, "v1 first seen"),
        ]
        for params, label in cases:
            _, queries = await route(pool, monkeypatch, **params)
            page_query, args = next((q, a) for q, a in queries if "SELECT f.id FROM findings f" in q)
            if label.startswith("v1"):
                page_query = "SELECT f.id FROM findings f" + page_query.split("SELECT f.id FROM findings f", 1)[1]
                page_query = page_query.rsplit(") page", 1)[0]
            plan = await _explain(conn, page_query, args)
            nodes = list(_nodes(plan))
            assert not any(node["Node Type"] in ("Sort", "Incremental Sort") for node in nodes), label
            scans = [node for node in nodes if node.get("Relation Name") == "findings"]
            assert scans and all("Index" in node["Node Type"] for node in scans), label
            assert max(node["Actual Rows"] for node in scans) <= 51 * 2, (label, scans[0]["Actual Rows"])
        # The verified filter reads the partial index of rows that could be proven, not every row.
        _, queries = await route(pool, monkeypatch, limit=50, proof_state="verified")
        page_query, args = next((q, a) for q, a in queries if q.startswith("SELECT f.id FROM findings f"))
        plan = await _explain(conn, page_query, args)
        scans = [node for node in _nodes(plan) if node.get("Relation Name") == "findings"]
        assert any(node.get("Index Name") == "idx_findings_proof_candidates" for node in _nodes(plan)), scans
        assert max(node["Actual Rows"] for node in scans) < 1000
        # Exposure: the proof is projected for candidate rows only, through their partial index.
        recording = _Recording(pool)
        monkeypatch.setattr(exposure_router, "_pool", lambda: recording)
        await exposure_router.exposure_assets(root_domain=None, kind=None, cohort=None, limit=10, offset=0)
        targets_query, targets_args = recording.queries[0]
        plan = await _explain(conn, targets_query, targets_args)
        assert any(node.get("Index Name") == "idx_findings_proof_candidates" for node in _nodes(plan))
        for node in _nodes(plan):
            if node.get("Relation Name") == "findings" and node.get("Index Name") != "idx_findings_proof_candidates":
                # Severity and needs-verification counts come from the covering index alone.
                assert node["Node Type"] == "Index Only Scan", node["Node Type"]

    run(scenario, undetermined=0)


# --- the upgrade migration -------------------------------------------------------------------------

LIST_INDEX_NAMES = [name for name, _table, _definition in list_schema.FINDINGS_SCALE_INDEXES]


async def _definitions(conn) -> dict[str, str]:
    rows = await conn.fetch(
        "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'findings' AND indexname = ANY($1::text[])",
        LIST_INDEX_NAMES)
    definitions = {row["indexname"]: row["indexdef"] for row in rows}
    definitions["findings_proof_gate_stats"] = await conn.fetchval(
        "SELECT pg_get_statisticsobjdef(oid) FROM pg_statistic_ext WHERE stxname = 'findings_proof_gate_stats'")
    definitions["finding_severity_rank"] = await conn.fetchval(
        "SELECT pg_get_functiondef('finding_severity_rank(text)'::regprocedure)")
    definitions["trg_finding_severity_rank"] = await conn.fetchval(
        "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname = 'trg_finding_severity_rank'")
    definitions["severity_rank column"] = await conn.fetchval(
        """SELECT format_type(a.atttypid, a.atttypmod) || ' notnull=' || a.attnotnull || ' default='
                  || pg_get_expr(d.adbin, d.adrelid)
           FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = 'findings'::regclass AND a.attname = 'severity_rank'""")
    return definitions


async def _back_to_2_10(conn) -> None:
    """A 2.10 database: no rank, no list indexes or statistics, the old timestamp trigger."""
    for name in LIST_INDEX_NAMES:
        await conn.execute(f"DROP INDEX IF EXISTS {name}")
    await conn.execute("DROP STATISTICS findings_proof_gate_stats")
    await conn.execute("DROP TRIGGER trg_finding_severity_rank ON findings")
    await conn.execute("ALTER TABLE findings DROP COLUMN severity_rank")
    await conn.execute("""CREATE OR REPLACE FUNCTION update_finding_timestamps() RETURNS TRIGGER AS $$
        BEGIN NEW.updated_at = NOW();
          IF NEW.status = 'resolved' AND OLD.status != 'resolved' THEN NEW.resolved_at = NOW(); END IF;
          RETURN NEW; END; $$ LANGUAGE plpgsql""")
    await conn.execute("DELETE FROM app_schema_migrations WHERE name = $1", list_schema.SEVERITY_RANK_MIGRATION)
    await conn.execute("ALTER TABLE findings DISABLE TRIGGER trigger_update_finding_timestamps")
    await conn.execute("UPDATE findings SET updated_at = $1", T0)
    await conn.execute("ALTER TABLE findings ENABLE TRIGGER trigger_update_finding_timestamps")


def test_the_upgrade_ranks_without_touching_updated_at_and_ends_like_a_fresh_install():
    async def scenario(conn, pool):
        fresh = await _definitions(conn)
        assert len(fresh) == len(LIST_INDEX_NAMES) + 4 and all(fresh.values())
        assert fresh["severity_rank column"] == "smallint notnull=true default=1"
        await _back_to_2_10(conn)
        # An interrupted concurrent build leaves an INVALID index under a list index's name.
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute("CREATE UNIQUE INDEX CONCURRENTLY idx_findings_scan_severity ON findings (severity)")

        # The startup schema (the column is added with its default: no rewrite, no NULLs) ...
        async with conn.transaction():
            for statement in list_schema.FINDINGS_LIST_SCHEMA_STATEMENTS:
                await conn.execute(statement)
        assert await conn.fetchval("SELECT count(*) FILTER (WHERE severity_rank = 1) FROM findings") == \
            await conn.fetchval("SELECT count(*) FROM findings")
        # ... the startup step under the lock ranks nothing (it kept a 500k database's API down for
        # a minute) and does not claim the rank complete ...
        expected = await conn.fetchval(
            "SELECT count(*) FROM findings WHERE finding_severity_rank(severity) <> 1")
        await list_schema.finish_findings_list_schema(conn)
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") == expected > 0
        assert not await conn.fetchval("SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name = $1)",
                                       list_schema.SEVERITY_RANK_MIGRATION)
        # ... the background task ranks after serving (small batches, updated_at untouched) and
        # then records the marker ...
        assert await list_schema.backfill_severity_rank(conn, batch=97) == expected
        assert await list_schema.repair_severity_rank(pool) == 0
        assert await conn.fetchval("SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name = $1)",
                                   list_schema.SEVERITY_RANK_MIGRATION)
        assert await conn.fetchval("SELECT count(*) FROM findings WHERE updated_at <> $1", T0) == 0
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") == 0
        # ... builds no index: the background builder does, and rebuilds the interrupted one.
        assert await conn.fetchval("SELECT to_regclass('idx_findings_severity_keyset')") is None
        built = await loop_scale_indexes.ensure_loop_scale_indexes(pool)
        assert set(LIST_INDEX_NAMES) <= set(built)
        assert await conn.fetchval("SELECT bool_and(indisvalid) FROM pg_index WHERE indrelid = 'findings'::regclass")
        assert await _definitions(conn) == fresh
        # Kept in step afterwards, and an ordinary update still stamps updated_at.
        changed = await conn.fetchval("SELECT id FROM findings WHERE severity = 'info' LIMIT 1")
        await conn.execute("UPDATE findings SET severity = 'critical' WHERE id = $1", changed)
        assert await conn.fetchval("SELECT (severity_rank, updated_at > $2) FROM findings WHERE id = $1",
                                   changed, T0) == (5, True)
        assert await conn.fetchval(
            "INSERT INTO findings (fingerprint, title, severity) VALUES ('new', 'new', 'high') RETURNING severity_rank") == 4
        # Idempotent: a second start changes nothing.
        await list_schema.finish_findings_list_schema(conn)
        assert await loop_scale_indexes.ensure_loop_scale_indexes(pool) == []
        assert await _definitions(conn) == fresh

    run(scenario)


async def _deadlocks(conn) -> int:
    await conn.execute("SELECT pg_stat_clear_snapshot()")
    return await conn.fetchval("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")


def test_api_and_worker_starting_together_on_a_2_10_database_do_not_deadlock():
    """Processes start together: while one upgrades under the startup lock, the others wait for it
    (each wait holds a snapshot). Nothing under that lock may wait for snapshots (a CONCURRENTLY
    index build does): PostgreSQL would break that cycle by killing a waiter with a deadlock."""
    async def scenario(conn, pool):
        await _back_to_2_10(conn)
        from retest_contract import run_schema_migrations
        dsn = require_disposable_database(DSN or "", "shakerscan_findings_list_test")
        pools = [await asyncpg.create_pool(dsn, min_size=1, max_size=2) for _ in range(3)]
        before = await _deadlocks(conn)
        try:
            await asyncio.wait_for(asyncio.gather(*(run_schema_migrations(p) for p in pools)), 120)
        finally:
            for p in pools:
                await p.close()
        await asyncio.sleep(1.5)  # backends flush their statistics when they go idle
        assert await _deadlocks(conn) == before
        # The startup ranked nothing; the API's background task does, once, under its try-lock.
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") > 0
        await asyncio.gather(*(list_schema.repair_severity_rank(pool) for _ in range(3)))
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") == 0
        assert await conn.fetchval("SELECT count(*) FROM findings WHERE updated_at <> $1", T0) == 0
        assert await loop_scale_indexes.ensure_loop_scale_indexes(pool)

    run(scenario)


def test_a_restart_during_concurrent_builds_on_every_builder_table_completes_without_deadlock():
    """The background builder is mid-CREATE INDEX CONCURRENTLY on findings, scans and every other
    table it builds on (stalled on an open snapshot, holding its lock), a process restarts and runs
    the startup migrations, and another process queues on the startup lock. Every statement the
    startup runs on an up-to-date database must be a catalog check that takes no lock the builds
    hold: the startup completes while the builds are still waiting, and nothing deadlocks."""
    async def scenario(conn, pool):
        from retest_contract import run_schema_migrations
        dsn = require_disposable_database(DSN or "", "shakerscan_findings_list_test")
        picks = {}
        for name, table, definition in loop_scale_indexes.LOOP_SCALE_INDEXES:
            if table not in picks and await conn.fetchval("SELECT to_regclass($1)", table):
                picks[table] = (name, definition)
        assert {"findings", "scans", "targets"} <= set(picks)
        for name, _definition in picks.values():
            await conn.execute(f"DROP INDEX IF EXISTS {name}")
        before = await _deadlocks(conn)
        holder = await asyncpg.connect(dsn)
        builders = []
        startup_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        waiter = await asyncpg.connect(dsn)
        try:
            # An open snapshot stalls every concurrent build after it has taken its table lock.
            await holder.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            await holder.fetchval("SELECT 1")
            for name, definition in picks.values():
                session = await asyncpg.connect(dsn)
                builders.append((session, asyncio.create_task(
                    session.execute(f"CREATE INDEX CONCURRENTLY {name} ON {definition}"))))
            await asyncio.sleep(1.0)
            assert not any(task.done() for _session, task in builders)
            startup = asyncio.create_task(run_schema_migrations(startup_pool))
            await asyncio.sleep(0.2)
            queued = asyncio.create_task(waiter.execute("SELECT pg_advisory_lock(8675309)"))
            await asyncio.wait_for(startup, 60)  # blocked behind a build, it would never finish
            assert not any(task.done() for _session, task in builders)
            await asyncio.wait_for(queued, 30)
            await waiter.execute("SELECT pg_advisory_unlock(8675309)")
            await holder.execute("ROLLBACK")
            for _session, task in builders:
                await asyncio.wait_for(task, 60)
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

    run(scenario)


def test_a_load_that_bypasses_the_trigger_succeeds_and_is_repaired():
    async def scenario(conn, pool):
        # A data-only restore of an older dump: no rank in the data, triggers disabled.
        await conn.execute("ALTER TABLE findings DISABLE TRIGGER USER")
        try:
            await conn.execute(
                "INSERT INTO findings (fingerprint, title, severity, updated_at)"
                " SELECT 'restored-' || i, 'restored', 'critical', $1 FROM generate_series(1, 300) AS i", T0)
        finally:
            await conn.execute("ALTER TABLE findings ENABLE TRIGGER USER")
        assert await conn.fetchval("SELECT count(*) FROM findings WHERE severity_rank = 1 AND severity = 'critical'") == 300
        assert await list_schema.repair_severity_rank(pool) >= 300
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") == 0
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE fingerprint LIKE 'restored-%' AND updated_at <> $1", T0) == 0
        # The API's maintenance task runs the same repair after it starts serving.
        await list_schema.repair_severity_rank_in_background(pool, delay=0)

    run(scenario)


def test_lists_answer_the_same_while_an_upgraded_database_is_still_being_ranked(monkeypatch):
    """The first 2.11 start serves before the existing findings are ranked: meanwhile the list
    orders by the function the rank is computed from, so every page holds the same rows in the same
    order, and a cursor taken before the rank completes continues after it."""
    async def scenario(conn, pool):
        async def answers():
            out = {}
            for filters in ({}, {"status": "active"}, {"severity": "critical,high"}, {"root_domain": "alpha.test"}):
                for sort_by, sort_order in SORTS:
                    for offset in (0, 150):
                        result, _queries = await route(pool, monkeypatch, sort_by=sort_by, sort_order=sort_order,
                                                       offset=offset, limit=50, **filters)
                        out[("legacy", str(filters), sort_by, sort_order, offset)] = (
                            [item["id"] for item in result["findings"]], result["total"])
                for sort in ("-severity", "severity"):
                    out[("v1", str(filters), sort)] = [
                        item["id"] for item in await walk(pool, monkeypatch, limit=41, sort=sort, **filters)]
            return out

        ranked = await answers()
        await _back_to_2_10(conn)
        async with conn.transaction():
            for statement in list_schema.FINDINGS_LIST_SCHEMA_STATEMENTS:
                await conn.execute(statement)
        await list_schema.finish_findings_list_schema(conn)
        assert await conn.fetchval(
            "SELECT count(*) FROM findings WHERE severity_rank <> finding_severity_rank(severity)") > 0
        list_schema.reset_severity_rank_ready()
        assert await list_schema.severity_rank_ready(conn) is False
        assert await answers() == ranked
        _result, queries = await route(pool, monkeypatch, limit=10)
        assert any("finding_severity_rank(f.severity)" in query for query, _args in queries)

        # A walk that starts unranked and finishes after the background rank recorded its marker.
        first, _ = await route(pool, monkeypatch, limit=41, sort="-severity")
        assert await list_schema.repair_severity_rank(pool) > 0
        monkeypatch.setattr(list_schema, "_RANK_RECHECK_SECONDS", 0.0)
        assert await list_schema.severity_rank_ready(conn) is True
        items, cursor = list(first["items"]), first["next_cursor"]
        while cursor:
            page, queries = await route(pool, monkeypatch, limit=200, sort="-severity", cursor=cursor)
            assert any("f.severity_rank" in query and "finding_severity_rank(f.severity)" not in query
                       for query, _args in queries)
            items += page["items"]
            cursor = page["next_cursor"]
        assert [item["id"] for item in items] == ranked[("v1", "{}", "-severity")]
        assert await loop_scale_indexes.ensure_loop_scale_indexes(pool)

    run(scenario)


def test_a_new_database_is_ranked_at_startup():
    async def scenario(conn, pool):
        await conn.execute("DELETE FROM app_schema_migrations WHERE name = $1", list_schema.SEVERITY_RANK_MIGRATION)
        await list_schema.finish_findings_list_schema(conn)
        assert await list_schema.severity_rank_ready(conn) is True

    run(scenario, data=False)


_OLD_RECONCILE = (
    """UPDATE targets t SET active_findings_count=counted.n
       FROM (SELECT t2.id, (SELECT COUNT(*) FROM findings f
                            WHERE f.target_id=t2.id AND f.status='active') AS n
             FROM targets t2) counted
       WHERE t.id=counted.id AND t.active_findings_count IS DISTINCT FROM counted.n""",
    """UPDATE target_device_profiles p SET active_findings_count=counted.n
       FROM (SELECT p2.target_id, (SELECT COUNT(*) FROM findings f
                                   WHERE f.device_target_id=p2.target_id
                                     AND f.status='active') AS n
             FROM target_device_profiles p2) counted
       WHERE p.target_id=counted.target_id AND p.active_findings_count IS DISTINCT FROM counted.n""",
)


def test_the_startup_badge_repair_counts_what_the_per_target_count_did():
    """The finding badges are repaired on every start under the startup lock; one grouped count
    replaced a count per target (~3 s per start at 500k findings) with the same result."""
    async def scenario(conn, pool):
        from targets.asset_migration import reconcile_active_finding_counts
        await conn.execute("UPDATE targets SET active_findings_count = (random() * 9)::int")
        await conn.execute("UPDATE target_device_profiles SET active_findings_count = (random() * 9)::int")
        state = """SELECT (SELECT array_agg((id, active_findings_count) ORDER BY id) FROM targets),
                          (SELECT array_agg((target_id, active_findings_count) ORDER BY target_id)
                           FROM target_device_profiles)"""
        tx = conn.transaction()
        await tx.start()
        for statement in _OLD_RECONCILE:
            await conn.execute(statement)
        expected = await conn.fetchrow(state)
        await tx.rollback()
        await reconcile_active_finding_counts(conn)
        assert await conn.fetchrow(state) == expected
        assert any(n for _id, n in expected[0]) and any(n for _id, n in expected[1])

    run(scenario)
