"""POST /discovery admission: validation, declared target, per-apex and global limits, requester.

Unit tests use an in-memory fixture connection (no network, no scanner process). The last test
runs the engine's real startup migrations against an explicit disposable PostgreSQL database
when DISCOVERY_TEST_DATABASE_URL names one.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
from pathlib import Path
import sys
import uuid

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "tests"))

from operations import discovery  # noqa: E402
from operations import router as operations_router  # noqa: E402


class FixtureConn:
    """Enough of an asyncpg connection for admission: targets, scope receipts, discovery runs.

    It applies the automated-source exclusion; the ``host``-row and ``created_via`` rules are
    SQL and are exercised against PostgreSQL in tests/test_target_asset_psl_postgres.py.
    Scope receipts are never consulted: ``fetchval`` fails the test if admission asks.
    """

    def __init__(self, targets=(), runs=()):
        self.targets = [dict(item) for item in targets]
        self.runs = [dict(item) for item in runs]
        self.locks = 0
        self.updates: list[tuple] = []

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, query, *args):
        if "pg_advisory_xact_lock" in query:
            self.locks += 1
        elif query.lstrip().startswith("INSERT INTO discovery_runs"):
            self.runs.append({"id": args[0], "root_domain": args[1], "status": "pending", "requested_by": args[2]})
        elif query.lstrip().startswith("UPDATE discovery_runs"):
            self.updates.append(args)
        return "OK"

    async def fetch(self, query, *args):
        if "FROM targets" in query:
            apex, undeclared = args
            return [{"url": row["url"]} for row in self.targets
                    if row.get("discovery_source", "manual") not in undeclared and apex in row["url"].lower()]
        if "FROM discovery_runs" in query:
            return [row for row in self.runs if row["status"] in {"pending", "running"}]
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        assert "FROM scope_receipts" in query
        raise AssertionError(f"admission consulted something else: {query}")


class FixturePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


def start(conn, root_domain, *, fail_enqueue=False):
    queued: list[dict] = []

    def enqueue(_redis, _queue, job):
        if fail_enqueue:
            raise RuntimeError("redis is down")
        queued.append(job)

    operations_router.configure_operations_router(
        lambda: FixturePool(conn), get_redis=lambda: object(), enqueue_job=enqueue,
    )
    result = asyncio.run(operations_router.start_discovery(root_domain=root_domain))
    return result, queued


DECLARED = [{"url": "https://app.example.co.uk"}]


@pytest.mark.parametrize("raw", ["", "https://x.com", "x.com/path", "1.2.3.4", "*.x.com", "co.uk", "com",
                                 "github.io", "x.com:8443", "-x.example.com", "a" * 300 + ".com"])
def test_invalid_domains_and_public_suffixes_are_refused_with_400(raw):
    conn = FixtureConn(targets=DECLARED)
    with pytest.raises(HTTPException) as refused:
        start(conn, raw)
    assert refused.value.status_code == 400
    assert refused.value.detail.startswith("Cannot discover subdomains: ")
    assert conn.runs == [] and conn.locks == 0  # nothing stored before validation


def test_public_suffix_refusal_names_a_domain_to_use_instead():
    with pytest.raises(HTTPException) as refused:
        start(FixtureConn(), "co.uk")
    assert "co.uk is a public suffix; name a domain you control, e.g. example.co.uk" in refused.value.detail


def test_targets_page_flow_queues_the_normalized_domain_and_records_the_requester():
    conn = FixtureConn(targets=DECLARED)
    result, queued = start(conn, " Example.CO.UK. ")
    assert result["status"] == "queued" and result["root_domain"] == "example.co.uk"
    (job,) = queued
    assert job["type"] == "discovery" and job["root_domain"] == "example.co.uk"
    assert job["discovery_id"] == result["discovery_id"]
    (run,) = conn.runs
    assert str(run["id"]) == result["discovery_id"] and run["root_domain"] == "example.co.uk"
    # Derived by the engine, never a caller-supplied value.
    assert run["requested_by"] == "local-operator"
    import inspect

    assert list(inspect.signature(operations_router.start_discovery).parameters) == ["root_domain"]
    assert conn.locks == 1


def test_a_subdomain_of_a_declared_apex_is_admitted_and_shares_its_apex_slot():
    conn = FixtureConn(targets=[{"url": "https://example.com"}])
    result, _ = start(conn, "dev.example.com")
    assert result["root_domain"] == "dev.example.com"
    with pytest.raises(HTTPException) as busy:
        start(conn, "example.com")
    assert busy.value.status_code == 409 and "already queued or running" in busy.value.detail


@pytest.mark.parametrize("targets", [
    [],
    [{"url": "https://notexample.co.uk"}, {"url": "https://example.co.uk.evil.test"}],
    [{"url": "https://shop.example.co.uk", "discovery_source": "subfinder"}],
    [{"url": "https://shop.example.co.uk", "discovery_source": "gungnir-monitor"}],
    [{"url": "https://shop.example.co.uk", "discovery_source": "ai_session"}],
    [{"url": "https://shop.example.co.uk", "discovery_source": "ai_gate"}],
    [{"url": "https://shop.example.co.uk:8443", "discovery_source": "device-service"}],
    [{"url": "https://shop.example.co.uk", "discovery_source": "scan"}],
])
def test_a_domain_with_no_declared_target_is_refused_with_403(targets):
    conn = FixtureConn(targets=targets)
    with pytest.raises(HTTPException) as refused:
        start(conn, "example.co.uk")
    assert refused.value.status_code == 403
    assert "Add a target under example.co.uk first" in refused.value.detail
    assert conn.runs == []


def test_a_host_target_counts_and_the_refusal_says_where_to_add_one():
    result, _ = start(FixtureConn(targets=[{"url": "host://db.example.net", "discovery_source": "host"}]), "example.net")
    assert result["status"] == "queued"
    with pytest.raises(HTTPException) as refused:
        start(FixtureConn(targets=[{"url": "https://a.example.org", "discovery_source": "scan"}]), "example.org")
    assert "was added on the Targets page" in refused.value.detail


def test_engine_wide_limit_refuses_with_429(monkeypatch):
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "2")
    runs = [{"id": uuid.uuid4(), "root_domain": name, "status": "running"} for name in ("a.test", "b.test")]
    conn = FixtureConn(targets=DECLARED, runs=runs)
    with pytest.raises(HTTPException) as refused:
        start(conn, "example.co.uk")
    assert refused.value.status_code == 429 and discovery.MAX_ACTIVE_ENV in refused.value.detail
    monkeypatch.setenv(discovery.MAX_ACTIVE_ENV, "3")
    assert start(conn, "example.co.uk")[0]["status"] == "queued"


def test_a_queue_failure_releases_the_apex():
    conn = FixtureConn(targets=DECLARED)
    with pytest.raises(RuntimeError):
        start(conn, "example.co.uk", fail_enqueue=True)
    (update,) = conn.updates
    assert update[0] == conn.runs[0]["id"]


def test_the_worker_revalidates_a_queued_domain_and_spawns_nothing(monkeypatch):
    import worker

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("no process may be spawned for an invalid queued domain")

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", forbidden)
    for queued in ("co.uk", "-oProxyCommand=x", "x.com; id", "https://x.com", None):
        outcome = asyncio.run(worker.run_discovery(queued))
        assert outcome["subdomains"] == [] and outcome["error"].startswith("Cannot discover subdomains")


def test_the_worker_runs_the_normalized_domain(monkeypatch):
    import worker

    seen: list[tuple] = []

    class Proc:
        async def communicate(self):
            return b'{"subdomains": ["a.example.com"], "by_source": {"subfinder": 1}, "subdomain_count": 1}', b""

    async def spawn(*argv, **_kwargs):
        seen.append(argv)
        return Proc()

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", spawn)
    outcome = asyncio.run(worker.run_discovery("Example.COM"))
    assert seen == [("python3", worker.SCANNER_PATH, "example.com", "--subfinder", "--quick")]
    assert outcome == {"subdomains": ["a.example.com"], "by_source": {"subfinder": 1}, "total": 1}


def test_the_admission_module_never_creates_processes():
    # It is imported by the API process (test_api_image_boundary): the worker owns the spawn.
    import ast

    tree = ast.parse((ROOT / "api" / "operations" / "discovery.py").read_text(encoding="utf-8"))
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names}
    assert not names & {"create_subprocess_exec", "create_subprocess_shell", "Popen", "run"}
    assert not imported & {"asyncio", "subprocess"}


DSN = os.environ.get("DISCOVERY_TEST_DATABASE_URL")


def _real_asyncpg(monkeypatch):
    # Another test module may leave an asyncpg stub in sys.modules; this test needs the driver.
    if not hasattr(sys.modules.get("asyncpg"), "connect"):
        monkeypatch.delitem(sys.modules, "asyncpg", raising=False)
    return pytest.importorskip("asyncpg")


async def _fresh_database(dsn: str, asyncpg, *, before_migrations=None):
    import retest_contract

    conn = await asyncpg.connect(dsn)
    await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
    await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
    if before_migrations:
        await before_migrations(conn)
    # The startup migrations an engine runs (scope_receipts, discovery_runs.requested_by, the
    # target asset model and the legacy root recompute).
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
    try:
        await retest_contract.run_schema_migrations(pool)
    finally:
        await pool.close()
    return conn


# The admission SQL (declared targets, bound receipts) runs against PostgreSQL in
# tests/test_target_asset_psl_postgres.py, which the target-assets CI job executes.


@pytest.mark.skipif(not DSN, reason="Requires an explicit disposable PostgreSQL database")
def test_upgrade_recomputes_legacy_public_suffix_roots_and_keeps_monitoring(monkeypatch):
    asyncpg = _real_asyncpg(monkeypatch)
    from disposable_postgres import require_disposable_database
    from scope.roots import monitored_root

    dsn = require_disposable_database(DSN or "", "shakerscan_discovery_test")

    async def legacy_rows(conn):
        # As an engine before 2.8.1 stored them: two-label roots.
        await conn.execute("""INSERT INTO targets(url, name, root_domain, is_root) VALUES
            ('https://shop.example.co.uk', 'shop', 'co.uk', false),
            ('https://example.co.uk', 'apex', 'co.uk', false),
            ('https://victim.github.io', 'pages', 'github.io', false),
            ('https://api.example.com', 'api', 'example.com', false)""")

    async def go():
        conn = await _fresh_database(dsn, asyncpg, before_migrations=legacy_rows)
        try:
            rows = {row["url"]: (row["root_domain"], row["is_root"]) for row in await conn.fetch(
                "SELECT url, root_domain, is_root FROM targets WHERE url LIKE 'https://%'")}
            # A second start changes nothing (idempotent).
            from scope.roots import recompute_spanning_target_roots

            again = await recompute_spanning_target_roots(conn)
            return rows, again
        finally:
            await conn.close()

    rows, again = asyncio.run(go())
    assert rows == {
        "https://shop.example.co.uk": ("example.co.uk", False),
        "https://example.co.uk": ("example.co.uk", True),
        "https://victim.github.io": ("victim.github.io", True),
        "https://api.example.com": ("example.com", False),
    }
    assert again == 0
    # Before the migration has run, the CT monitor already watches the recomputed root.
    assert monitored_root("co.uk", "https://shop.example.co.uk") == "example.co.uk"
    assert monitored_root("co.uk", "https://co.uk") == ""
