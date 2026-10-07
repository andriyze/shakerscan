"""The Scan option "Discover subdomains" records what it found.

The soak scan of shakerscan.com ran ``subdomains.discover`` (success, 12 observations in 11 s)
and nothing showed: the names reached only the endpoint manifest, where they were out of the
scan's origin scope. The finalizer now lists them in ``report.discovery.subdomains`` and the
worker records them as a discovery run and DNS-checked targets, as the Targets page does.

The PostgreSQL test runs the recorder on the real schema when
SUBDOMAIN_TARGETS_TEST_DATABASE_URL names a disposable localhost/shakerscan_subdomain_test
database; the other tests use fixtures.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import time

import pytest

from api.scan import subdomain_targets
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.disposable_postgres import require_disposable_database
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

ROOT = Path(__file__).resolve().parents[1]

HOSTS = ("api.shakerscan.com", "docs.shakerscan.com", "old.shakerscan.com")


def _report_with_subdomains(hosts=HOSTS):
    discover = _action("discover.subdomains", 0, capability_name="subdomains.discover")
    final = _action("finalize.report", 1, dependencies=(discover.action_id,))
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(discover, final),
    )
    observations = {discover.action_id: tuple(
        {"kind": "subdomain", "host": host, "root_domain": "shakerscan.com"}
        for host in hosts
    )}
    return finalize_scan_report(
        plan=plan, target_url="https://shakerscan.com",
        action_results={discover.action_id: _result_with_observation_count(discover, len(hosts))},
        observations=observations,
    )


def test_the_report_lists_the_subdomains_the_scan_discovered():
    section = _report_with_subdomains()["discovery"]["subdomains"]
    assert section["hosts"] == sorted(HOSTS)
    assert section["count"] == 3
    assert section["root_domain"] == "shakerscan.com"
    assert section["source"] == "subfinder"
    # The names are not tested by this scan; they become targets for their own scans.
    assert section["scope"] == "discovered_names_not_scanned_by_this_scan"


class _FakeConn:
    def __init__(self, existing=None):
        self.existing = existing
        self.inserted_targets = []
        self.runs = []

    async def fetchrow(self, query, *args):
        assert "FROM discovery_runs" in query and args == (str(SCAN_ID),)
        return self.existing

    async def execute(self, query, *args):
        if "INSERT INTO targets" in query:
            self.inserted_targets.append(args[0])
            return "INSERT 0 1"
        if "INSERT INTO discovery_runs" in query:
            self.runs.append(args)
            return "INSERT 0 1"
        raise AssertionError(query)


def _pool(conn):
    @asynccontextmanager
    async def acquire():
        yield conn

    class _Pool:
        def acquire(self):
            return acquire()

    return _Pool()


async def _plan(names):
    names = list(names)
    return {
        "scannable": [name for name in names if not name.startswith("old.")],
        "unresolved": [name for name in names if name.startswith("old.")],
        "unknown": [],
    }


def test_discovered_subdomains_become_a_discovery_run_and_targets():
    report = _report_with_subdomains()
    conn = _FakeConn()
    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(conn), report, scan_id=str(SCAN_ID), plan_targets=_plan,
    ))
    assert conn.inserted_targets == ["https://api.shakerscan.com", "https://docs.shakerscan.com"]
    assert len(conn.runs) == 1
    run = conn.runs[0]
    assert run[1] == "shakerscan.com" and run[2] == 3 and run[3] == 2
    assert json.loads(run[5])["scan_id"] == str(SCAN_ID)
    assert outcome["status"] == "recorded"
    assert outcome["added"] == 2 and outcome["unresolved_count"] == 1
    assert report["discovery"]["subdomains"]["targets"] == outcome


def test_a_redelivered_scan_reports_its_existing_run_instead_of_recording_another():
    report = _report_with_subdomains()
    conn = _FakeConn(existing={
        "id": "5f9c0e0c-6f43-4d3c-9d2f-6f1b0b8f7a10",
        "sources_used": json.dumps({"dns_resolution": {"added": 2, "scannable": 2, "unresolved_count": 1}}),
    })

    async def _no_dns(names):
        raise AssertionError("an existing run needs no new lookups")

    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(conn), report, scan_id=str(SCAN_ID), plan_targets=_no_dns,
    ))
    assert conn.inserted_targets == [] and conn.runs == []
    assert outcome["discovery_id"] == "5f9c0e0c-6f43-4d3c-9d2f-6f1b0b8f7a10"
    assert outcome["added"] == 2


def test_a_recording_fault_is_reported_and_never_fails_the_scan():
    report = _report_with_subdomains()

    async def _resolver_down(names):
        raise OSError("resolver unavailable")

    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(_FakeConn()), report, scan_id=str(SCAN_ID), plan_targets=_resolver_down,
    ))
    assert outcome == {"status": "failed", "error": "OSError"}
    assert report["discovery"]["subdomains"]["targets"] == outcome


def test_a_report_without_subdomains_records_nothing():
    report = {"discovery": {"tech": {"items": []}}}
    assert asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(_FakeConn()), report, scan_id=str(SCAN_ID),
    )) is None


def test_a_list_cut_at_the_report_limit_says_how_many_names_were_found():
    hosts = tuple(f"h{index:04d}.shakerscan.com" for index in range(1_200))
    section = _report_with_subdomains(hosts)["discovery"]["subdomains"]
    assert section["count"] == 1_000 and len(section["hosts"]) == 1_000
    assert section["total"] == 1_200
    assert section["truncated"] is True
    complete = _report_with_subdomains()["discovery"]["subdomains"]
    assert complete["total"] == 3 and complete["truncated"] is False


def test_every_name_the_recording_did_not_check_or_add_is_counted_with_its_cap():
    """1,500 names: the report lists 1,000, DNS checks a window of 300, and 100 become targets.
    The outcome used to say only "100 added", so 1,400 names vanished without a word."""
    hosts = tuple(f"h{index:04d}.shakerscan.com" for index in range(1_000))
    report = _report_with_subdomains(hosts)
    report["discovery"]["subdomains"]["total"] = 1_500
    conn = _FakeConn()

    async def resolves(_name):
        return ["203.0.113.10"]

    async def plan(names):
        return await subdomain_targets.target_resolution.plan_discovered_targets(
            names, lookup=resolves,
        )

    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(conn), report, scan_id=str(SCAN_ID), plan_targets=plan,
    ))
    assert len(conn.inserted_targets) == 100
    assert outcome["found"] == 1_500
    assert outcome["checked"] == 300 and outcome["not_checked"] == 1_200
    assert outcome["added"] == 100
    assert outcome["target_limit"] == 100 and outcome["over_target_limit"] == 200
    assert outcome["partial"] is True
    assert outcome["partial_reasons"] == ["report_list_limit", "dns_resolve_limit", "target_limit"]
    run = conn.runs[0]
    assert run[2] == 1_500
    stored = json.loads(run[5])["dns_resolution"]
    assert stored["judged"] == 300 and stored["beyond_resolve_limit"] == 700

    # A redelivered job reports the same account from the stored run.
    redelivered = _report_with_subdomains(hosts)
    redelivered["discovery"]["subdomains"]["total"] = 1_500
    again = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(_FakeConn(existing={"id": outcome["discovery_id"], "sources_used": run[5]})),
        redelivered, scan_id=str(SCAN_ID),
    ))
    assert again["checked"] == 300 and again["over_target_limit"] == 200


def test_a_dead_resolver_cannot_hold_the_finished_scan_beyond_the_dns_deadline(monkeypatch):
    """Each lookup has a 3 s timeout; 40 names at 16 at a time took about 9 s before the scan
    could be saved, and a full window about a minute. One deadline now bounds the whole check."""
    async def hangs(_name):
        await asyncio.sleep(30)
        return []

    monkeypatch.setattr(subdomain_targets.target_resolution, "system_lookup", hangs)
    monkeypatch.setattr(subdomain_targets, "DNS_DEADLINE_SECONDS", 0.2)
    hosts = tuple(f"h{index:02d}.shakerscan.com" for index in range(40))
    conn = _FakeConn()
    started = time.monotonic()
    outcome = asyncio.run(subdomain_targets.record_scan_subdomain_discovery(
        _pool(conn), _report_with_subdomains(hosts), scan_id=str(SCAN_ID),
    ))
    assert time.monotonic() - started < 2.0
    assert outcome["status"] == "recorded"
    assert outcome["dns_deadline_skipped"] == 40
    assert outcome["checked"] == 0 and outcome["not_checked"] == 40
    assert "dns_deadline" in outcome["partial_reasons"]
    # An unjudged name stays scannable, as a resolver fault always has; the report says so.
    assert len(conn.inserted_targets) == 40


# --- the recorder on real PostgreSQL ----------------------------------------------------------

DSN = os.environ.get("SUBDOMAIN_TARGETS_TEST_DATABASE_URL")


@pytest.mark.skipif(not DSN, reason="Requires an explicit disposable PostgreSQL database")
def test_the_recorder_writes_the_real_discovery_and_target_tables():
    asyncpg = pytest.importorskip("asyncpg")
    dsn = require_disposable_database(DSN or "", "shakerscan_subdomain_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
            report = _report_with_subdomains()
            first = await subdomain_targets.record_scan_subdomain_discovery(
                _pool(conn), report, scan_id=str(SCAN_ID), plan_targets=_plan,
            )
            again = await subdomain_targets.record_scan_subdomain_discovery(
                _pool(conn), _report_with_subdomains(), scan_id=str(SCAN_ID), plan_targets=_plan,
            )
            targets = await conn.fetch(
                "SELECT url, discovery_source, root_domain FROM targets ORDER BY url"
            )
            runs = await conn.fetch("SELECT * FROM discovery_runs")
            return first, again, targets, runs
        finally:
            await conn.close()

    first, again, targets, runs = asyncio.run(go())
    assert first["status"] == "recorded" and first["added"] == 2
    assert again["discovery_id"] == first["discovery_id"]
    assert [row["url"] for row in targets] == ["https://api.shakerscan.com", "https://docs.shakerscan.com"]
    assert {row["discovery_source"] for row in targets} == {"subfinder"}
    assert len(runs) == 1 and runs[0]["status"] == "completed" and runs[0]["subdomains_found"] == 3
