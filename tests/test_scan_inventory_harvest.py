"""A completed canonical Scan's discovery must reach the persistent endpoint inventory.

A canonical Scan records its discovery output as durable ``discover.*`` action receipts and
observation manifests; it never emits the old ``active_checks.active_worklist`` report block.
The worker persisted inventory only from that old block, so an on-demand ASM recon that
crawled 229 transactions still left the target with no inventory, and the "Discover
endpoints" action the UI recommends for an empty inventory could never satisfy itself.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from scan.execution import ScanExecutionPlan
from scan.inventory_harvest import scan_inventory_worklist

SCAN_ID = "38e0dd54-0000-4000-8000-000000000001"


def _binding() -> TargetBinding:
    return TargetBinding(
        target_id="target-recon",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.30",),
        allowed_root_domains=("example.test",),
    )


def _recon_options(*, run_kind: str | None = "asm_recon") -> dict:
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=False,
            allow_state_changing_http=False,
            network_discovery=False,
            subdomain_discovery=False,
            include_families=("recon",),
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, 2000, 200, 5000, 900, 4, 0, 100),
    )
    options = plan.option_metadata()
    options.update({"active": False, "network_discovery": False, "subfinder": False})
    options["_canonical_target_binding"] = _binding().canonical_dict()
    if run_kind:
        options["run_kind"] = run_kind
    return options


class _Conn:
    def __init__(self, statuses, observations):
        self.statuses = statuses
        self.observations = observations
        self.queries = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        assert args[0] == uuid.UUID(SCAN_ID)
        if "FROM scan_capability_actions" in query:
            return [{"action_id": key, "status": value} for key, value in self.statuses.items()]
        if "FROM scan_observation_manifests" in query:
            import json

            return [
                {"action_id": key, "observations_json": json.dumps(value)}
                for key, value in self.observations.items()
            ]
        raise AssertionError(query)


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


def _recon_receipts():
    statuses = {
        "discover.web_probe": "success",
        "discover.web_crawl": "success",
        "discover.browser_crawl": "success",
    }
    observations = {
        "discover.web_crawl": [
            {"kind": "discovered_route", "method": "GET",
             "url": "https://app.example.test/hub/orders?id=7"},
        ],
        "discover.browser_crawl": [
            {"kind": "discovered_route", "method": "POST",
             "url": "https://app.example.test/hub/login",
             "content_type": "application/x-www-form-urlencoded",
             "body_field_names": ["username", "password"]},
            {"kind": "discovered_route", "method": "GET",
             "url": "https://elsewhere.test/collect?x=1"},
        ],
    }
    return statuses, observations


def test_completed_asm_recon_yields_its_discovered_endpoints_for_the_inventory():
    conn = _Conn(*_recon_receipts())
    # The canonical report carries no active_checks block at all.
    result = {"findings": [], "scan_metadata": {"status": "completed"}}

    worklist, source = asyncio.run(scan_inventory_worklist(
        _Pool(conn), result, scan_id=SCAN_ID,
        target_url="https://app.example.test", options=_recon_options(),
    ))

    assert "GET /hub/orders?id=" in worklist
    assert "POST /hub/login form:password=1&username=1" in worklist
    assert not any("elsewhere.test" in item for item in worklist)
    # A recon refresh is recorded as recon provenance, a scanner-discovered candidate.
    assert source == "recon"


def test_standalone_canonical_scan_also_harvests_its_own_discovery():
    conn = _Conn(*_recon_receipts())
    worklist, source = asyncio.run(scan_inventory_worklist(
        _Pool(conn), {"findings": []}, scan_id=SCAN_ID,
        target_url="https://app.example.test", options=_recon_options(run_kind=None),
    ))
    assert "GET /hub/orders?id=" in worklist
    assert source == "scan"


def test_report_worklist_still_wins_and_needs_no_database_read():
    conn = _Conn({}, {})
    result = {"active_checks": {"active_worklist": ["GET /legacy?q="]}}
    worklist, source = asyncio.run(scan_inventory_worklist(
        _Pool(conn), result, scan_id=SCAN_ID,
        target_url="https://app.example.test", options=_recon_options(run_kind=None),
    ))
    assert worklist == ["GET /legacy?q="]
    assert source == "scan"
    assert conn.queries == []


def test_scan_without_discovery_receipts_or_canonical_authority_yields_nothing():
    conn = _Conn({}, {})
    assert asyncio.run(scan_inventory_worklist(
        _Pool(conn), {}, scan_id=SCAN_ID,
        target_url="https://app.example.test", options=_recon_options(),
    )) == ([], "recon")
    # A non-canonical (device/AI) run has no frozen binding: nothing is read.
    conn = _Conn(*_recon_receipts())
    assert asyncio.run(scan_inventory_worklist(
        _Pool(conn), {}, scan_id=SCAN_ID,
        target_url="https://app.example.test", options={"run_kind": "device_posture"},
    )) == ([], "scan")
    assert conn.queries == []


def test_worker_persists_standalone_inventory_through_the_canonical_harvest():
    """The worker's standalone-scan inventory step must use the canonical harvest."""
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    start = source.index("# Continuous ASM: persist this scan's discovered endpoint worklist")
    block = source[start:source.index("ASM authenticated telemetry inventory", start)]
    assert "await scan_inventory_worklist(" in block
    assert "source=inventory_source" in block
    assert "result.get('active_checks')" not in block
