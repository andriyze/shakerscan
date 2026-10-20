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
from scan.inventory_harvest import (
    post_scan_probes_allowed,
    record_scan_inventory,
    scan_inventory_worklist,
)

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


def _recon_options(*, run_kind: str | None = "asm_recon", max_endpoints: int = 2000) -> dict:
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=False,
            allow_state_changing_http=False,
            network_discovery=False,
            subdomain_discovery=False,
            include_families=("recon",),
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, max_endpoints, 200, 5000, 900, 4, 0, min(100, max_endpoints)),
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


def _many_routes(count):
    statuses = {"discover.web_crawl": "success"}
    observations = {"discover.web_crawl": [
        {"kind": "discovered_route", "method": "GET",
         "url": f"https://app.example.test/page{index}?id=1"}
        for index in range(count)
    ] + [
        {"kind": "discovered_route", "method": "GET", "url": "http://app.example.test/plain?q=1"},
        {"kind": "discovered_route", "method": "GET",
         "url": "https://app.example.test:8443/other-port?q=1"},
        {"kind": "discovered_route", "method": "GET", "url": "https://evil.test/x?q=1"},
    ]}
    return statuses, observations


def test_the_harvest_never_records_more_than_the_scan_endpoint_budget():
    conn = _Conn(*_many_routes(12))
    worklist, _source = asyncio.run(scan_inventory_worklist(
        _Pool(conn), {}, scan_id=SCAN_ID, target_url="https://app.example.test",
        options=_recon_options(max_endpoints=5),
    ))
    assert 0 < len(worklist) <= 5


def test_the_harvest_keeps_only_the_bound_origin():
    conn = _Conn(*_many_routes(3))
    worklist, _source = asyncio.run(scan_inventory_worklist(
        _Pool(conn), {}, scan_id=SCAN_ID, target_url="https://app.example.test",
        options=_recon_options(),
    ))
    # The bound origin's routes (and the scan's seed) only: no other scheme, port or host.
    assert sorted(worklist) == ["GET /", "GET /page0?id=", "GET /page1?id=", "GET /page2?id="]


class _Inventory:
    """Records what the inventory step asks for; a probe here would be traffic outside the scan."""

    def __init__(self):
        self.calls = []

    async def filter_reachable_worklist(self, target, worklist, options):
        self.calls.append("filter_reachable_worklist")
        return worklist

    def auth_state_from_options(self, options):
        return "anon"

    async def upsert_endpoints(self, conn, target_id, worklist, *, source, auth_state, scan_id):
        self.calls.append(("upsert", source, tuple(sorted(worklist))))
        return len(worklist)


def test_a_canonical_scan_records_its_inventory_without_new_traffic():
    """The harvest records what the scan's own pinned, budgeted discovery observed.

    The reachability filter re-requests every endpoint with its own resolver and no budget; run
    after every canonical scan it would add traffic the scan never admitted.
    """
    conn = _Conn(*_recon_receipts())
    inventory = _Inventory()
    count, source = asyncio.run(record_scan_inventory(
        _Pool(conn), inventory, {}, scan_id=SCAN_ID, target_id="target-recon",
        target_url="https://app.example.test", options=_recon_options(),
    ))
    assert count >= 2 and source == "recon"
    assert [call[0] for call in inventory.calls] == ["upsert"]
    assert post_scan_probes_allowed(_recon_options()) is False


def test_a_legacy_report_worklist_is_still_filtered_for_phantoms():
    conn = _Conn({}, {})
    inventory = _Inventory()
    result = {"active_checks": {"active_worklist": ["GET /legacy?q="]}}
    asyncio.run(record_scan_inventory(
        _Pool(conn), inventory, result, scan_id=SCAN_ID, target_id="target-recon",
        target_url="https://app.example.test", options={"run_kind": "scan"},
    ))
    assert inventory.calls[0] == "filter_reachable_worklist"
    assert post_scan_probes_allowed({"run_kind": "scan"}) is True


def test_the_worker_gates_both_post_scan_probes_on_the_canonical_check():
    source = (Path(__file__).resolve().parents[1] / "api" / "worker.py").read_text()
    start = source.index("# Continuous ASM: persist this scan's discovered endpoint worklist")
    block = source[start:source.index("finalize_ai_finding_retest(", start)]
    assert "await record_scan_inventory(" in block
    assert "filter_reachable_worklist" not in block
    assert "if _sweep_max > 0 and post_scan_probes_allowed(options):" in block
