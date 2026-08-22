from __future__ import annotations

from datetime import datetime, timezone
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.network import SubdomainsDiscoverAdapter
from runtime.budget_reservations import DurableBudgetReservation
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.capability_settlement import terminalize_capability_reservation
from runtime.models import ScanPolicy, TargetBinding
from scan.capability_execution import (
    CANONICAL_SCAN_NETWORK_PORTS,
    ScanCapabilityContractError,
    fit_prepared_scan_capability,
    scan_budget_ledger_limits,
    scan_capability_action_digest,
    scan_external_execution_target,
    scan_network_capability_allocation,
    scan_template_capability_allocation,
    scan_content_discovery_capability_allocation,
    scan_web_crawl_capability_allocation,
    scan_web_probe_capability_allocation,
    prepare_scan_external_capability,
    prepare_scan_process_capability,
)


NOW = datetime(2026, 8, 22, 18, 0, tzinfo=timezone.utc)


def _budget(**overrides):
    result = {
        "max_duration_seconds": 1_200,
        "max_http_requests": 100,
        "max_endpoints": 50,
        "max_browser_actions": 20,
        "max_tcp_ports": 10,
        "max_tool_wall_seconds": 60,
        "max_workers": 2,
    }
    result.update(overrides)
    return result


def _target():
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )


def _prepared():
    return SubdomainsDiscoverAdapter().prepare(
        target=_target(),
        args={"root_domain": "example.test"},
        policy=ScanPolicy(subdomain_discovery=True, scope_receipt_id="scope-1"),
    )


def test_scan_ledger_has_one_shared_dimension_mapping_for_replay_and_discovery():
    limits = scan_budget_ledger_limits(_budget())

    assert limits == {
        "http_requests": 100,
        "state_changing_requests": 100,
        "browser_actions": 20,
        "tcp_ports_attempted": 10,
        "hosts_attempted": 50,
        "tool_wall_seconds": 60,
    }


def test_scan_capability_is_clamped_before_reservation_and_digest_binds_authority():
    prepared = fit_prepared_scan_capability(
        _prepared(), ledger_limits=scan_budget_ledger_limits(_budget()),
    )

    assert prepared.estimated_budget == {
        "hosts_attempted": 1,
        "tool_wall_seconds": 60,
    }
    digest = scan_capability_action_digest(
        scan_id="scan-1",
        execution_plan_digest="a" * 64,
        target=_target(),
        prepared=prepared,
    )
    assert len(digest) == 64
    changed = fit_prepared_scan_capability(
        _prepared(),
        ledger_limits=scan_budget_ledger_limits(
            _budget(max_tool_wall_seconds=30)
        ),
    )
    assert scan_capability_action_digest(
        scan_id="scan-1",
        execution_plan_digest="a" * 64,
        target=_target(),
        prepared=changed,
    ) != digest

    with pytest.raises(ScanCapabilityContractError, match="no capacity"):
        fit_prepared_scan_capability(
            _prepared(),
            ledger_limits=scan_budget_ledger_limits(
                _budget(max_endpoints=0), allow_zero=True,
            ),
        )


def test_network_allocation_reserves_two_bounded_passes_within_scan_ceiling():
    allocation = scan_network_capability_allocation(
        _budget(
            max_endpoints=6,
            max_tcp_ports=10,
            max_tool_wall_seconds=61,
        ),
        available_address_count=4,
    )

    assert allocation["address_count"] == 3
    assert allocation["ports"] == CANONICAL_SCAN_NETWORK_PORTS[:1]
    first = allocation["port_discovery_limits"]
    second = allocation["fingerprint_limits"]
    assert first["hosts_attempted"] + second["hosts_attempted"] == 6
    assert first["tcp_ports_attempted"] + second["tcp_ports_attempted"] == 6
    assert first["tool_wall_seconds"] + second["tool_wall_seconds"] == 61


def test_network_allocation_degrades_to_port_only_when_budget_cannot_fingerprint():
    allocation = scan_network_capability_allocation(
        _budget(
            max_endpoints=1,
            max_tcp_ports=1,
            max_tool_wall_seconds=1,
        ),
        available_address_count=2,
    )

    assert allocation["address_count"] == 1
    assert allocation["ports"] == CANONICAL_SCAN_NETWORK_PORTS[:1]
    assert allocation["fingerprint_limits"] is None


def test_template_allocation_preserves_budget_for_the_baseline_scan():
    assert scan_template_capability_allocation(_budget()) == {
        "http_requests": 25,
        "tool_wall_seconds": 15,
    }
    assert scan_template_capability_allocation(
        _budget(max_http_requests=20_000, max_tool_wall_seconds=2_700)
    ) == {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
    }
    assert scan_template_capability_allocation(
        _budget(max_http_requests=1)
    ) is None


def test_web_probe_allocation_preserves_later_stage_capacity():
    assert scan_web_probe_capability_allocation(_budget()) == {
        "http_requests": 4,
        "tool_wall_seconds": 30,
    }
    assert scan_web_probe_capability_allocation(
        _budget(max_http_requests=3, max_tool_wall_seconds=3),
        preserve_http_requests=2,
        preserve_tool_wall_seconds=2,
    ) == {
        "http_requests": 1,
        "tool_wall_seconds": 1,
    }
    assert scan_web_probe_capability_allocation(
        _budget(max_http_requests=2), preserve_http_requests=2,
    ) is None


def test_web_crawl_allocation_preserves_the_scan_backbone():
    assert scan_web_crawl_capability_allocation(_budget()) == {
        "http_requests": 10,
        "tool_wall_seconds": 6,
    }
    assert scan_web_crawl_capability_allocation(
        _budget(max_http_requests=20_000, max_tool_wall_seconds=2_700)
    ) == {
        "http_requests": 150,
        "tool_wall_seconds": 75,
    }
    assert scan_web_crawl_capability_allocation(
        _budget(max_http_requests=3)
    ) is None


def test_content_discovery_allocation_preserves_the_scan_backbone():
    assert scan_content_discovery_capability_allocation(_budget()) == {
        "http_requests": 10,
        "tool_wall_seconds": 6,
    }
    assert scan_content_discovery_capability_allocation(
        _budget(max_http_requests=20_000, max_tool_wall_seconds=2_700)
    ) == {
        "http_requests": 220,
        "tool_wall_seconds": 75,
    }
    assert scan_content_discovery_capability_allocation(
        _budget(max_tool_wall_seconds=3)
    ) is None


def test_external_target_must_match_the_exact_frozen_origin():
    assert scan_external_execution_target(
        "https://app.example.test/account?id=1#secret",
        target=_target(),
    ) == "https://app.example.test/account?id=1"

    with pytest.raises(ScanCapabilityContractError, match="origin"):
        scan_external_execution_target(
            "http://app.example.test/account",
            target=_target(),
        )
    with pytest.raises(ScanCapabilityContractError, match="host"):
        scan_external_execution_target(
            "https://evil.example.test/account",
            target=_target(),
        )


def test_scan_process_reserves_exact_remaining_multidimensional_budget():
    prepared, runtime = prepare_scan_process_capability(
        execution_plan_digest="a" * 64,
        target=_target(),
        stage_rows=({"name": "deterministic_baseline", "enabled": True},),
        ledger_limits=scan_budget_ledger_limits(_budget()),
        consumed={
            "http_requests": 7,
            "state_changing_requests": 2,
            "browser_actions": 3,
            "tcp_ports_attempted": 10,
            "hosts_attempted": 4,
            "tool_wall_seconds": 5,
        },
        allow_state_changing_http=True,
    )

    assert runtime == {
        "http_requests": 93,
        "state_changing_requests": 93,
        "browser_actions": 17,
        "tcp_ports_attempted": 0,
        "hosts_attempted": 46,
        "tool_wall_seconds": 55,
    }
    assert prepared.capability_name == "scan.execute"
    assert prepared.adapter_name == "scanner.dast"
    assert prepared.estimated_budget == {
        "http_requests": 93,
        "state_changing_requests": 93,
        "browser_actions": 17,
        "hosts_attempted": 46,
        "tool_wall_seconds": 55,
    }


def test_scan_process_requests_missing_mandatory_capacity_to_fail_closed():
    prepared, runtime = prepare_scan_process_capability(
        execution_plan_digest="a" * 64,
        target=_target(),
        stage_rows=(),
        ledger_limits=scan_budget_ledger_limits(_budget()),
        consumed={"http_requests": 100, "tool_wall_seconds": 60},
        allow_state_changing_http=False,
    )

    assert runtime["http_requests"] == 0
    assert runtime["tool_wall_seconds"] == 0
    assert prepared.estimated_budget["http_requests"] == 1
    assert prepared.estimated_budget["tool_wall_seconds"] == 1


def test_scan_external_capability_requires_frozen_binding_and_active_approval():
    specification = CAPABILITY_REGISTRY.require("templates.scan")
    policy = ScanPolicy(
        active_testing=True,
        approval_receipt_id="approval-1",
        scope_receipt_id="scope-1",
    )
    prepared = prepare_scan_external_capability(
        specification=specification,
        target=_target(),
        args={"severity": "high,critical", "tags": "cve,exposure"},
        policy=policy,
    )

    assert prepared.capability_name == "templates.scan"
    assert prepared.adapter_name == "nuclei"
    assert prepared.estimated_budget == {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
    }
    assert prepared.redacted_execution["target_binding_digest"] == _target().digest
    assert prepared.redacted_execution["input"] == {
        "severity": "high,critical",
        "tags": "cve,exposure",
    }

    with pytest.raises(ScanCapabilityContractError, match="active testing approval"):
        prepare_scan_external_capability(
            specification=specification,
            target=_target(),
            args={},
            policy=ScanPolicy(active_testing=True),
        )
    with pytest.raises(ScanCapabilityContractError, match="unsupported"):
        prepare_scan_external_capability(
            specification=specification,
            target=_target(),
            args={"argv": ["-target", "attacker.test"]},
            policy=policy,
        )


def test_shared_terminalizer_binds_scan_receipt_and_partial_observations():
    requested = DurableBudgetReservation.request(
        owner_kind="scan",
        owner_id="scan-1",
        capability_name="subdomains.discover",
        amounts={"hosts_attempted": 1, "tool_wall_seconds": 60},
        reservation_id="reservation-1",
        now=NOW,
    )
    running = requested.reserve(now=NOW, lease_seconds=90).start(
        worker_id="worker:test", now=NOW, lease_seconds=90,
    )
    terminal, receipt = terminalize_capability_reservation(
        running,
        action_digest="b" * 64,
        capability_name="subdomains.discover",
        adapter_name="subfinder",
        adapter_version="1",
        parser_version="subfinder-lines/v1",
        target_id="target-1",
        target_kind="web",
        capability_input={"root_domain": "example.test"},
        action_status="partial",
        actual_budget={"hosts_attempted": 1, "tool_wall_seconds": 4},
        worker_id="worker:test",
        started_at=NOW.isoformat(),
        finished_at=NOW.replace(second=5).isoformat(),
        receipt_id="receipt-1",
        scope_receipt_id="scope-1",
        result={
            "timed_out": True,
            "receipt_observations": [
                {
                    "kind": "subdomain",
                    "host": "api.example.test",
                    "root_domain": "example.test",
                }
            ],
        },
    )

    assert terminal.status == "committed"
    assert receipt.scan_id == "scan-1"
    assert receipt.hunt_id is None
    assert receipt.partial is True and receipt.timed_out is True
    assert receipt.public_dict()["observations"][0]["host"] == "api.example.test"
