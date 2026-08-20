from __future__ import annotations

import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import agent_tools
import command_arsenal
from runtime.budgets import (
    BudgetError, BudgetExceeded, BudgetLedger, reconcile_budget_snapshot,
    reserve_budget_snapshot,
)
from runtime.capability_registry import CAPABILITY_REGISTRY, LEGACY_TOOL_TO_CAPABILITY
from runtime.receipts import CapabilityReceipt


def test_registry_is_authoritative_for_legacy_hunt_tools_and_arsenal():
    registered = {spec.legacy_tool_name: spec for spec in CAPABILITY_REGISTRY.legacy_tools()}

    assert set(registered) == set(agent_tools.RUN_TOOL_NAMES)
    assert set(LEGACY_TOOL_TO_CAPABILITY) == set(agent_tools.RUN_TOOL_NAMES)
    for tool_name, template in agent_tools.SCANNER_ARG_TEMPLATES.items():
        spec = registered[tool_name]
        assert template["capability"] == spec.name
        assert template["binary"] == spec.binary
        assert template["risk"] == (
            "read_only" if spec.risk_tier in {"read_only", "passive"} else "active"
        )
        assert template["output_schema"] == spec.output_schema
        assert template["evidence_contract"] == spec.evidence_contract

    arsenal = {
        item["tool_name"]: item
        for item in command_arsenal.describe_tools(probe_versions=False)["tools"]
    }
    for tool_name, spec in registered.items():
        assert arsenal[tool_name]["capability_name"] == spec.name
        assert arsenal[tool_name]["risk_tier"] == spec.risk_tier
        assert arsenal[tool_name]["evidence_parser"] == spec.output_schema


def test_registry_filters_target_kind_and_active_permission():
    safe_web = {spec.name for spec in CAPABILITY_REGISTRY.list(
        target_kind="web", include_active=False
    )}
    all_device = {spec.name for spec in CAPABILITY_REGISTRY.list(target_kind="device")}

    assert safe_web == {
        "web.probe", "http.request", "subdomains.discover", "tls.inspect", "collections.inspect",
        "collections.select", "collections.replay_safe",
    }
    assert all_device == {
        "device.inspect", "device.capabilities.inspect", "device.http.probe",
        "device.scan", "device.service.verify", "collections.inspect", "collections.select",
        "device.ssh.propose",
    }
    assert not CAPABILITY_REGISTRY.require("web.probe").requires_active_approval
    assert CAPABILITY_REGISTRY.require("ports.discover").requires_active_approval


def test_every_capability_declares_runtime_contract():
    for spec in CAPABILITY_REGISTRY.list():
        assert spec.adapter
        assert spec.adapter_version
        assert spec.target_kinds
        assert spec.budget_cost
        assert spec.placement_requirements
        assert spec.input_schema["type"] == "object"
        assert spec.output_schema
        assert spec.evidence_contract


def test_budget_ledger_reserves_before_commit_and_refunds_unused_capacity():
    ledger = BudgetLedger({"http_requests": 10, "tool_wall_seconds": 20})
    reservation = ledger.reserve({"http_requests": 7, "tool_wall_seconds": 10})

    assert ledger.snapshot()["remaining"] == {"http_requests": 3, "tool_wall_seconds": 10}
    charged = ledger.commit(reservation, {"http_requests": 4, "tool_wall_seconds": 8})

    assert dict(charged) == {"http_requests": 4, "tool_wall_seconds": 8}
    assert ledger.snapshot() == {
        "limits": {"http_requests": 10, "tool_wall_seconds": 20},
        "reserved": {"http_requests": 0, "tool_wall_seconds": 0},
        "consumed": {"http_requests": 4, "tool_wall_seconds": 8},
        "remaining": {"http_requests": 6, "tool_wall_seconds": 12},
    }


def test_budget_ledger_rejects_exhaustion_atomically_and_release_is_reusable():
    ledger = BudgetLedger({"tcp_ports_attempted": 100, "agent_actions": 2})
    first = ledger.reserve({"tcp_ports_attempted": 80, "agent_actions": 1})

    with pytest.raises(BudgetExceeded) as exc:
        ledger.reserve({"tcp_ports_attempted": 21, "agent_actions": 1})
    assert exc.value.shortages == {"tcp_ports_attempted": 1}
    assert ledger.snapshot()["reserved"] == {"tcp_ports_attempted": 80, "agent_actions": 1}

    ledger.release(first)
    second = ledger.reserve({"tcp_ports_attempted": 100, "agent_actions": 2})
    ledger.commit(second)
    assert ledger.snapshot()["remaining"] == {"tcp_ports_attempted": 0, "agent_actions": 0}


def test_budget_ledger_rejects_undeclared_or_overrun_dimensions_without_losing_hold():
    ledger = BudgetLedger({"http_requests": 5})
    reservation = ledger.reserve({"http_requests": 3})

    with pytest.raises(BudgetError):
        ledger.commit(reservation, {"browser_actions": 1})
    assert ledger.snapshot()["reserved"]["http_requests"] == 3

    with pytest.raises(BudgetError):
        ledger.commit(reservation, {"http_requests": 4})
    assert ledger.snapshot()["reserved"]["http_requests"] == 3

    ledger.release(reservation)


def test_persistent_budget_snapshot_uses_the_shared_dimensions():
    limits = {"agent_actions": 2, "http_requests": 10, "tcp_ports_attempted": 100}
    used = reserve_budget_snapshot(
        limits, {"agent_actions": 1}, {"agent_actions": 1, "http_requests": 4},
    )
    assert used == {"agent_actions": 2, "http_requests": 4, "tcp_ports_attempted": 0}
    with pytest.raises(BudgetExceeded):
        reserve_budget_snapshot(limits, used, {"agent_actions": 1})


def test_persistent_budget_reconciliation_preserves_later_reservations():
    # Current usage includes this call's hold (5) and another call's later hold (3).
    assert reconcile_budget_snapshot(
        {"http_requests": 8, "agent_actions": 2},
        {"http_requests": 5, "agent_actions": 1},
        {"http_requests": 2, "agent_actions": 1},
    ) == {"http_requests": 5, "agent_actions": 2}


def test_persistent_budget_reconciliation_retains_unknown_and_releases_proven_zero():
    assert reconcile_budget_snapshot(
        {"tcp_ports_attempted": 100, "tool_wall_seconds": 30},
        {"tcp_ports_attempted": 100, "tool_wall_seconds": 30},
        {"tcp_ports_attempted": 0},
    ) == {"tcp_ports_attempted": 0, "tool_wall_seconds": 30}


def test_typed_receipt_requires_scan_or_hunt_and_honest_timeout_state():
    with pytest.raises(ValueError):
        CapabilityReceipt(
            capability_name="web.probe", adapter_name="httpx", adapter_version="1",
            target_id="target", status="succeeded", input_digest="a" * 64,
            parser_version="httpx-json/v1",
        )
    with pytest.raises(ValueError):
        CapabilityReceipt(
            capability_name="web.probe", adapter_name="httpx", adapter_version="1",
            target_id="target", hunt_id="hunt", status="timed_out", input_digest="a" * 64,
            parser_version="httpx-json/v1", timed_out=True,
        )

    receipt = CapabilityReceipt(
        capability_name="web.crawl", adapter_name="katana", adapter_version="1",
        target_id="target", hunt_id="hunt", status="timed_out", input_digest="b" * 64,
        parser_version="katana-lines/v1", partial=True, timed_out=True,
        budget_reserved={"http_requests": 150}, budget_consumed={"http_requests": 57},
    )
    public = receipt.public_dict()
    assert public["partial"] is True
    assert public["timed_out"] is True
    assert public["budget_consumed"] == {"http_requests": 57}
