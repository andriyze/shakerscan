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
from runtime.capability_registry import CAPABILITY_REGISTRY, PROCESS_TOOL_TO_CAPABILITY
from runtime.receipts import CapabilityReceipt


def test_registry_is_authoritative_for_legacy_hunt_tools_and_arsenal():
    registered = {spec.process_tool_name: spec for spec in CAPABILITY_REGISTRY.process_tools()}

    assert set(registered) == set(agent_tools.RUN_TOOL_NAMES)
    assert set(PROCESS_TOOL_TO_CAPABILITY) == set(agent_tools.RUN_TOOL_NAMES)
    for tool_name, template in agent_tools.SCANNER_ARG_TEMPLATES.items():
        spec = registered[tool_name]
        assert template["capability"] == spec.name
        assert template["binary"] == spec.binary
        assert template["risk"] == (
            "read_only" if spec.risk_tier in {"read_only", "passive"} else "active"
        )
        assert template["output_schema"] == spec.output_schema
        assert template["evidence_contract"] == spec.evidence_contract

    arsenal = command_arsenal.describe_tools(probe_versions=False)["tools"]
    for tool_name, spec in registered.items():
        matching = next(
            item for item in arsenal
            if item["tool_name"] == tool_name
            and item["capability_name"] == spec.name
        )
        assert matching["capability_name"] == spec.name
        assert matching["risk_tier"] == spec.risk_tier
        assert matching["evidence_parser"] == spec.output_schema


def test_registry_filters_target_kind_and_active_permission():
    safe_web = {spec.name for spec in CAPABILITY_REGISTRY.list(
        target_kind="web", include_active=False,
    )}
    all_device = {
        spec.name for spec in CAPABILITY_REGISTRY.list(target_kind="device")
    }

    assert safe_web == {
        "scan.finalize", "scan.execute",
        "web.probe", "http.request", "dns.inspect", "subdomains.discover", "tls.inspect", "browser.navigate",
        "browser.interact", "web.crawl", "web.browser_crawl",
        "web.content_discover",
        "templates.passive_scan", "templates.passive_batch",
        "collections.inspect", "collections.select", "collections.replay_safe",
    }
    assert all_device == {
        "device.inspect", "device.capabilities.inspect", "device.http.probe",
        "device.scan", "device.service.verify", "collections.inspect", "collections.select",
        "collections.replay_safe", "device.ssh.propose", "device.ssh.execute_confirmed",
        "candidate.verify",
    }
    assert not CAPABILITY_REGISTRY.require("web.probe").requires_active_approval
    assert CAPABILITY_REGISTRY.require("ports.discover").requires_active_approval


def test_scan_finalize_is_an_offline_placed_evidence_report_assembler():
    specification = CAPABILITY_REGISTRY.require("scan.finalize")

    assert specification.budget_cost == {"tool_wall_seconds": 1}
    assert specification.placement_requirements == {
        "network_reachability": False,
        "runtime_target_binding": False,
        "fixed_stage_plan": True,
        "durable_reservation": True,
        "placed_evidence_only": True,
        "offline_only": True,
    }


def test_scan_execute_remains_only_as_historical_compatibility_identity():
    specification = CAPABILITY_REGISTRY.require("scan.execute")

    assert specification.placement_requirements["deprecated_compatibility"] is True
    assert specification.planner_visible is False


def test_auth_session_registry_contract_is_target_bound_and_worker_private():
    specification = CAPABILITY_REGISTRY.require("auth.session.establish")

    assert specification.risk_tier == "credential"
    assert specification.required_approval == "credential_use"
    assert specification.budget_cost == {
        "http_requests": 4,
        "tool_wall_seconds": 45,
    }
    assert specification.placement_requirements == {
        "network_reachability": True,
        "runtime_target_binding": True,
        "credentials_resolved_server_side": True,
        "worker_private_result": True,
    }
    assert specification.planner_visible is True
    assert specification.hunt_executor == "worker_auth"
    assert specification.planner_contract()["input_schema"] == {
        "type": "object",
        "properties": {
            "as_principal": {
                "type": "string",
                "enum": ["primary", "secondary", "service"],
            },
        },
        "additionalProperties": False,
        "required": ["as_principal"],
    }


def test_active_collection_replay_has_an_approval_bound_hidden_contract():
    specification = CAPABILITY_REGISTRY.require("collections.replay_active")

    assert specification.risk_tier == "active"
    assert specification.required_approval == "state_changing_http"
    assert specification.adapter == "collections.replay"
    assert specification.budget_cost == {
        "http_requests": 2_000,
        "state_changing_requests": 2_000,
        "tool_wall_seconds": 300,
    }
    assert specification.planner_visible is False


def test_authz_verification_is_read_only_proof_gated_and_worker_bound():
    specification = CAPABILITY_REGISTRY.require("authz.verify")

    assert specification.execution_kind == "http"
    assert specification.risk_tier == "active"
    assert specification.required_approval == "active_testing"
    assert specification.budget_cost == {
        "http_requests": 4,
        "tool_wall_seconds": 60,
    }
    assert specification.placement_requirements[
        "deterministic_proof_contract"
    ] is True
    assert specification.planner_visible is True
    assert specification.hunt_executor == "worker_http"
    assert set(
        specification.planner_contract()["input_schema"]["properties"]
    ) == {"primary_session_ref", "secondary_session_ref", "routes"}


def test_ssh_proposal_registry_budget_is_control_plane_only():
    proposal = CAPABILITY_REGISTRY.require("device.ssh.propose")

    assert proposal.budget_cost == {
        "active_actions": 1,
        "tool_wall_seconds": 5,
    }
    assert "device_fragility_points" not in proposal.budget_cost
    assert proposal.placement_requirements == {
        "control_plane": True,
        "credential_binding": "ssh",
    }


def test_confirmed_ssh_registry_contract_is_worker_placed_and_planner_hidden():
    confirmed = CAPABILITY_REGISTRY.require("device.ssh.execute_confirmed")

    assert confirmed.budget_cost == {
        "active_actions": 1,
        "tool_wall_seconds": 30,
        "device_fragility_points": 12,
    }
    assert confirmed.placement_requirements == {
        "device_worker": True,
        "credential_binding": "ssh",
        "user_confirmation": True,
    }
    assert confirmed.planner_visible is False


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


def test_canonical_http_tools_declare_content_free_principal_bindings():
    for capability_name in (
        "web.probe", "web.crawl", "web.content_discover", "templates.scan",
        "xss.verify", "sqli.verify", "http.request",
    ):
        properties = CAPABILITY_REGISTRY.require(
            capability_name
        ).input_schema["properties"]
        assert properties["as_principal"]["enum"] == [
            "primary", "secondary", "service",
        ]
        assert properties["principal_binding_digest"]["pattern"] == (
            "^[0-9a-f]{64}$"
        )


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
        started_at="2026-08-22T12:00:00+00:00",
        finished_at="2026-08-22T12:01:00+00:00",
    )
    public = receipt.public_dict()
    assert public["partial"] is True
    assert public["timed_out"] is True
    assert public["budget_consumed"] == {"http_requests": 57}
