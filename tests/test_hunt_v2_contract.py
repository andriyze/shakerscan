from __future__ import annotations

import sys

from tests.api_sources import (
    api_tree_source, definition_source, route_is_declared, route_source,
)
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.contracts import capability_manifest
from hunt.start_contract import normalize_hunt_start_payload


def _contract(
    target_kind: str,
    *,
    budget_profile: str = "balanced",
    active: bool = False,
    credentials_requested: bool = False,
    budgets: dict[str, int] | None = None,
):
    return normalize_hunt_start_payload({
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": target_kind,
        "goal": "Inspect the target",
        "budget_profile": budget_profile,
        "budgets": budgets or {},
        "policy": {
            "active_testing": active,
            "authorization_confirmed": active or credentials_requested,
            "approval_receipt_id": "receipt" if active or credentials_requested else None,
        },
        "credential_refs": (
            {"ssh_credential_profile_id": "credential-1"}
            if credentials_requested else {}
        ),
        "capabilities": [],
        "request_collection_ids": [],
    })


def test_hunt_without_receipt_is_passive_and_target_filtered():
    contract = _contract("web")
    names = {
        item["name"]
        for item in capability_manifest(contract, credentials_available=False)
    }
    assert contract.policy.active_testing is False
    assert "web.probe" in names
    assert "http.request" in names
    assert "tls.inspect" not in names
    assert "collections.replay_safe" in names
    assert "templates.scan" not in names
    assert "ports.discover" not in names


def test_hunt_with_valid_receipt_gets_active_capabilities_but_never_mutation():
    contract = _contract(
        "device", budget_profile="thorough", active=True,
        credentials_requested=True,
    )
    capabilities = capability_manifest(contract, credentials_available=True)
    assert contract.policy.active_testing is True
    assert contract.policy.allow_state_changing_http is False
    names = {item["name"] for item in capabilities}
    assert names >= {"device.inspect", "device.http.probe", "device.scan", "device.ssh.propose"}
    assert "device.ssh.execute_confirmed" not in names
    assert not names & {
        "web.probe", "templates.scan", "web.crawl", "web.content_discover",
        "xss.verify", "sqli.verify", "service.fingerprint", "ports.discover", "tls.inspect",
    }


def test_device_ssh_proposal_requires_bound_credentials():
    contract = _contract("device", budget_profile="thorough", active=True)
    assert "device.ssh.propose" not in {
        item["name"]
        for item in capability_manifest(contract, credentials_available=False)
    }


def test_hunt_budget_profile_is_bounded():
    contract = _contract("api", budget_profile="fast")
    assert contract.resolved_budget_object.max_capability_calls == 20
    assert contract.resolved_budget_object.max_candidates == 20


def test_zero_ceiling_removes_capabilities_that_require_that_dimension():
    passive = _contract("web", budgets={"max_browser_actions": 0})
    passive_names = {
        item["name"]
        for item in capability_manifest(passive, credentials_available=False)
    }
    assert "browser.navigate" not in passive_names
    assert "browser.interact" not in passive_names

    active = _contract("web", active=True, budgets={"max_active_actions": 0})
    active_names = {
        item["name"]
        for item in capability_manifest(active, credentials_available=False)
    }
    assert "templates.scan" not in active_names
    assert "xss.verify" not in active_names


def test_hunt_actions_emit_capability_receipts_and_never_accept_raw_argv():
    root = Path(__file__).resolve().parents[1]
    api = api_tree_source()
    migration = (root / "api" / "retest_contract.py").read_text()

    assert route_is_declared("POST", "/hunts/{hunt_id}/capabilities/{capability_name:path}")
    assert route_is_declared("POST", "/hunts/{hunt_id}/shell-plans/{plan_id}/confirm")
    assert "capability_name=name" in api
    assert "adapter_name=str(spec.adapter)" in api
    assert '"used_after_reconciliation": reconciled_used' in api
    assert "reconcile_budget_snapshot" in api
    assert "_enqueue_canonical_network_capability" in api
    assert "hunt_id=str(run[\"id\"])" in api
    assert "reserve_budget_snapshot" in api
    assert "trusted_collection_headers" in api
    assert 'action_name=f"hunt.capability:{name}"' in api
    assert "require_expiry=True" in api
    assert "require_target_binding=True" in api
    assert 'elif name == "http.request"' in api
    assert "inspect_tls_origin" in api
    assert "_hunt_tls_inspect" not in api
    # device_agent.validate_tool_call was only reachable from the deleted legacy
    # reply handler. Canonical Hunt validates every capability input through the
    # semantic registry before any reservation or action write.
    assert "validate_hunt_input" in api
    assert "ADD COLUMN IF NOT EXISTS capability_name" in migration
    assert "ADD COLUMN IF NOT EXISTS hunt_id" in migration
    assert "argv" not in capability_manifest(
        _contract("web", budget_profile="fast"),
        credentials_available=False,
    )[0]["input_schema"].get("properties", {})
