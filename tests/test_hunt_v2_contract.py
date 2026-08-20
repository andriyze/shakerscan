from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.contracts import capability_manifest, resolve_hunt_policy


def test_hunt_without_receipt_is_passive_and_target_filtered():
    policy = resolve_hunt_policy(
        target_kind="web", budget_profile="balanced", approval_receipt_id=None,
        approval_validated=False,
    )
    names = {item["name"] for item in capability_manifest(policy)}
    assert policy.active_testing is False
    assert "web.probe" in names
    assert "http.request" in names
    assert "tls.inspect" in names
    assert "collections.replay_safe" in names
    assert "templates.scan" not in names
    assert "ports.discover" not in names


def test_hunt_with_valid_receipt_gets_active_capabilities_but_never_mutation():
    policy = resolve_hunt_policy(
        target_kind="device", budget_profile="thorough", approval_receipt_id="receipt",
        approval_validated=True, credentials_available=True,
        device_fragility_profile="authenticated_active",
    )
    capabilities = capability_manifest(policy)
    assert policy.active_testing is True
    assert policy.credential_access is True
    assert policy.mutation_allowed is False
    names = {item["name"] for item in capabilities}
    assert names >= {"device.inspect", "device.http.probe", "device.scan", "device.ssh.propose"}
    assert not names & {
        "web.probe", "templates.scan", "web.crawl", "web.content_discover",
        "xss.verify", "sqli.verify", "service.fingerprint", "ports.discover", "tls.inspect",
    }


def test_device_ssh_proposal_requires_bound_credentials():
    policy = resolve_hunt_policy(
        target_kind="device", budget_profile="thorough", approval_receipt_id="receipt",
        approval_validated=True, credentials_available=False,
        device_fragility_profile="authenticated_active",
    )
    assert "device.ssh.propose" not in {item["name"] for item in capability_manifest(policy)}


def test_hunt_budget_profile_is_bounded():
    policy = resolve_hunt_policy(
        target_kind="api", budget_profile="fast", approval_receipt_id=None,
        approval_validated=False,
    )
    assert policy.budget.max_capability_calls == 20
    assert policy.budget.max_candidates == 20


def test_hunt_actions_emit_capability_receipts_and_never_accept_raw_argv():
    root = Path(__file__).resolve().parents[1]
    api = (root / "api" / "api.py").read_text()
    migration = (root / "api" / "retest_contract.py").read_text()

    assert 'app.post("/hunts/{hunt_id}/capabilities/{capability_name:path}")' in api
    assert 'app.post("/hunts/{hunt_id}/shell-plans/{plan_id}/confirm")' in api
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
    assert "_hunt_tls_inspect" in api
    assert "device_agent.validate_tool_call" in api
    assert "ADD COLUMN IF NOT EXISTS capability_name" in migration
    assert "ADD COLUMN IF NOT EXISTS hunt_id" in migration
    assert "argv" not in capability_manifest(resolve_hunt_policy(
        target_kind="web", budget_profile="fast", approval_receipt_id=None,
        approval_validated=False,
    ))[0]["input_schema"].get("properties", {})
