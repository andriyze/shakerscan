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
    assert {item["name"] for item in capabilities} >= {"web.probe", "ports.discover"}


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
    assert "capability_name=name" in api
    assert "adapter_name=str(spec.adapter)" in api
    assert "budget_json={\"reserved\": charges" in api
    assert "hunt_id=str(run[\"id\"])" in api
    assert "reserve_budget_snapshot" in api
    assert "trusted_collection_headers" in api
    assert 'action_name=f"hunt.capability:{name}"' in api
    assert "require_expiry=True" in api
    assert "ADD COLUMN IF NOT EXISTS capability_name" in migration
    assert "ADD COLUMN IF NOT EXISTS hunt_id" in migration
    assert "argv" not in capability_manifest(resolve_hunt_policy(
        target_kind="web", budget_profile="fast", approval_receipt_id=None,
        approval_validated=False,
    ))[0]["input_schema"].get("properties", {})
